/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
*/

"use strict";

import { randomUUID } from "node:crypto";
import {
    ApplyObject,
    DeleteCertificate,
    DeleteIssuer,
    DeleteSecret,
    LoadCertificate,
    LoadSecret,
    ReplaceCertificate,
    TriggerCertificateRenewal,
    setCertificateIssuerRef,
} from "@vms/modules/kube";
import { Log } from "@vms/modules/log";
import { META_ANNOTATION_VMS_CONTROLLED, META_ANNOTATION_VMS_DBLINK } from "@vms/modules/common";
import { ClientFromPool } from "./db.js";
import { NotifyTransaction } from "./notify.js";
import { refuseIfRevoked } from "./tls-revoke.js";
import { retargetParentCertificateFks } from "./tls-rotation.js";

const ISSUER_LINK_ANNOTATION = "skupper.io/vms-issuerlink";
const DEFAULT_CA_DURATION = "8760h";
const DEFAULT_SECRET_TIMEOUT_MS = 60_000;
const DEFAULT_SECRET_INTERVAL_MS = 200;
const LIVE_CHILDREN_SQL =
    "SELECT Id, ObjectName, IsCA, SignedBy, Expiration, RenewalTime, RotationOrdinal, Label " +
    "FROM TlsCertificates " +
    "WHERE SignedBy = $1 " +
    "AND NOT EXISTS (SELECT 1 FROM TlsCertificates newer WHERE newer.Supercedes = TlsCertificates.Id) " +
    "AND NOT EXISTS (SELECT 1 FROM TlsClientRevocations r WHERE r.CertificateId = TlsCertificates.Id)";

function httpError(statusCode, message) {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
}

function kubeStatusCode(err) {
    return err?.statusCode || err?.code || err?.response?.statusCode;
}

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export function nextCaObjectName(oldName, newId) {
    if (!oldName) {
        return `vms-ca-${newId}`;
    }
    const uuidSuffix = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (uuidSuffix.test(oldName)) {
        return oldName.replace(uuidSuffix, newId);
    }
    return `${oldName}-${newId}`;
}

export function joinPemBundle(pems) {
    const parts = (pems || []).map((pem) => (pem || "").trim()).filter(Boolean);
    if (parts.length == 0) {
        return "";
    }
    return `${parts.join("\n")}\n`;
}

function issuerObject(name, dbLink) {
    return {
        apiVersion: "cert-manager.io/v1",
        kind: "Issuer",
        metadata: {
            name: name,
            annotations: {
                [META_ANNOTATION_VMS_DBLINK]: dbLink,
            },
        },
        spec: {
            ca: {
                secretName: name,
            },
            secretName: name,
        },
    };
}

function newCaCertificateObject(oldCert, { name, dbLink, issuerName, issuerLink }) {
    return {
        apiVersion: "cert-manager.io/v1",
        kind: "Certificate",
        metadata: {
            name: name,
            annotations: {
                [META_ANNOTATION_VMS_DBLINK]: dbLink,
            },
        },
        spec: {
            secretName: name,
            secretTemplate: {
                annotations: {
                    [META_ANNOTATION_VMS_CONTROLLED]: "true",
                    [META_ANNOTATION_VMS_DBLINK]: dbLink,
                    [ISSUER_LINK_ANNOTATION]: issuerLink,
                },
            },
            duration: oldCert.spec?.duration || DEFAULT_CA_DURATION,
            renewBefore: oldCert.spec?.renewBefore,
            subject: oldCert.spec?.subject,
            commonName: name,
            isCA: true,
            privateKey: {
                algorithm: oldCert.spec?.privateKey?.algorithm || "RSA",
                encoding: oldCert.spec?.privateKey?.encoding || "PKCS1",
                size: oldCert.spec?.privateKey?.size || 2048,
                rotationPolicy: "Never",
            },
            usages: oldCert.spec?.usages || ["signing"],
            issuerRef: {
                name: issuerName,
                kind: oldCert.spec?.issuerRef?.kind || "Issuer",
                group: oldCert.spec?.issuerRef?.group || "cert-manager.io",
            },
        },
    };
}

async function loadCertificateOrThrow(objectName, missingStatus) {
    try {
        const cert = await LoadCertificate(objectName);
        if (!cert) {
            throw httpError(missingStatus, `Certificate object ${objectName} is missing`);
        }
        return cert;
    } catch (err) {
        if (err.statusCode === missingStatus) {
            throw err;
        }
        if (kubeStatusCode(err) == 404) {
            throw httpError(missingStatus, `Certificate object ${objectName} is missing`);
        }
        throw err;
    }
}

async function listLiveChildren(client, caId) {
    const result = await client.query(LIVE_CHILDREN_SQL, [caId]);
    return result.rows;
}

async function collectLiveDescendants(client, caId) {
    const descendants = [];
    for (const child of await listLiveChildren(client, caId)) {
        descendants.push(child);
        if (child.isca) {
            descendants.push(...(await collectLiveDescendants(client, child.id)));
        }
    }
    return descendants;
}

async function hasLiveChildren(client, caId) {
    const result = await client.query(`${LIVE_CHILDREN_SQL} LIMIT 1`, [caId]);
    return result.rowCount > 0 || result.rows.length > 0;
}

async function assertDescendantsPresent(client, caId) {
    const descendants = await collectLiveDescendants(client, caId);
    for (const child of descendants) {
        if (!child.objectname) {
            throw httpError(
                409,
                `Cannot rotate CA key: child ${child.id} has no Kubernetes object`
            );
        }
        try {
            await loadCertificateOrThrow(child.objectname, 409);
        } catch (err) {
            if (err.statusCode === 409) {
                throw httpError(
                    409,
                    `Cannot rotate CA key: certificate object ${child.objectname} is missing`
                );
            }
            throw err;
        }
    }
    return descendants;
}

async function waitForReadySecret(name, timeoutMs, intervalMs) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const secret = await LoadSecret(name);
        if (secret?.data?.["tls.crt"]) {
            const cert = await LoadCertificate(name);
            if (cert) {
                return { secret, cert };
            }
        }
        if (Date.now() >= deadline) {
            throw httpError(504, `Timed out waiting for CA secret ${name}`);
        }
        await delay(intervalMs);
    }
}

async function deleteNewCaKube(name) {
    try {
        await DeleteIssuer(name);
    } catch (error) {
        Log(`WARN: Failed to delete Issuer ${name}: ${error.message}`);
    }
    try {
        await DeleteCertificate(name);
    } catch (error) {
        Log(`WARN: Failed to delete Certificate ${name}: ${error.message}`);
    }
    try {
        await DeleteSecret(name);
    } catch (error) {
        Log(`WARN: Failed to delete Secret ${name}: ${error.message}`);
    }
}

async function pemFromCaSecret(objectName) {
    const secret = await LoadSecret(objectName);
    const encoded = secret?.data?.["tls.crt"];
    if (!encoded) {
        return null;
    }
    return Buffer.from(encoded, "base64").toString("utf-8");
}

async function loadCertRow(client, certId) {
    const result = await client.query(
        "SELECT Id, IsCA, ObjectName, SignedBy, Supercedes, Expiration, RenewalTime, RotationOrdinal, Label " +
            "FROM TlsCertificates WHERE Id = $1",
        [certId]
    );
    return result.rows[0];
}

export async function overlayDualTrustCa(client, certId, secretData) {
    if (!client || !certId || !secretData) {
        return secretData;
    }
    const cert = await loadCertRow(client, certId);
    if (!cert) {
        return secretData;
    }
    const issuerId = cert.isca ? cert.id : cert.signedby;
    if (!issuerId) {
        return secretData;
    }
    const issuer = await loadCertRow(client, issuerId);
    if (!issuer) {
        return secretData;
    }

    let oldName;
    let newName;
    if (issuer.supercedes) {
        const predecessor = await loadCertRow(client, issuer.supercedes);
        if (predecessor && predecessor.objectname !== issuer.objectname) {
            if (await hasLiveChildren(client, predecessor.id)) {
                oldName = predecessor.objectname;
                newName = issuer.objectname;
            }
        }
    }
    if (!oldName) {
        const successorResult = await client.query(
            "SELECT Id, ObjectName FROM TlsCertificates WHERE Supercedes = $1",
            [issuer.id]
        );
        const successor = successorResult.rows[0];
        if (successor && successor.objectname !== issuer.objectname) {
            oldName = issuer.objectname;
            newName = successor.objectname;
        }
    }
    if (!oldName || !newName || oldName === newName) {
        return secretData;
    }

    const pems = [];
    for (const name of [oldName, newName]) {
        const pem = await pemFromCaSecret(name);
        if (pem) {
            pems.push(pem);
        }
    }
    if (pems.length < 2) {
        return secretData;
    }
    return {
        ...secretData,
        "ca.crt": Buffer.from(joinPemBundle(pems), "utf-8").toString("base64"),
    };
}

export async function certIdsToRefreshAfterIssuerCutover(newCaId, oldCaId) {
    if (!newCaId || !oldCaId || newCaId === oldCaId) {
        return [];
    }
    const client = await ClientFromPool("system");
    try {
        if (await hasLiveChildren(client, oldCaId)) {
            return [];
        }
        const children = await listLiveChildren(client, newCaId);
        return children.filter((child) => !child.isca).map((child) => child.id);
    } finally {
        client.release();
    }
}

function flattenReissueIds(node) {
    const ids = [];
    for (const child of node.children || []) {
        if (child.action == "reissue") {
            ids.push(child.id);
        }
        if (child.action == "cascade") {
            ids.push(...(child.refreshCertIds || flattenReissueIds(child)));
        }
    }
    return ids;
}

async function retargetLeafIssuer(child, issuerName, newCaId) {
    const kubeCert = await loadCertificateOrThrow(child.objectname, 409);
    const updated = setCertificateIssuerRef(kubeCert, issuerName, newCaId);
    if (updated) {
        await ReplaceCertificate(updated);
    }
    await TriggerCertificateRenewal(child.objectname);
}

export async function rotateCaKey(oldCaId, options = {}) {
    const secretTimeoutMs = options.secretTimeoutMs ?? DEFAULT_SECRET_TIMEOUT_MS;
    const secretIntervalMs = options.secretIntervalMs ?? DEFAULT_SECRET_INTERVAL_MS;
    const client = await ClientFromPool("system");
    let oldCert;
    try {
        const result = await client.query(
            "SELECT Id, IsCA, ObjectName, SignedBy, Expiration, RenewalTime, RotationOrdinal, Label " +
                "FROM TlsCertificates WHERE Id = $1",
            [oldCaId]
        );
        if (result.rowCount == 0) {
            throw httpError(404, "Certificate not found");
        }
        oldCert = result.rows[0];
        if (!oldCert.isca) {
            throw httpError(409, "CA key rotation is only supported for certificate authorities");
        }
        await refuseIfRevoked(client, oldCaId);
        if (!oldCert.objectname) {
            throw httpError(400, "Certificate has no Kubernetes object");
        }
        const superseded = await client.query(
            "SELECT Id, ObjectName FROM TlsCertificates WHERE Supercedes = $1",
            [oldCaId]
        );
        if (superseded.rowCount > 0) {
            throw httpError(409, "Certificate has been superseded");
        }
        await assertDescendantsPresent(client, oldCaId);
    } finally {
        client.release();
    }

    const oldKubeCert = await loadCertificateOrThrow(oldCert.objectname, 404);
    const issuerName = options.issuerName || oldKubeCert.spec?.issuerRef?.name;
    if (!issuerName) {
        throw httpError(400, "CA has no issuer");
    }
    const signedBy = options.signedBy !== undefined ? options.signedBy : oldCert.signedby;
    const issuerLink = options.issuerLink || signedBy || "root";
    const newId = options.newId || randomUUID();
    const newObjectName = nextCaObjectName(oldCert.objectname, newId);
    const certObj = newCaCertificateObject(oldKubeCert, {
        name: newObjectName,
        dbLink: newId,
        issuerName,
        issuerLink,
    });

    const created = await ApplyObject(certObj);
    if (!created) {
        throw httpError(500, `Failed to create Certificate ${newObjectName}`);
    }

    let ready;
    try {
        ready = await waitForReadySecret(newObjectName, secretTimeoutMs, secretIntervalMs);
        const issuerCreated = await ApplyObject(issuerObject(newObjectName, newId));
        if (!issuerCreated) {
            throw httpError(500, `Failed to create Issuer ${newObjectName}`);
        }
    } catch (err) {
        await deleteNewCaKube(newObjectName);
        throw err;
    }

    const expiration = ready.cert.status?.notAfter
        ? new Date(ready.cert.status.notAfter)
        : undefined;
    const renewal = ready.cert.status?.renewalTime
        ? new Date(ready.cert.status.renewalTime)
        : undefined;
    const notify = new NotifyTransaction();
    const writeClient = await ClientFromPool("system");
    try {
        await writeClient.query("BEGIN");
        await writeClient.query(
            "INSERT INTO TlsCertificates (Id, IsCA, ObjectName, SignedBy, Expiration, RenewalTime, RotationOrdinal, Supercedes, Label) " +
                "VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8)",
            [
                newId,
                newObjectName,
                signedBy,
                expiration,
                renewal,
                (oldCert.rotationordinal ?? 0) + 1,
                oldCert.id,
                oldCert.label,
            ]
        );
        notify.add("TlsCertificates", newId);
        await retargetParentCertificateFks(writeClient, notify, oldCert.id, newId);
        await writeClient.query("COMMIT");
        await notify.commit();
    } catch (err) {
        Log(`Rolling back CA key-rotation transaction: ${err.stack}`);
        await writeClient.query("ROLLBACK");
        await deleteNewCaKube(newObjectName);
        throw err;
    } finally {
        writeClient.release();
    }

    const children = [];
    const childClient = await ClientFromPool("system");
    try {
        const liveChildren = await listLiveChildren(childClient, oldCert.id);
        for (const child of liveChildren) {
            if (child.isca) {
                children.push(
                    await rotateCaKey(child.id, {
                        issuerName: newObjectName,
                        issuerLink: newId,
                        signedBy: newId,
                        secretTimeoutMs,
                        secretIntervalMs,
                    })
                );
            } else {
                await retargetLeafIssuer(child, newObjectName, newId);
                children.push({
                    id: child.id,
                    objectname: child.objectname,
                    isca: false,
                    action: "reissue",
                });
            }
        }
    } finally {
        childClient.release();
    }

    const keyRotation = {
        newCertificateId: newId,
        objectName: newObjectName,
        children,
    };
    return {
        ...oldCert,
        keyRotation,
        refreshCertIds: flattenReissueIds({ children }),
        action: "cascade",
        id: oldCert.id,
        newCertificateId: newId,
        objectname: oldCert.objectname,
        isca: true,
    };
}
