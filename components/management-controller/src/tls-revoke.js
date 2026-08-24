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

import { DeleteCertificate, DeleteSecret } from "@vms/modules/kube";
import { Log } from "@vms/modules/log";
import { UpdateLocalState } from "@vms/modules/state-sync";
import { IsValidUuid } from "@vms/modules/util";
import { ClientFromPool } from "./db.js";
import { AccessCertificateChanged, SiteCertificateChanged } from "./sync-management.js";
import { getCurrentCertificateId, TLS_CERTIFICATE_PARENT_TABLES } from "./tls-rotation.js";

function httpError(statusCode, message) {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
}

export async function isRevoked(client, certId) {
    if (!certId) {
        return false;
    }
    const result = await client.query(
        "SELECT 1 FROM TlsClientRevocations WHERE CertificateId = $1",
        [certId]
    );
    return result.rowCount > 0;
}

export async function refuseIfRevoked(client, certId) {
    if (await isRevoked(client, certId)) {
        throw httpError(409, "Certificate has been revoked");
    }
}

export async function insertRevocation(client, certId, expiration, reason) {
    await client.query(
        "INSERT INTO TlsClientRevocations (CertificateId, Expiration, Reason) VALUES ($1, $2, $3) ON CONFLICT (CertificateId) DO NOTHING",
        [certId, expiration, reason]
    );
}

export async function deleteExpiredRevocations(client) {
    await client.query(
        "DELETE FROM TlsClientRevocations WHERE Expiration IS NOT NULL AND Expiration < CURRENT_TIMESTAMP"
    );
}

export async function listRevokedCertificateIds(client) {
    const result = await client.query("SELECT CertificateId FROM TlsClientRevocations");
    return result.rows.map((row) => row.certificateid);
}

export async function deleteKubeTlsObjects(objectName) {
    try {
        await DeleteSecret(objectName);
    } catch (error) {
        Log(`WARN: Failed to delete Secret ${objectName}: ${error.message}`);
    }
    try {
        await DeleteCertificate(objectName);
    } catch (error) {
        Log(`WARN: Failed to delete Certificate ${objectName}: ${error.message}`);
    }
}

export async function deleteKubeTlsObjectList(objectNames) {
    const seen = new Set();
    for (const name of objectNames) {
        if (!name || seen.has(name)) {
            continue;
        }
        seen.add(name);
        await deleteKubeTlsObjects(name);
    }
}

export async function dropAccessPointCertificate(client, notify, accessId) {
    const objectNames = [];
    const pending = await client.query(
        "SELECT Id FROM CertificateRequests WHERE AccessPoint = $1",
        [accessId]
    );
    for (const row of pending.rows) {
        objectNames.push(`vms-access-${row.id}`);
        await client.query("DELETE FROM CertificateRequests WHERE Id = $1", [row.id]);
        notify.delete("CertificateRequests", row.id);
    }

    const apResult = await client.query(
        "SELECT Certificate FROM BackboneAccessPoints WHERE Id = $1",
        [accessId]
    );
    const certId = apResult.rows[0]?.certificate;
    if (!certId) {
        return objectNames;
    }

    const tlsResult = await client.query(
        "SELECT Id, ObjectName FROM TlsCertificates WHERE Id = $1",
        [certId]
    );
    if (tlsResult.rowCount != 1 || !tlsResult.rows[0].objectname) {
        return objectNames;
    }
    const objectName = tlsResult.rows[0].objectname;
    objectNames.push(objectName);

    await client.query("UPDATE BackboneAccessPoints SET Certificate = NULL WHERE Id = $1", [
        accessId,
    ]);

    const chain = await client.query("SELECT Id FROM TlsCertificates WHERE ObjectName = $1", [
        objectName,
    ]);
    await client.query("UPDATE TlsCertificates SET Supercedes = NULL WHERE ObjectName = $1", [
        objectName,
    ]);
    for (const row of chain.rows) {
        if (!(await isRevoked(client, row.id))) {
            await client.query("DELETE FROM TlsCertificates WHERE Id = $1", [row.id]);
            notify.delete("TlsCertificates", row.id);
        }
    }

    return objectNames;
}

async function objectNameHasOtherTlsRow(client, objectName, certId) {
    const result = await client.query(
        "SELECT 1 FROM TlsCertificates WHERE ObjectName = $1 AND Id <> $2 LIMIT 1",
        [objectName, certId]
    );
    return result.rowCount > 0;
}

async function certificateHasParentFk(client, certId) {
    for (const table of TLS_CERTIFICATE_PARENT_TABLES) {
        const result = await client.query(`SELECT 1 FROM ${table} WHERE Certificate = $1 LIMIT 1`, [
            certId,
        ]);
        if (result.rowCount > 0) {
            return true;
        }
    }
    return false;
}

export async function advertiseTlsRevoked(certId) {
    const client = await ClientFromPool("system");
    try {
        const members = await client.query("SELECT Id FROM MemberSites WHERE Certificate = $1", [
            certId,
        ]);
        for (const row of members.rows) {
            await UpdateLocalState(row.id, `tls-site-${row.id}`, null);
        }
        const interiors = await client.query(
            "SELECT Id FROM InteriorSites WHERE Certificate = $1",
            [certId]
        );
        for (const row of interiors.rows) {
            await UpdateLocalState(row.id, `tls-site-${row.id}`, null);
        }
        const accessPoints = await client.query(
            "SELECT Id, InteriorSite FROM BackboneAccessPoints WHERE Certificate = $1",
            [certId]
        );
        for (const row of accessPoints.rows) {
            await UpdateLocalState(row.interiorsite, `tls-server-${row.id}`, null);
        }
    } finally {
        client.release();
    }
}

export async function RevokeCertificate(cid, { reason = "Revoked via API", expiration } = {}) {
    if (!IsValidUuid(cid)) {
        throw httpError(400, `Malformed certificate ID: ${cid}`);
    }

    const client = await ClientFromPool("system");
    let cert;
    let objectNameReferenced;
    let hasParentFks;
    let currentCertificateId;
    try {
        const result = await client.query(
            "SELECT id, objectname, label, isca, expiration FROM TlsCertificates WHERE id = $1",
            [cid]
        );
        if (result.rowCount == 0) {
            throw httpError(404, "Certificate not found");
        }
        cert = result.rows[0];
        if (cert.isca) {
            throw httpError(409, "CA certificate revocation is not supported");
        }
        await insertRevocation(client, cid, expiration ?? cert.expiration, reason);
        objectNameReferenced = cert.objectname
            ? await objectNameHasOtherTlsRow(client, cert.objectname, cid)
            : false;
        hasParentFks = await certificateHasParentFk(client, cid);
        if (!hasParentFks && cert.objectname) {
            currentCertificateId = await getCurrentCertificateId(client, cert.objectname);
        }
    } finally {
        client.release();
    }

    // Generations share kube objects; only delete when this was the last TlsCertificates row.
    if (cert.objectname && !objectNameReferenced) {
        await deleteKubeTlsObjects(cert.objectname);
    }
    if (hasParentFks) {
        await advertiseTlsRevoked(cid);
    } else if (currentCertificateId && currentCertificateId !== cid) {
        // Predecessor no longer holds parent FKs; bump lastValid on the live successor.
        await SiteCertificateChanged(currentCertificateId);
        await AccessCertificateChanged(currentCertificateId);
    }
    return cert;
}
