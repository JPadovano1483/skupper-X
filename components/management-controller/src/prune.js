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

import {
    GetIssuers,
    DeleteIssuer,
    GetCertificates,
    DeleteCertificate,
    GetSecrets,
    DeleteSecret,
} from "@vms/modules/kube";
import { Log } from "@vms/modules/log";
import { META_ANNOTATION_VMS_CONTROLLED } from "@vms/modules/common";
import { ClientFromPool } from "./db.js";
import { NotifyTransaction } from "./notify.js";
import { deleteExpiredSupersededCertificates, getCurrentCertificateId } from "./tls-rotation.js";
import { AccessCertificateChanged, SiteCertificateChanged } from "./sync-management.js";

function uniqueObjectNames(objectNames) {
    const names = [];
    const seen = new Set();
    for (const name of objectNames || []) {
        if (!name || seen.has(name)) {
            continue;
        }
        seen.add(name);
        names.push(name);
    }
    return names;
}

function isVmsControlledOrphan(obj, dbCertNames) {
    return (
        obj?.metadata?.annotations?.[META_ANNOTATION_VMS_CONTROLLED] == "true" &&
        !dbCertNames.has(obj.metadata.name)
    );
}

async function deleteKubeOrphan(kind, name, deleteHandler) {
    try {
        await deleteHandler(name);
        Log(`  Deleted ${kind}: ${name}`);
    } catch (error) {
        Log(`WARN: Failed to delete ${kind} ${name}: ${error.message}`);
    }
}

export async function reconcileCertificates() {
    const client = await ClientFromPool("system");
    try {
        const result = await client.query("SELECT ObjectName FROM TlsCertificates");
        const dbCertNames = new Set(result.rows.map((row) => row.objectname).filter(Boolean));

        for (const issuer of (await GetIssuers()) || []) {
            if (isVmsControlledOrphan(issuer, dbCertNames)) {
                await deleteKubeOrphan("issuer", issuer.metadata.name, DeleteIssuer);
            }
        }

        for (const cert of (await GetCertificates()) || []) {
            if (isVmsControlledOrphan(cert, dbCertNames)) {
                await deleteKubeOrphan("certificate", cert.metadata.name, DeleteCertificate);
            }
        }

        for (const secret of (await GetSecrets()) || []) {
            if (isVmsControlledOrphan(secret, dbCertNames)) {
                await deleteKubeOrphan("secret", secret.metadata.name, DeleteSecret);
            }
        }
    } catch (error) {
        Log(`Exception in reconcileCertificates: ${error.stack}`);
    } finally {
        client.release();
    }
}

export async function DeleteOrphanCertificates() {
    const client = await ClientFromPool("system");
    const notify = new NotifyTransaction();
    try {
        await client.query("BEGIN");
        const expiredObjectNames = await deleteExpiredSupersededCertificates(client, notify);
        const deleteMap = {};
        const tlsResult = await client.query(
            "SELECT Id, SignedBy, Supercedes FROM TlsCertificates"
        );
        const referencedAsPredecessor = new Set(
            tlsResult.rows.map((row) => row.supercedes).filter(Boolean)
        );
        for (const tlsRow of tlsResult.rows) {
            if (tlsRow.signedby) {
                if (!deleteMap[tlsRow.signedby]) {
                    deleteMap[tlsRow.signedby] = {
                        pleaseDelete: false,
                        children: [],
                    };
                }
                deleteMap[tlsRow.signedby].children.push(tlsRow.id);
            }
            if (!deleteMap[tlsRow.id]) {
                deleteMap[tlsRow.id] = {
                    pleaseDelete: true,
                    children: [],
                };
            } else {
                deleteMap[tlsRow.id].pleaseDelete = true;
            }
        }

        for (const table of [
            "ManagementControllers",
            "Backbones",
            "BackboneAccessPoints",
            "InteriorSites",
            "ApplicationNetworks",
            "NetworkCredentials",
            "MemberInvitations",
            "MemberSites",
        ]) {
            const result = await client.query(`SELECT Id, Certificate FROM ${table}`);
            for (const row of result.rows) {
                if (row.certificate) {
                    if (deleteMap[row.certificate]) {
                        deleteMap[row.certificate].pleaseDelete = false;
                    } else {
                        Log(`Record ${table}[${row.id}] references a non-exist TlsCertificate`);
                    }
                }
            }
        }

        // Superseded predecessors stay until deleteExpiredSupersededCertificates removes them.
        for (const certId of referencedAsPredecessor) {
            if (deleteMap[certId]) {
                deleteMap[certId].pleaseDelete = false;
            }
        }

        const depthFirstDelete = async function (client, notify, certId) {
            const record = deleteMap[certId];
            for (const childId of record.children) {
                await depthFirstDelete(client, notify, childId);
            }
            if (record.pleaseDelete) {
                await client.query("DELETE FROM TlsCertificates WHERE Id = $1", [certId]);
                notify.delete("TlsCertificates", certId);
                Log(`Orphan TlsCertificate ${certId} to be deleted`);
                record.pleaseDelete = false;
            }
        };

        for (const certId of Object.keys(deleteMap)) {
            await depthFirstDelete(client, notify, certId);
        }

        await client.query("COMMIT");
        await notify.commit();
        return expiredObjectNames;
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in DeleteOrphanCertificates: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
}

async function advertiseTlsLastValid(objectNames) {
    const names = uniqueObjectNames(objectNames);
    if (names.length == 0) {
        return;
    }
    const client = await ClientFromPool("system");
    try {
        for (const objectName of names) {
            const certId = await getCurrentCertificateId(client, objectName);
            if (certId) {
                await SiteCertificateChanged(certId);
                await AccessCertificateChanged(certId);
            }
        }
    } finally {
        client.release();
    }
}

export async function PruneNow() {
    try {
        Log("[Prune - Reconciling Kubernetes objects to the database]");
        const expiredObjectNames = await DeleteOrphanCertificates();
        await reconcileCertificates();
        await advertiseTlsLastValid(expiredObjectNames);
    } catch (error) {
        Log(`Exception in PruneNow: ${error.stack}`);
    }
}

export async function Start() {
    await PruneNow();
}
