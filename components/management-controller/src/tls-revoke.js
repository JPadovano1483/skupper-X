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

async function deleteKubeTlsObjects(objectName) {
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
    } finally {
        client.release();
    }

    if (cert.objectname) {
        await deleteKubeTlsObjects(cert.objectname);
    }
    await advertiseTlsRevoked(cid);
    return cert;
}
