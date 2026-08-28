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

export const TLS_CERTIFICATE_PARENT_TABLES = [
    "ManagementControllers",
    "Backbones",
    "BackboneAccessPoints",
    "InteriorSites",
    "ApplicationNetworks",
    "NetworkCredentials",
    "MemberInvitations",
    "MemberSites",
];

export function timestampsEqual(left, right) {
    if (!left && !right) {
        return true;
    }
    if (!left || !right) {
        return false;
    }
    return new Date(left).getTime() === new Date(right).getTime();
}

export async function getTlsRotationMeta(client, objectName) {
    if (!objectName) {
        return null;
    }
    const result = await client.query(
        "SELECT RotationOrdinal, Expiration FROM TlsCertificates WHERE ObjectName = $1",
        [objectName]
    );
    if (result.rowCount == 0 || result.rows.length == 0) {
        return null;
    }
    let ordinal = 0;
    let lastValid = null;
    const now = Date.now();
    for (const row of result.rows) {
        const rotationOrdinal = row.rotationordinal ?? 0;
        if (rotationOrdinal > ordinal) {
            ordinal = rotationOrdinal;
        }
        const expirationMs = row.expiration ? new Date(row.expiration).getTime() : null;
        if (expirationMs == null || expirationMs > now) {
            if (lastValid == null || rotationOrdinal < lastValid) {
                lastValid = rotationOrdinal;
            }
        }
    }
    if (lastValid == null) {
        lastValid = ordinal;
    }
    return { ordinal, lastValid };
}

export async function getCurrentCertificateId(client, objectName) {
    if (!objectName) {
        return undefined;
    }
    const result = await client.query(
        "SELECT Id FROM TlsCertificates WHERE ObjectName = $1 ORDER BY RotationOrdinal DESC LIMIT 1",
        [objectName]
    );
    return result.rows[0]?.id;
}

export async function lockLatestCertificateByObjectName(client, objectName) {
    if (!objectName) {
        return undefined;
    }
    const result = await client.query(
        "SELECT Id, IsCA, ObjectName, SignedBy, Expiration, RenewalTime, RotationOrdinal, Label " +
            "FROM TlsCertificates WHERE ObjectName = $1 ORDER BY RotationOrdinal DESC LIMIT 1 FOR UPDATE",
        [objectName]
    );
    return result.rows[0];
}

export async function retargetParentCertificateFks(client, notify, oldId, newId) {
    for (const table of TLS_CERTIFICATE_PARENT_TABLES) {
        const updated = await client.query(
            `UPDATE ${table} SET Certificate = $1 WHERE Certificate = $2 RETURNING Id`,
            [newId, oldId]
        );
        for (const row of updated.rows) {
            notify.update(table, row.id);
        }
    }
}

export async function deleteExpiredSupersededCertificates(client, notify) {
    const expired = await client.query(
        "SELECT c.Id, c.ObjectName FROM TlsCertificates c " +
            "WHERE c.Expiration IS NOT NULL AND c.Expiration < CURRENT_TIMESTAMP " +
            "AND EXISTS (SELECT 1 FROM TlsCertificates newer WHERE newer.Supercedes = c.Id) " +
            "AND NOT EXISTS (SELECT 1 FROM TlsCertificates child WHERE child.SignedBy = c.Id) " +
            "AND NOT EXISTS (SELECT 1 FROM TlsClientRevocations r WHERE r.CertificateId = c.Id) " +
            "ORDER BY c.RotationOrdinal ASC"
    );
    const objectNames = [];
    const seen = new Set();
    for (const row of expired.rows) {
        await client.query("UPDATE TlsCertificates SET Supercedes = NULL WHERE Supercedes = $1", [
            row.id,
        ]);
        await client.query("DELETE FROM TlsCertificates WHERE Id = $1", [row.id]);
        notify.delete("TlsCertificates", row.id);
        if (row.objectname && !seen.has(row.objectname)) {
            seen.add(row.objectname);
            objectNames.push(row.objectname);
        }
    }
    return objectNames;
}
