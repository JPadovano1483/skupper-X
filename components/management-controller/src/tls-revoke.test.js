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

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockClient = {
    query: vi.fn(),
    release: vi.fn(),
};

vi.mock("./db.js", () => ({
    ClientFromPool: vi.fn(async () => mockClient),
}));

vi.mock("@vms/modules/kube", () => ({
    DeleteSecret: vi.fn(),
    DeleteCertificate: vi.fn(),
}));

vi.mock("@vms/modules/state-sync", () => ({
    UpdateLocalState: vi.fn(),
}));

vi.mock("./sync-management.js", () => ({
    SiteCertificateChanged: vi.fn(async () => {}),
    AccessCertificateChanged: vi.fn(async () => {}),
}));

import {
    isRevoked,
    refuseIfRevoked,
    insertRevocation,
    deleteExpiredRevocations,
    listRevokedCertificateIds,
    dropAccessPointCertificate,
    deleteKubeTlsObjectList,
    advertiseTlsRevoked,
    RevokeCertificate,
} from "./tls-revoke.js";
import { ClientFromPool } from "./db.js";
import { DeleteSecret, DeleteCertificate } from "@vms/modules/kube";
import { UpdateLocalState } from "@vms/modules/state-sync";
import { AccessCertificateChanged, SiteCertificateChanged } from "./sync-management.js";
import { TLS_CERTIFICATE_PARENT_TABLES } from "./tls-rotation.js";

const CERT_ID = "00000000-0000-4000-8000-000000000007";
const SUCCESSOR_ID = "00000000-0000-4000-8000-000000000008";

function parentFkSql(table) {
    return `SELECT 1 FROM ${table} WHERE Certificate = $1 LIMIT 1`;
}

describe("isRevoked", () => {
    it("returns false when certId is missing", async () => {
        expect(await isRevoked(mockClient, null)).toBe(false);
        expect(mockClient.query).not.toHaveBeenCalled();
    });

    it("returns true when a revocation row exists", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 1, rows: [{}] });

        expect(await isRevoked(mockClient, CERT_ID)).toBe(true);
        expect(mockClient.query).toHaveBeenCalledWith(
            "SELECT 1 FROM TlsClientRevocations WHERE CertificateId = $1",
            [CERT_ID]
        );
    });

    it("returns false when no revocation row exists", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 0, rows: [] });

        expect(await isRevoked(mockClient, CERT_ID)).toBe(false);
    });
});

describe("refuseIfRevoked", () => {
    it("throws 409 when the certificate is revoked", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 1, rows: [{}] });

        await expect(refuseIfRevoked(mockClient, CERT_ID)).rejects.toMatchObject({
            statusCode: 409,
            message: "Certificate has been revoked",
        });
    });

    it("resolves when the certificate is not revoked", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 0, rows: [] });

        await expect(refuseIfRevoked(mockClient, CERT_ID)).resolves.toBeUndefined();
    });
});

describe("insertRevocation", () => {
    it("inserts a revocation row", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 1 });
        const expiration = new Date("2026-12-31T00:00:00.000Z");

        await insertRevocation(mockClient, CERT_ID, expiration, "test");

        expect(mockClient.query).toHaveBeenCalledWith(
            "INSERT INTO TlsClientRevocations (CertificateId, Expiration, Reason) VALUES ($1, $2, $3) ON CONFLICT (CertificateId) DO NOTHING",
            [CERT_ID, expiration, "test"]
        );
    });
});

describe("deleteExpiredRevocations", () => {
    it("deletes revocations whose expiration has passed", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 2 });

        await deleteExpiredRevocations(mockClient);

        expect(mockClient.query).toHaveBeenCalledWith(
            "DELETE FROM TlsClientRevocations WHERE Expiration IS NOT NULL AND Expiration < CURRENT_TIMESTAMP"
        );
    });
});

describe("listRevokedCertificateIds", () => {
    it("returns certificate ids from TlsClientRevocations", async () => {
        mockClient.query.mockResolvedValue({
            rows: [{ certificateid: "cert-a" }, { certificateid: "cert-b" }],
        });

        expect(await listRevokedCertificateIds(mockClient)).toEqual(["cert-a", "cert-b"]);
    });
});

describe("advertiseTlsRevoked", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        ClientFromPool.mockResolvedValue(mockClient);
    });

    it("nulls tls-site and tls-server hashes for related objects", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM MemberSites")) {
                return { rows: [{ id: "member-1" }] };
            }
            if (sql.includes("FROM InteriorSites")) {
                return { rows: [{ id: "site-1" }] };
            }
            if (sql.includes("FROM BackboneAccessPoints")) {
                return { rows: [{ id: "ap-1", interiorsite: "site-1" }] };
            }
            return { rows: [] };
        });

        await advertiseTlsRevoked(CERT_ID);

        expect(UpdateLocalState).toHaveBeenCalledWith("member-1", "tls-site-member-1", null);
        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-site-site-1", null);
        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-server-ap-1", null);
        expect(mockClient.release).toHaveBeenCalled();
    });
});

describe("RevokeCertificate", () => {
    const certRow = {
        id: CERT_ID,
        objectname: "vms-member-cert-1",
        label: "member-a",
        isca: false,
        expiration: "2026-12-31T00:00:00.000Z",
    };

    beforeEach(() => {
        vi.clearAllMocks();
        ClientFromPool.mockResolvedValue(mockClient);
        DeleteSecret.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
        mockClient.query.mockImplementation(async (sql) => {
            if (
                sql.includes("SELECT id, objectname, label, isca, expiration FROM TlsCertificates")
            ) {
                return { rowCount: 1, rows: [certRow] };
            }
            if (sql.includes("INSERT INTO TlsClientRevocations")) {
                return { rowCount: 1 };
            }
            if (sql.includes("SELECT 1 FROM TlsCertificates WHERE ObjectName")) {
                return { rowCount: 0, rows: [] };
            }
            if (sql === parentFkSql("MemberSites")) {
                return { rowCount: 1, rows: [{}] };
            }
            if (
                sql.startsWith("SELECT 1 FROM ") &&
                sql.includes("WHERE Certificate = $1 LIMIT 1")
            ) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("FROM MemberSites")) {
                return { rowCount: 1, rows: [{ id: "member-1" }] };
            }
            if (sql.includes("FROM InteriorSites") || sql.includes("FROM BackboneAccessPoints")) {
                return { rowCount: 0, rows: [] };
            }
            return { rows: [], rowCount: 0 };
        });
    });

    it("inserts a revocation, deletes kube objects, and advertises null hashes", async () => {
        await expect(RevokeCertificate(CERT_ID)).resolves.toEqual(certRow);

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsClientRevocations"),
            [CERT_ID, certRow.expiration, "Revoked via API"]
        );
        expect(DeleteSecret).toHaveBeenCalledWith("vms-member-cert-1");
        expect(DeleteCertificate).toHaveBeenCalledWith("vms-member-cert-1");
        expect(UpdateLocalState).toHaveBeenCalledWith("member-1", "tls-site-member-1", null);
        expect(SiteCertificateChanged).not.toHaveBeenCalled();
        expect(AccessCertificateChanged).not.toHaveBeenCalled();
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("skips kube delete when another row shares objectname", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (
                sql.includes("SELECT id, objectname, label, isca, expiration FROM TlsCertificates")
            ) {
                return { rowCount: 1, rows: [certRow] };
            }
            if (sql.includes("INSERT INTO TlsClientRevocations")) {
                return { rowCount: 1 };
            }
            if (sql.includes("SELECT 1 FROM TlsCertificates WHERE ObjectName")) {
                return { rowCount: 1, rows: [{}] };
            }
            if (sql === parentFkSql("MemberSites")) {
                return { rowCount: 1, rows: [{}] };
            }
            if (
                sql.startsWith("SELECT 1 FROM ") &&
                sql.includes("WHERE Certificate = $1 LIMIT 1")
            ) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("FROM MemberSites")) {
                return { rowCount: 1, rows: [{ id: "member-1" }] };
            }
            if (sql.includes("FROM InteriorSites") || sql.includes("FROM BackboneAccessPoints")) {
                return { rowCount: 0, rows: [] };
            }
            return { rows: [], rowCount: 0 };
        });

        await RevokeCertificate(CERT_ID);

        expect(DeleteSecret).not.toHaveBeenCalled();
        expect(DeleteCertificate).not.toHaveBeenCalled();
        expect(UpdateLocalState).toHaveBeenCalledWith("member-1", "tls-site-member-1", null);
        expect(SiteCertificateChanged).not.toHaveBeenCalled();
        expect(AccessCertificateChanged).not.toHaveBeenCalled();
    });

    it("skips advertiseTlsRevoked for predecessors and advertises lastValid on the successor", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (
                sql.includes("SELECT id, objectname, label, isca, expiration FROM TlsCertificates")
            ) {
                return { rowCount: 1, rows: [certRow] };
            }
            if (sql.includes("INSERT INTO TlsClientRevocations")) {
                return { rowCount: 1 };
            }
            if (sql.includes("SELECT 1 FROM TlsCertificates WHERE ObjectName")) {
                return { rowCount: 1, rows: [{}] };
            }
            if (
                sql.startsWith("SELECT 1 FROM ") &&
                sql.includes("WHERE Certificate = $1 LIMIT 1")
            ) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("ORDER BY RotationOrdinal DESC")) {
                return { rowCount: 1, rows: [{ id: SUCCESSOR_ID }] };
            }
            return { rows: [], rowCount: 0 };
        });

        await RevokeCertificate(CERT_ID);

        expect(DeleteSecret).not.toHaveBeenCalled();
        expect(DeleteCertificate).not.toHaveBeenCalled();
        expect(UpdateLocalState).not.toHaveBeenCalled();
        expect(SiteCertificateChanged).toHaveBeenCalledWith(SUCCESSOR_ID);
        expect(AccessCertificateChanged).toHaveBeenCalledWith(SUCCESSOR_ID);
        expect(mockClient.query).toHaveBeenCalledWith(
            "SELECT 1 FROM TlsCertificates WHERE ObjectName = $1 AND Id <> $2 LIMIT 1",
            [certRow.objectname, CERT_ID]
        );
        for (const table of TLS_CERTIFICATE_PARENT_TABLES) {
            expect(mockClient.query).toHaveBeenCalledWith(parentFkSql(table), [CERT_ID]);
        }
    });

    it("rejects a malformed certificate id", async () => {
        await expect(RevokeCertificate("not-a-uuid")).rejects.toMatchObject({
            statusCode: 400,
            message: "Malformed certificate ID: not-a-uuid",
        });
        expect(ClientFromPool).not.toHaveBeenCalled();
    });

    it("returns 404 when the certificate row is missing", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 0, rows: [] });

        await expect(RevokeCertificate(CERT_ID)).rejects.toMatchObject({
            statusCode: 404,
            message: "Certificate not found",
        });
        expect(DeleteSecret).not.toHaveBeenCalled();
    });

    it("refuses CA revocation", async () => {
        mockClient.query.mockResolvedValue({
            rowCount: 1,
            rows: [{ ...certRow, isca: true }],
        });

        await expect(RevokeCertificate(CERT_ID)).rejects.toMatchObject({
            statusCode: 409,
            message: "CA certificate revocation is not supported",
        });
        expect(DeleteSecret).not.toHaveBeenCalled();
    });

    it("uses the caller-supplied reason", async () => {
        await RevokeCertificate(CERT_ID, { reason: "Evicted via API" });

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsClientRevocations"),
            [CERT_ID, certRow.expiration, "Evicted via API"]
        );
    });
});

describe("dropAccessPointCertificate", () => {
    const notify = {
        delete: vi.fn(),
    };

    beforeEach(() => {
        vi.clearAllMocks();
        notify.delete.mockReset();
    });

    it("unlinks and deletes the issued certificate", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM CertificateRequests")) {
                return { rows: [] };
            }
            if (sql.includes("SELECT Certificate FROM BackboneAccessPoints")) {
                return { rows: [{ certificate: CERT_ID }] };
            }
            if (sql.includes("FROM TlsCertificates")) {
                return { rowCount: 1, rows: [{ id: CERT_ID, objectname: "vms-access-req-1" }] };
            }
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 0, rows: [] };
            }
            return { rowCount: 1 };
        });

        const objectNames = await dropAccessPointCertificate(mockClient, notify, "ap-1");

        expect(objectNames).toEqual(["vms-access-req-1"]);
        expect(mockClient.query).toHaveBeenCalledWith(
            "UPDATE BackboneAccessPoints SET Certificate = NULL WHERE Id = $1",
            ["ap-1"]
        );
        expect(mockClient.query).toHaveBeenCalledWith(
            "UPDATE TlsCertificates SET Supercedes = NULL WHERE ObjectName = $1",
            ["vms-access-req-1"]
        );
        expect(mockClient.query).toHaveBeenCalledWith("DELETE FROM TlsCertificates WHERE Id = $1", [
            CERT_ID,
        ]);
        expect(notify.delete).toHaveBeenCalledWith("TlsCertificates", CERT_ID);
    });

    it("cancels pending certificate requests and keeps revoked rows", async () => {
        const requestId = "00000000-0000-4000-8000-000000000009";
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM CertificateRequests WHERE AccessPoint")) {
                return { rows: [{ id: requestId }] };
            }
            if (sql.includes("SELECT Certificate FROM BackboneAccessPoints")) {
                return { rows: [{ certificate: CERT_ID }] };
            }
            if (sql.includes("FROM TlsCertificates")) {
                return { rowCount: 1, rows: [{ id: CERT_ID, objectname: "vms-access-issued" }] };
            }
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 1, rows: [{}] };
            }
            return { rowCount: 1 };
        });

        const objectNames = await dropAccessPointCertificate(mockClient, notify, "ap-1");

        expect(objectNames).toEqual([`vms-access-${requestId}`, "vms-access-issued"]);
        expect(mockClient.query).toHaveBeenCalledWith(
            "DELETE FROM CertificateRequests WHERE Id = $1",
            [requestId]
        );
        expect(notify.delete).toHaveBeenCalledWith("CertificateRequests", requestId);
        expect(mockClient.query).not.toHaveBeenCalledWith(
            "DELETE FROM TlsCertificates WHERE Id = $1",
            [CERT_ID]
        );
    });

    it("returns an empty list when the access point has no certificate", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM CertificateRequests")) {
                return { rows: [] };
            }
            if (sql.includes("SELECT Certificate FROM BackboneAccessPoints")) {
                return { rows: [{ certificate: null }] };
            }
            return { rows: [], rowCount: 0 };
        });

        expect(await dropAccessPointCertificate(mockClient, notify, "ap-1")).toEqual([]);
        expect(notify.delete).not.toHaveBeenCalled();
    });
});

describe("deleteKubeTlsObjectList", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        DeleteSecret.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
    });

    it("deletes unique kube objects and ignores blanks", async () => {
        await deleteKubeTlsObjectList(["vms-access-a", "", "vms-access-a", "vms-access-b"]);

        expect(DeleteSecret).toHaveBeenCalledTimes(2);
        expect(DeleteCertificate).toHaveBeenCalledTimes(2);
        expect(DeleteSecret).toHaveBeenCalledWith("vms-access-a");
        expect(DeleteSecret).toHaveBeenCalledWith("vms-access-b");
    });
});
