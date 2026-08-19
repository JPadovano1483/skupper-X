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

vi.mock("./notify.js", () => ({
    NotifyTransaction: class {
        delete = vi.fn();
        async commit() {}
    },
}));

vi.mock("@vms/modules/kube", () => ({
    GetIssuers: vi.fn(async () => []),
    DeleteIssuer: vi.fn(),
    GetCertificates: vi.fn(async () => []),
    DeleteCertificate: vi.fn(),
    GetSecrets: vi.fn(async () => []),
    DeleteSecret: vi.fn(),
}));

import {
    DeleteOrphanCertificates,
    PruneNow,
    deleteUnreferencedKubeTls,
    reconcileCertificates,
} from "./prune.js";
import {
    GetIssuers,
    DeleteIssuer,
    GetCertificates,
    DeleteCertificate,
    GetSecrets,
    DeleteSecret,
} from "@vms/modules/kube";
import { META_ANNOTATION_VMS_CONTROLLED } from "@vms/modules/common";

function kubeObj(name, controlled = true) {
    return {
        metadata: {
            name,
            annotations: controlled ? { [META_ANNOTATION_VMS_CONTROLLED]: "true" } : {},
        },
    };
}

describe("DeleteOrphanCertificates", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("SELECT Id, SignedBy FROM TlsCertificates")) {
                return { rows: [{ id: "orphan-cert", signedby: null }] };
            }
            if (sql.includes("SELECT Id, Certificate FROM")) {
                return { rows: [] };
            }
            if (sql.startsWith("DELETE FROM TlsCertificates")) {
                return { rowCount: 1 };
            }
            return { rows: [] };
        });
    });

    it("deletes tls certificates not referenced by other tables", async () => {
        await DeleteOrphanCertificates();

        expect(mockClient.query).toHaveBeenCalledWith(
            "DELETE FROM TlsClientRevocations WHERE Expiration IS NOT NULL AND Expiration < CURRENT_TIMESTAMP"
        );
        expect(mockClient.query).toHaveBeenCalledWith("DELETE FROM TlsCertificates WHERE Id = $1", [
            "orphan-cert",
        ]);
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("does not delete certificates that still have a revocation row", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("DELETE FROM TlsClientRevocations")) {
                return { rowCount: 0 };
            }
            if (sql.includes("SELECT Id, SignedBy FROM TlsCertificates")) {
                return { rows: [{ id: "revoked-cert", signedby: null }] };
            }
            if (sql.includes("SELECT CertificateId FROM TlsClientRevocations")) {
                return { rows: [{ certificateid: "revoked-cert" }] };
            }
            if (sql.includes("SELECT Id, Certificate FROM")) {
                return { rows: [] };
            }
            if (sql.startsWith("DELETE FROM TlsCertificates")) {
                return { rowCount: 1 };
            }
            return { rows: [] };
        });

        await DeleteOrphanCertificates();

        expect(mockClient.query).not.toHaveBeenCalledWith(
            "DELETE FROM TlsCertificates WHERE Id = $1",
            ["revoked-cert"]
        );
    });
});

describe("reconcileCertificates", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockResolvedValue({
            rows: [{ objectname: "keep-me" }, { objectname: null }],
        });
        GetIssuers.mockResolvedValue([
            kubeObj("keep-me"),
            kubeObj("orphan-issuer"),
            kubeObj("uncontrolled-issuer", false),
        ]);
        GetCertificates.mockResolvedValue([kubeObj("keep-me"), kubeObj("orphan-cert")]);
        GetSecrets.mockResolvedValue([kubeObj("keep-me"), kubeObj("orphan-secret")]);
        DeleteIssuer.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
        DeleteSecret.mockResolvedValue({});
    });

    it("deletes vms-controlled kube objects whose names are not in TlsCertificates", async () => {
        await reconcileCertificates();

        expect(DeleteIssuer).toHaveBeenCalledWith("orphan-issuer");
        expect(DeleteIssuer).not.toHaveBeenCalledWith("keep-me");
        expect(DeleteIssuer).not.toHaveBeenCalledWith("uncontrolled-issuer");
        expect(DeleteCertificate).toHaveBeenCalledWith("orphan-cert");
        expect(DeleteCertificate).not.toHaveBeenCalledWith("keep-me");
        expect(DeleteSecret).toHaveBeenCalledWith("orphan-secret");
        expect(DeleteSecret).not.toHaveBeenCalledWith("keep-me");
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("continues when a kube delete fails", async () => {
        DeleteIssuer.mockRejectedValue(new Error("issuer gone"));

        await reconcileCertificates();

        expect(DeleteCertificate).toHaveBeenCalledWith("orphan-cert");
        expect(DeleteSecret).toHaveBeenCalledWith("orphan-secret");
    });
});

describe("deleteUnreferencedKubeTls", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        DeleteSecret.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
    });

    it("skips kube delete when any TlsCertificates row still uses the object name", async () => {
        mockClient.query.mockResolvedValue({
            rows: [{ objectname: "vms-site-1" }],
        });

        await deleteUnreferencedKubeTls(["vms-site-1", "vms-access-1", "", "vms-site-1"]);

        expect(mockClient.query).toHaveBeenCalledWith(
            "SELECT DISTINCT ObjectName FROM TlsCertificates WHERE ObjectName = ANY($1)",
            [["vms-site-1", "vms-access-1"]]
        );
        expect(DeleteSecret).toHaveBeenCalledWith("vms-access-1");
        expect(DeleteCertificate).toHaveBeenCalledWith("vms-access-1");
        expect(DeleteSecret).not.toHaveBeenCalledWith("vms-site-1");
        expect(DeleteCertificate).not.toHaveBeenCalledWith("vms-site-1");
    });

    it("does not query when there are no object names", async () => {
        await deleteUnreferencedKubeTls(["", null]);

        expect(mockClient.query).not.toHaveBeenCalled();
        expect(DeleteSecret).not.toHaveBeenCalled();
    });
});

describe("PruneNow", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("SELECT Id, SignedBy FROM TlsCertificates")) {
                return { rows: [] };
            }
            if (sql.includes("SELECT Id, Certificate FROM")) {
                return { rows: [] };
            }
            if (sql.includes("SELECT ObjectName FROM TlsCertificates")) {
                return { rows: [] };
            }
            return { rows: [] };
        });
        GetIssuers.mockResolvedValue([]);
        GetCertificates.mockResolvedValue([]);
        GetSecrets.mockResolvedValue([]);
    });

    it("deletes orphan db certs then reconciles kube objects", async () => {
        await PruneNow();

        expect(mockClient.query).toHaveBeenCalledWith(
            "DELETE FROM TlsClientRevocations WHERE Expiration IS NOT NULL AND Expiration < CURRENT_TIMESTAMP"
        );
        expect(GetIssuers).toHaveBeenCalled();
        expect(GetCertificates).toHaveBeenCalled();
        expect(GetSecrets).toHaveBeenCalled();
    });
});
