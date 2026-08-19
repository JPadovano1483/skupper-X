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

vi.mock("@vms/modules/state-sync", () => ({
    DeletePeer: vi.fn(),
    UpdateLocalState: vi.fn(),
}));

vi.mock("@vms/modules/kube", () => ({
    LoadSecret: vi.fn(),
    DeleteSecret: vi.fn(),
    DeleteCertificate: vi.fn(),
}));

vi.mock("./backbone-links.js", () => ({
    RegisterHandler: vi.fn(),
}));

vi.mock("./notify.js", () => ({
    RegisterNotification: vi.fn(),
    NotifyTransaction: class {
        add() {}
        update() {}
        delete() {}
        async commit() {}
    },
}));

const mockClient = {
    query: vi.fn(),
    release: vi.fn(),
};

vi.mock("./db.js", () => ({
    ClientFromPool: vi.fn(async () => mockClient),
}));

import {
    GetBackboneLinks_TX,
    GetBackboneAccessPoints_TX,
    SiteDeleted,
    SiteCertificateChanged,
    SiteIngressChanged,
    MemberEvicted,
    _registerPeerForTest,
    _onNewMemberForTest,
    _onLostMemberForTest,
    _getStateTlsMemberSiteForTest,
    _onStateChangeBackboneForTest,
} from "./sync-management.js";
import { DeletePeer, UpdateLocalState } from "@vms/modules/state-sync";
import { LoadSecret, DeleteSecret, DeleteCertificate } from "@vms/modules/kube";

describe("GetBackboneLinks_TX", () => {
    it("returns links keyed by id with hostname", async () => {
        const client = {
            query: vi.fn(async () => ({
                rows: [
                    {
                        id: "link-1",
                        hostname: "router.example.com",
                        port: 9090,
                        cost: 2,
                    },
                ],
            })),
        };

        const links = await GetBackboneLinks_TX(client, "site-1");

        expect(links).toEqual({
            "link-1": {
                host: "router.example.com",
                port: 9090,
                cost: "2",
            },
        });
    });

    it("omits links without hostname", async () => {
        const client = {
            query: vi.fn(async () => ({
                rows: [
                    {
                        id: "link-2",
                        hostname: null,
                        port: 9090,
                        cost: 1,
                    },
                ],
            })),
        };

        const links = await GetBackboneLinks_TX(client, "site-1");

        expect(links).toEqual({});
    });
});

describe("GetBackboneAccessPoints_TX", () => {
    it("includes manage access points when initialOnly is true", async () => {
        const client = {
            query: vi.fn(async () => ({
                rows: [
                    {
                        id: "ap-manage",
                        kind: "manage",
                        bindhost: "",
                        accesstype: "local",
                        colocated: false,
                    },
                    {
                        id: "ap-van",
                        kind: "van",
                        bindhost: "",
                        accesstype: "",
                        colocated: false,
                    },
                ],
            })),
        };

        const accessPoints = await GetBackboneAccessPoints_TX(client, "site-1", true);

        expect(Object.keys(accessPoints)).toEqual(["ap-manage"]);
        expect(accessPoints["ap-manage"]).toEqual({ kind: "manage", accessType: "local" });
    });

    it("includes all access points when initialOnly is false", async () => {
        const client = {
            query: vi.fn(async () => ({
                rows: [
                    {
                        id: "ap-manage",
                        kind: "manage",
                        bindhost: "0.0.0.0",
                        accesstype: "",
                        colocated: false,
                    },
                    {
                        id: "ap-van",
                        kind: "van",
                        bindhost: "",
                        accesstype: "",
                        colocated: false,
                    },
                ],
            })),
        };

        const accessPoints = await GetBackboneAccessPoints_TX(client, "site-1", false);

        expect(Object.keys(accessPoints).sort((a, b) => a.localeCompare(b))).toEqual([
            "ap-manage",
            "ap-van",
        ]);
        expect(accessPoints["ap-manage"].bindhost).toBe("0.0.0.0");
    });
});

describe("SiteDeleted", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        mockClient.query.mockResolvedValue({ rows: [] });
    });

    it("nulls tls-site and tls-server state before DeletePeer", async () => {
        mockClient.query.mockResolvedValue({
            rows: [{ id: "ap-1" }, { id: "ap-2" }],
        });

        await SiteDeleted("site-1");

        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-site-site-1", null);
        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-server-ap-1", null);
        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-server-ap-2", null);
        expect(DeletePeer).toHaveBeenCalledWith("site-1");
        expect(UpdateLocalState.mock.invocationCallOrder[0]).toBeLessThan(
            DeletePeer.mock.invocationCallOrder[0]
        );
    });

    it("uses provided access point ids without querying", async () => {
        await SiteDeleted("site-1", ["ap-9"]);

        expect(mockClient.query).not.toHaveBeenCalled();
        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-site-site-1", null);
        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-server-ap-9", null);
        expect(DeletePeer).toHaveBeenCalledWith("site-1");
    });

    it("still deletes the peer when access-point lookup fails", async () => {
        mockClient.query.mockRejectedValue(new Error("db down"));

        await SiteDeleted("site-1");

        expect(UpdateLocalState).toHaveBeenCalledWith("site-1", "tls-site-site-1", null);
        expect(DeletePeer).toHaveBeenCalledWith("site-1");
    });
});

describe("SiteCertificateChanged", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
    });

    it("updates tls-site state hash for connected backbone sites", async () => {
        _registerPeerForTest("site-1", "backbone");

        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("FROM InteriorSites") && sql.includes("Certificate = $1")) {
                return {
                    rowCount: 1,
                    rows: [{ id: "site-1", objectname: "site-tls-secret" }],
                };
            }
            return { rows: [] };
        });

        LoadSecret.mockResolvedValue({
            data: { "tls.crt": Buffer.from("cert").toString("base64") },
        });

        await SiteCertificateChanged("cert-1");

        expect(LoadSecret).toHaveBeenCalledWith("site-tls-secret");
        expect(UpdateLocalState).toHaveBeenCalledWith(
            "site-1",
            "tls-site-site-1",
            expect.stringMatching(/^[a-f0-9]{40}$/)
        );
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("skips update when site is not connected", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("FROM InteriorSites") && sql.includes("Certificate = $1")) {
                return {
                    rowCount: 1,
                    rows: [{ id: "site-offline", objectname: "site-tls-secret" }],
                };
            }
            return { rows: [] };
        });

        await SiteCertificateChanged("cert-2");

        expect(LoadSecret).not.toHaveBeenCalled();
        expect(UpdateLocalState).not.toHaveBeenCalled();
    });

    it("updates tls-site state hash for connected member sites", async () => {
        _registerPeerForTest("member-1", "member");

        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("FROM InteriorSites") && sql.includes("UNION")) {
                return {
                    rowCount: 1,
                    rows: [{ id: "member-1", objectname: "member-tls-secret" }],
                };
            }
            return { rows: [] };
        });

        LoadSecret.mockResolvedValue({
            data: { "tls.crt": Buffer.from("member-cert").toString("base64") },
        });

        await SiteCertificateChanged("cert-member-1");

        expect(LoadSecret).toHaveBeenCalledWith("member-tls-secret");
        expect(UpdateLocalState).toHaveBeenCalledWith(
            "member-1",
            "tls-site-member-1",
            expect.stringMatching(/^[a-f0-9]{40}$/)
        );
    });
});

describe("SiteIngressChanged", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
    });

    it("updates access point hash for connected sites", async () => {
        _registerPeerForTest("site-2", "backbone");

        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("FROM BackboneAccessPoints JOIN InteriorSites")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            kind: "manage",
                            bindhost: "0.0.0.0",
                            accesstype: "local",
                            certificate: "cert-ap",
                            lifecycle: "ready",
                            colocated: false,
                        },
                    ],
                };
            }
            return { rows: [] };
        });

        await SiteIngressChanged("site-2", "ap-1");

        expect(UpdateLocalState).toHaveBeenCalledWith(
            "site-2",
            "access-ap-1",
            expect.stringMatching(/^[a-f0-9]{40}$/)
        );
        expect(mockClient.release).toHaveBeenCalled();
    });
});

describe("MemberEvicted", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("clears tls-site state for the evicted member", async () => {
        _registerPeerForTest("member-1", "member");

        await MemberEvicted("member-1");

        expect(UpdateLocalState).toHaveBeenCalledWith("member-1", "tls-site-member-1", null);
    });

    it("does not throw when the peer is unknown", async () => {
        await expect(MemberEvicted("offline-member")).resolves.toBeUndefined();

        expect(UpdateLocalState).toHaveBeenCalledWith(
            "offline-member",
            "tls-site-offline-member",
            null
        );
    });
});

function memberTlsQueryHandler({
    lifecycle = "ready",
    certificate = "cert-1",
    objectname = "member-tls-secret",
    revoked = false,
} = {}) {
    return async (sql) => {
        if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
            return {};
        }
        if (sql.includes("FROM TlsClientRevocations")) {
            return { rowCount: revoked ? 1 : 0, rows: revoked ? [{}] : [] };
        }
        if (sql.includes("FROM MemberSites") && sql.includes("TlsCertificates")) {
            return {
                rowCount: 1,
                rows: [
                    {
                        lifecycle,
                        firstactivetime: null,
                        certificate,
                        objectname,
                    },
                ],
            };
        }
        if (sql.includes("FROM EdgeLinks")) {
            return { rows: [] };
        }
        if (sql.includes("UPDATE MemberSites")) {
            return { rowCount: 1 };
        }
        return { rows: [] };
    };
}

describe("getStateTlsMemberSite", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        LoadSecret.mockResolvedValue({
            data: { "tls.crt": Buffer.from("member-cert").toString("base64") },
        });
    });

    it("returns a secret hash for an active member", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "active" }));

        const [hash, data] = await _getStateTlsMemberSiteForTest("member-1");

        expect(LoadSecret).toHaveBeenCalledWith("member-tls-secret");
        expect(hash).toMatch(/^[a-f0-9]{40}$/);
        expect(data).toEqual({ "tls.crt": Buffer.from("member-cert").toString("base64") });
    });

    it("returns a null hash for an expired member without loading the secret", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "expired" }));

        const [hash, data] = await _getStateTlsMemberSiteForTest("member-1");

        expect(LoadSecret).not.toHaveBeenCalled();
        expect(hash).toBeNull();
        expect(data).toBeNull();
    });

    it("returns a null hash for a revoked certificate without loading the secret", async () => {
        mockClient.query.mockImplementation(
            memberTlsQueryHandler({ lifecycle: "active", revoked: true })
        );

        const [hash, data] = await _getStateTlsMemberSiteForTest("member-1");

        expect(LoadSecret).not.toHaveBeenCalled();
        expect(hash).toBeNull();
        expect(data).toBeNull();
    });

    it("returns a null hash when the kube secret is missing", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "active" }));
        LoadSecret.mockResolvedValue(undefined);

        const [hash, data] = await _getStateTlsMemberSiteForTest("member-1");

        expect(hash).toBeNull();
        expect(data).toBeNull();
    });
});

describe("onNewMember", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        LoadSecret.mockResolvedValue({
            data: { "tls.crt": Buffer.from("member-cert").toString("base64") },
        });
    });

    it("loads the secret and promotes a ready member to active", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "ready" }));

        const [localState] = await _onNewMemberForTest("member-1");

        expect(LoadSecret).toHaveBeenCalledWith("member-tls-secret");
        expect(localState["tls-site-member-1"]).toMatch(/^[a-f0-9]{40}$/);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("LifeCycle = 'active'"),
            ["member-1"]
        );
    });

    it("advertises a null tls-site hash for expired members and does not promote them", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "expired" }));

        const [localState] = await _onNewMemberForTest("member-1");

        expect(LoadSecret).not.toHaveBeenCalled();
        expect(localState["tls-site-member-1"]).toBeNull();
        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("LifeCycle = 'active'"),
            expect.anything()
        );
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1"),
            ["member-1"]
        );
    });

    it("advertises a null tls-site hash for revoked certs and does not load the secret", async () => {
        mockClient.query.mockImplementation(
            memberTlsQueryHandler({ lifecycle: "active", revoked: true })
        );

        const [localState] = await _onNewMemberForTest("member-1");

        expect(LoadSecret).not.toHaveBeenCalled();
        expect(localState["tls-site-member-1"]).toBeNull();
    });

    it("does not load the secret when an evicted member reconnects", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "expired" }));

        const [localState] = await _onNewMemberForTest("member-1");

        expect(LoadSecret).not.toHaveBeenCalled();
        expect(localState["tls-site-member-1"]).toBeNull();
        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("LifeCycle = 'active'"),
            expect.anything()
        );
    });

    it("advertises a null tls-site hash when the kube secret is missing", async () => {
        mockClient.query.mockImplementation(memberTlsQueryHandler({ lifecycle: "active" }));
        LoadSecret.mockResolvedValue(undefined);

        const [localState] = await _onNewMemberForTest("member-1");

        expect(localState["tls-site-member-1"]).toBeNull();
        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("LifeCycle = 'active'"),
            expect.anything()
        );
    });
});

describe("onLostMember", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("UPDATE MemberSites")) {
                return { rowCount: 1 };
            }
            return { rows: [] };
        });
    });

    it("updates LastHeartbeat without resurrecting certs or lifecycle", async () => {
        await _onLostMemberForTest("member-1");

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1"),
            ["member-1"]
        );
        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("LifeCycle = 'active'"),
            expect.anything()
        );
        expect(LoadSecret).not.toHaveBeenCalled();
        expect(UpdateLocalState).not.toHaveBeenCalled();
        expect(mockClient.release).toHaveBeenCalled();
    });
});

function accessStatusQueryHandler({
    found = true,
    lifecycle = "ready",
    hostname = "old.example.com",
    port = "9090",
    certificate = "cert-ap-1",
    objectname = "vms-access-req-1",
    pendingRequests = [],
    revoked = false,
} = {}) {
    return async (sql) => {
        if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
            return {};
        }
        if (
            sql.includes(
                "SELECT Id, Lifecycle, Hostname, Port, Certificate FROM BackboneAccessPoints"
            )
        ) {
            if (!found) {
                return { rowCount: 0, rows: [] };
            }
            return {
                rowCount: 1,
                rows: [
                    {
                        id: "ap-1",
                        lifecycle,
                        hostname,
                        port,
                        certificate,
                    },
                ],
            };
        }
        if (sql.includes("FROM CertificateRequests WHERE AccessPoint")) {
            return { rows: pendingRequests.map((id) => ({ id })) };
        }
        if (sql.includes("SELECT Certificate FROM BackboneAccessPoints")) {
            return { rows: [{ certificate }] };
        }
        if (sql.includes("FROM TlsCertificates WHERE Id")) {
            return {
                rowCount: objectname ? 1 : 0,
                rows: objectname ? [{ objectname }] : [],
            };
        }
        if (sql.includes("FROM TlsClientRevocations")) {
            return { rowCount: revoked ? 1 : 0, rows: revoked ? [{}] : [] };
        }
        if (sql.includes("UPDATE BackboneAccessPoints")) {
            return { rowCount: 1 };
        }
        if (
            sql.includes("DELETE FROM TlsCertificates") ||
            sql.includes("DELETE FROM CertificateRequests")
        ) {
            return { rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
    };
}

describe("onStateChangeBackbone", () => {
    const siteId = "site-1";
    const accessId = "ap-1";

    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        DeleteSecret.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
    });

    it("sets host/port and lifecycle new for a partial access point", async () => {
        mockClient.query.mockImplementation(
            accessStatusQueryHandler({
                lifecycle: "partial",
                hostname: null,
                port: null,
                certificate: null,
                objectname: null,
            })
        );

        await _onStateChangeBackboneForTest(siteId, `accessstatus-${accessId}`, "hash-1", {
            host: "router.example.com",
            port: 9090,
        });

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("Lifecycle = 'new'"),
            ["router.example.com", 9090, accessId]
        );
        expect(DeleteSecret).not.toHaveBeenCalled();
        expect(DeleteCertificate).not.toHaveBeenCalled();
        expect(UpdateLocalState).not.toHaveBeenCalled();
    });

    it("deletes the TLS cert and re-issues when a ready access point hostname changes", async () => {
        mockClient.query.mockImplementation(accessStatusQueryHandler());

        await _onStateChangeBackboneForTest(siteId, `accessstatus-${accessId}`, "hash-2", {
            host: "new.example.com",
            port: 9090,
        });

        expect(mockClient.query).toHaveBeenCalledWith(
            "UPDATE BackboneAccessPoints SET Certificate = NULL WHERE Id = $1",
            [accessId]
        );
        expect(mockClient.query).toHaveBeenCalledWith("DELETE FROM TlsCertificates WHERE Id = $1", [
            "cert-ap-1",
        ]);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("Lifecycle = 'new'"),
            ["new.example.com", 9090, accessId]
        );
        expect(DeleteSecret).toHaveBeenCalledWith("vms-access-req-1");
        expect(DeleteCertificate).toHaveBeenCalledWith("vms-access-req-1");
        expect(UpdateLocalState).toHaveBeenCalledWith(siteId, `tls-server-${accessId}`, null);
    });

    it("returns the access point to partial and drops the cert when host/port is deleted", async () => {
        mockClient.query.mockImplementation(accessStatusQueryHandler());

        await _onStateChangeBackboneForTest(siteId, `accessstatus-${accessId}`, null, {});

        expect(mockClient.query).toHaveBeenCalledWith("DELETE FROM TlsCertificates WHERE Id = $1", [
            "cert-ap-1",
        ]);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("Lifecycle = 'partial'"),
            [accessId]
        );
        expect(DeleteSecret).toHaveBeenCalledWith("vms-access-req-1");
        expect(DeleteCertificate).toHaveBeenCalledWith("vms-access-req-1");
        expect(UpdateLocalState).toHaveBeenCalledWith(siteId, `tls-server-${accessId}`, null);
    });

    it("ignores host/port deletion when the access point row is already gone", async () => {
        mockClient.query.mockImplementation(accessStatusQueryHandler({ found: false }));

        await expect(
            _onStateChangeBackboneForTest(siteId, `accessstatus-${accessId}`, null, {})
        ).resolves.toBeUndefined();

        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("Lifecycle = 'partial'"),
            expect.anything()
        );
        expect(DeleteSecret).not.toHaveBeenCalled();
        expect(UpdateLocalState).not.toHaveBeenCalled();
    });

    it("does not re-issue when host and port are unchanged on a ready access point", async () => {
        mockClient.query.mockImplementation(accessStatusQueryHandler());

        await _onStateChangeBackboneForTest(siteId, `accessstatus-${accessId}`, "hash-same", {
            host: "old.example.com",
            port: 9090,
        });

        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("Lifecycle = 'new'"),
            expect.anything()
        );
        expect(DeleteSecret).not.toHaveBeenCalled();
        expect(UpdateLocalState).not.toHaveBeenCalled();
    });
});
