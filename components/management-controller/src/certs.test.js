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

/** @type {Record<string, Function>} */
const notificationHandlers = {};
let secretWatchHandler;

/** @type {Array<{ method: string, table: string, id: string }>} */
const notifyEvents = [];

vi.mock("@vms/modules/kube", () => ({
    ApplyObject: vi.fn(),
    LoadCertificate: vi.fn(),
    TriggerCertificateRenewal: vi.fn(),
    WatchSecrets: vi.fn((handler) => {
        secretWatchHandler = handler;
    }),
    WatchCertificates: vi.fn(),
    GetIssuers: vi.fn(async () => []),
}));

vi.mock("./config.js", () => ({
    BackboneExpiration: vi.fn(() => ({ years: 1 })),
    DefaultCaExpiration: vi.fn(() => ({ days: 30 })),
    DefaultCertExpiration: vi.fn(() => ({ days: 7 })),
    CertRenewBefore: vi.fn(() => ({ days: 30 })),
    SiteControllerImage: vi.fn(() => "quay.io/skupper/vms-site-controller:latest"),
    RootIssuer: vi.fn(() => "vms-root"),
    CertOrganization: vi.fn(() => "enterprise.com"),
}));

vi.mock("./sync-management.js", () => ({
    SiteCertificateChanged: vi.fn(),
    AccessCertificateChanged: vi.fn(),
}));

vi.mock("./claim-server.js", () => ({
    CompleteMember: vi.fn(),
}));

vi.mock("./site-deployment-state.js", () => ({
    AccessPointCertReady: vi.fn(),
    SiteLifecycleChanged_TX: vi.fn(),
}));

vi.mock("./watch-server.js", () => ({
    WatchNotify: vi.fn(),
}));

vi.mock("./db.js", () => ({
    ClientFromPool: vi.fn(async () => mockClient),
    IntervalMilliseconds: vi.fn((value) => {
        if (value?.years) {
            return value.years * 365 * 24 * 3600000;
        }
        if (value?.days) {
            return value.days * 24 * 3600000;
        }
        if (value?.hours) {
            return value.hours * 3600000;
        }
        return 3600000;
    }),
}));

vi.mock("./notify.js", () => ({
    RegisterNotification: vi.fn((tableName, handler) => {
        notificationHandlers[tableName] = handler;
    }),
    NotifyTransaction: class {
        add(table, id) {
            notifyEvents.push({ method: "add", table, id });
        }
        update(table, id) {
            notifyEvents.push({ method: "update", table, id });
        }
        delete(table, id) {
            notifyEvents.push({ method: "delete", table, id });
        }
        async commit() {}
    },
}));

import { Start, RotateCertificate } from "./certs.js";
import { RegisterNotification } from "./notify.js";
import { ApplyObject, LoadCertificate, TriggerCertificateRenewal } from "@vms/modules/kube";
import { SiteCertificateChanged, AccessCertificateChanged } from "./sync-management.js";

function transactionSql(sql) {
    return sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK";
}

describe("certs Start", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        secretWatchHandler = undefined;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
    });

    it("registers notification handlers for certificate lifecycle tables", async () => {
        await Start();

        expect(RegisterNotification).toHaveBeenCalledWith(
            "ManagementControllers",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith("Backbones", expect.any(Function), true);
        expect(RegisterNotification).toHaveBeenCalledWith(
            "BackboneAccessPoints",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "ApplicationNetworks",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "NetworkCredentials",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "InteriorSites",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "MemberInvitations",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "MemberSites",
            expect.any(Function),
            true
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "CertificateRequests",
            expect.any(Function),
            false
        );
    });
});

describe("onManagementControllersChange", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("creates mgmtController certificate request for new controller rows", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM ManagementControllers WHERE Lifecycle = 'new'")) {
                return {
                    rowCount: 1,
                    rows: [{ id: "mc-uuid-1", name: "management-server-abc" }],
                };
            }
            if (sql.includes("INSERT INTO CertificateRequests")) {
                return { rows: [{ id: "cert-req-1" }] };
            }
            if (sql.includes("UPDATE ManagementControllers SET Lifecycle = 'vms_cr_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.ManagementControllers("UPDATE", "mc-uuid-1");

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("'mgmtController'"),
            expect.arrayContaining(["mc-uuid-1"])
        );
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining(
                "UPDATE ManagementControllers SET Lifecycle = 'vms_cr_created'"
            ),
            ["mc-uuid-1"]
        );
        expect(notifyEvents).toContainEqual({
            method: "add",
            table: "CertificateRequests",
            id: "cert-req-1",
        });
        expect(notifyEvents).toContainEqual({
            method: "update",
            table: "ManagementControllers",
            id: "mc-uuid-1",
        });
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("ignores DELETE actions", async () => {
        await notificationHandlers.ManagementControllers("DELETE", "mc-uuid-1");
        expect(mockClient.query).not.toHaveBeenCalled();
    });
});

describe("onBackbonesChange", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("creates backboneCA certificate request for new backbone rows", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM Backbones WHERE id = $1")) {
                return {
                    rowCount: 1,
                    rows: [{ id: "bb-uuid-1", name: "backbone-a", lifecycle: "new" }],
                };
            }
            if (sql.includes("INSERT INTO CertificateRequests")) {
                return { rows: [{ id: "cert-req-2" }] };
            }
            if (sql.includes("UPDATE Backbones SET Lifecycle = 'vms_cr_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.Backbones("UPDATE", "bb-uuid-1");

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("'backboneCA'"),
            expect.arrayContaining(["bb-uuid-1"])
        );
        expect(notifyEvents).toContainEqual({
            method: "add",
            table: "CertificateRequests",
            id: "cert-req-2",
        });
        expect(notifyEvents).toContainEqual({
            method: "update",
            table: "Backbones",
            id: "bb-uuid-1",
        });
    });

    it("notifies dependents when backbone lifecycle is ready", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM Backbones WHERE id = $1")) {
                return {
                    rowCount: 1,
                    rows: [{ id: "bb-uuid-1", name: "backbone-a", lifecycle: "ready" }],
                };
            }
            if (sql.includes("FROM BackboneAccessPoints AS ap")) {
                return { rows: [{ id: "ap-1" }] };
            }
            if (sql.includes("FROM ApplicationNetworks WHERE Backbone = $1")) {
                return { rows: [{ id: "van-1" }] };
            }
            if (sql.includes("FROM InteriorSites WHERE Backbone = $1")) {
                return { rows: [{ id: "site-1" }] };
            }
            if (sql.includes("FROM NetworkCredentials AS cred")) {
                return { rows: [{ id: "cred-1" }] };
            }
            return {};
        });

        await notificationHandlers.Backbones("UPDATE", "bb-uuid-1");

        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO CertificateRequests"),
            expect.anything()
        );
        expect(notifyEvents).toEqual([
            { method: "update", table: "BackboneAccessPoints", id: "ap-1" },
            { method: "update", table: "ApplicationNetworks", id: "van-1" },
            { method: "update", table: "InteriorSites", id: "site-1" },
            { method: "update", table: "NetworkCredentials", id: "cred-1" },
        ]);
    });
});

describe("onCertificateRequestsChange", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("processes due certificate requests on ADD", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM CertificateRequests WHERE RequestTime")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: "cert-req-3",
                            requesttype: "mgmtController",
                            durationhours: 8760,
                        },
                    ],
                };
            }
            if (sql.includes("UPDATE CertificateRequests SET Lifecycle = 'cm_cert_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.CertificateRequests("ADD", "cert-req-3");

        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                kind: "Certificate",
                metadata: expect.objectContaining({
                    name: "vms-mgmt-controller-cert-req-3",
                }),
                spec: expect.objectContaining({
                    duration: "8760h",
                    renewBefore: "720h",
                }),
            })
        );
        expect(notifyEvents).toContainEqual({
            method: "update",
            table: "CertificateRequests",
            id: "cert-req-3",
        });
    });

    it("clamps renewBefore to one-third of duration when the configured window does not fit", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM CertificateRequests WHERE RequestTime")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: "cert-req-short",
                            requesttype: "mgmtController",
                            durationhours: 24,
                        },
                    ],
                };
            }
            if (sql.includes("UPDATE CertificateRequests SET Lifecycle = 'cm_cert_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.CertificateRequests("ADD", "cert-req-short");

        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                spec: expect.objectContaining({
                    duration: "24h",
                    renewBefore: "8h",
                }),
            })
        );
    });

    it("ignores non-ADD actions", async () => {
        await notificationHandlers.CertificateRequests("UPDATE", "cert-req-3");
        expect(mockClient.query).not.toHaveBeenCalled();
        expect(ApplyObject).not.toHaveBeenCalled();
    });
});

describe("onBackboneAccessPointsChange", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("creates accessPoint certificate request for new access points on ready backbones", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM BackboneAccessPoints") && sql.includes("Lifecycle = 'new'")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: "ap-uuid-1",
                            name: "manage-ap",
                            hostname: "router.example.com",
                            starttime: null,
                            endtime: null,
                            deletedelay: null,
                        },
                    ],
                };
            }
            if (sql.includes("INSERT INTO CertificateRequests")) {
                return { rows: [{ id: "cert-req-ap-1" }] };
            }
            if (sql.includes("UPDATE BackboneAccessPoints SET Lifecycle = 'vms_cr_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.BackboneAccessPoints("UPDATE", "ap-uuid-1");

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("'accessPoint'"),
            expect.arrayContaining(["ap-uuid-1"])
        );
        expect(notifyEvents).toContainEqual({
            method: "add",
            table: "CertificateRequests",
            id: "cert-req-ap-1",
        });
    });
});

describe("onApplicationNetworksChange", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("creates vanCA certificate request for new application networks", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM ApplicationNetworks") && sql.includes("Backbones.Lifecycle")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: "van-uuid-1",
                            name: "van-a",
                            lifecycle: "new",
                            starttime: new Date("2026-01-01T00:00:00Z"),
                            endtime: null,
                            deletedelay: null,
                            bbca: "bb-ca-1",
                        },
                    ],
                };
            }
            if (sql.includes("INSERT INTO CertificateRequests")) {
                return { rows: [{ id: "cert-req-van-1" }] };
            }
            if (sql.includes("UPDATE ApplicationNetworks SET Lifecycle = 'vms_cr_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.ApplicationNetworks("UPDATE", "van-uuid-1");

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("'vanCA'"),
            expect.arrayContaining(["van-uuid-1"])
        );
        expect(notifyEvents).toContainEqual({
            method: "add",
            table: "CertificateRequests",
            id: "cert-req-van-1",
        });
    });

    it("notifies member invitations and sites when network becomes ready", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM ApplicationNetworks") && sql.includes("Backbones.Lifecycle")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: "van-uuid-2",
                            name: "van-b",
                            lifecycle: "ready",
                            bbca: "bb-ca-1",
                        },
                    ],
                };
            }
            if (sql.includes("FROM MemberInvitations WHERE MemberOf")) {
                return { rows: [{ id: "invite-1" }] };
            }
            if (sql.includes("FROM MemberSites WHERE MemberOf")) {
                return { rows: [{ id: "member-1" }] };
            }
            return {};
        });

        await notificationHandlers.ApplicationNetworks("UPDATE", "van-uuid-2");

        expect(notifyEvents).toEqual([
            { method: "update", table: "MemberInvitations", id: "invite-1" },
            { method: "update", table: "MemberSites", id: "member-1" },
        ]);
    });
});

describe("onInteriorSitesChange", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("creates interiorRouter certificate request for new interior sites", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM InteriorSites") && sql.includes("Lifecycle = 'new'")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: "site-uuid-1",
                            name: "backbone-site-a",
                            bbca: "bb-ca-1",
                        },
                    ],
                };
            }
            if (sql.includes("INSERT INTO CertificateRequests")) {
                return { rows: [{ id: "cert-req-site-1" }] };
            }
            if (sql.includes("UPDATE InteriorSites SET Lifecycle = 'vms_cr_created'")) {
                return {};
            }
            return {};
        });

        await notificationHandlers.InteriorSites("UPDATE", "site-uuid-1");

        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("'interiorRouter'"),
            expect.arrayContaining(["site-uuid-1"])
        );
        expect(notifyEvents).toContainEqual({
            method: "add",
            table: "CertificateRequests",
            id: "cert-req-site-1",
        });
    });
});

describe("onSecretWatch", () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        notifyEvents.length = 0;
        secretWatchHandler = undefined;
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        await Start();
    });

    it("propagates secret MODIFIED renewals for managed certs", async () => {
        LoadCertificate.mockResolvedValue({
            status: {
                notAfter: "2026-10-12T12:00:00.000Z",
                renewalTime: "2026-10-11T12:00:00.000Z",
            },
        });
        mockClient.query.mockImplementation(async (sql) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("SELECT Id FROM TlsCertificates WHERE Id = $1 AND ObjectName = $2")) {
                return { rowCount: 1, rows: [{ id: "cert-1" }] };
            }
            if (sql.includes("UPDATE TlsCertificates SET Expiration = $1, RenewalTime = $2")) {
                return {};
            }
            return { rowCount: 0, rows: [] };
        });

        secretWatchHandler("MODIFIED", {
            metadata: {
                name: "vms-interior-cert-1",
                resourceVersion: "42",
                annotations: {
                    "skupper.io/vms-controlled": "true",
                    "skupper.io/vms-dblink": "cert-1",
                },
            },
            data: {
                "tls.crt": "base64-cert",
            },
        });

        await vi.waitFor(() => {
            expect(SiteCertificateChanged).toHaveBeenCalledWith("cert-1");
            expect(AccessCertificateChanged).toHaveBeenCalledWith("cert-1");
        });
    });
});

describe("RotateCertificate", () => {
    const certId = "00000000-0000-4000-8000-000000000007";
    const certRow = {
        id: certId,
        objectname: "vms-interior-cert-1",
        label: "site-a",
        isca: false,
        expiration: "2026-10-12T12:00:00.000Z",
        renewaltime: "2026-10-11T12:00:00.000Z",
        generation: 1,
    };

    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 0, rows: [] };
            }
            return { rowCount: 1, rows: [certRow] };
        });
    });

    it("triggers cert-manager renewal for a leaf certificate", async () => {
        TriggerCertificateRenewal.mockResolvedValue({});

        await expect(RotateCertificate(certId)).resolves.toEqual(certRow);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("FROM tlsCertificates WHERE id = $1"),
            [certId]
        );
        expect(TriggerCertificateRenewal).toHaveBeenCalledWith("vms-interior-cert-1");
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("rejects a malformed certificate id", async () => {
        await expect(RotateCertificate("not-a-uuid")).rejects.toMatchObject({
            statusCode: 400,
            message: "Malformed certificate ID: not-a-uuid",
        });
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
        expect(mockClient.query).not.toHaveBeenCalled();
    });

    it("returns 404 when the certificate row is missing", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 0, rows: [] });

        await expect(RotateCertificate(certId)).rejects.toMatchObject({
            statusCode: 404,
            message: "Certificate not found",
        });
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("refuses CA rotation", async () => {
        mockClient.query.mockResolvedValue({
            rowCount: 1,
            rows: [{ ...certRow, isca: true }],
        });

        await expect(RotateCertificate(certId)).rejects.toMatchObject({
            statusCode: 409,
            message: "CA certificate rotation is not supported",
        });
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
    });

    it("rejects a certificate with no Kubernetes object name", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 0, rows: [] };
            }
            return { rowCount: 1, rows: [{ ...certRow, objectname: null }] };
        });

        await expect(RotateCertificate(certId)).rejects.toMatchObject({
            statusCode: 400,
            message: "Certificate has no Kubernetes object",
        });
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
    });

    it("refuses rotation of a revoked certificate", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 1, rows: [{}] };
            }
            return { rowCount: 1, rows: [certRow] };
        });

        await expect(RotateCertificate(certId)).rejects.toMatchObject({
            statusCode: 409,
            message: "Certificate has been revoked",
        });
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
    });

    it("maps a missing Certificate CR to 404", async () => {
        const missing = new Error("not found");
        missing.statusCode = 404;
        TriggerCertificateRenewal.mockRejectedValue(missing);

        await expect(RotateCertificate(certId)).rejects.toMatchObject({
            statusCode: 404,
            message: "Certificate object vms-interior-cert-1 not found",
        });
    });
});
