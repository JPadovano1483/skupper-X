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

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { TEST_UUIDS } from "./test-helpers/mock-db.js";

const mockClient = {
    query: vi.fn(),
    release: vi.fn(),
};

vi.mock("@vms/modules/kube", () => ({
    GetNamespaces: vi.fn(async () => []),
    createNamespace: vi.fn(),
    deleteNamespace: vi.fn(),
    LoadSecret: vi.fn(),
    ApplyObject: vi.fn(),
    ReplaceSecret: vi.fn(),
    GetSites: vi.fn(async () => []),
    LoadRouterAccess: vi.fn(),
    DeleteSecret: vi.fn(),
    DeleteCertificate: vi.fn(),
}));

vi.mock("./db.js", () => ({
    ClientFromPool: vi.fn(async () => mockClient),
}));

vi.mock("./notify.js", async (importOriginal) => {
    const actual = await importOriginal();
    return {
        ...actual,
        RegisterNotification: vi.fn(actual.RegisterNotification),
        NotifyTransaction: class {
            add() {}
            update() {}
            delete() {}
            async commit() {}
        },
    };
});

import { Start } from "./colo-sync.js";
import { RegisterNotification } from "./notify.js";
import {
    GetNamespaces,
    LoadSecret,
    ApplyObject,
    ReplaceSecret,
    GetSites,
    LoadRouterAccess,
    DeleteSecret,
    DeleteCertificate,
} from "@vms/modules/kube";

const COLO_NS = "colo-ns-1";
const SITE_ID = TEST_UUIDS.site;
const AP_ID = TEST_UUIDS.accessPoint;
const BB_ID = TEST_UUIDS.backbone;
const SITE_CERT_ID = TEST_UUIDS.cert;
const AP_CERT_ID = "00000000-0000-4000-8000-000000000008";
const MC_SITE_SECRET_NAME = "vms-interior-site-cert";
const MC_AP_SECRET_NAME = "vms-manage-ap-cert";
const SITE_SECRET_NAME = `vms-site-${SITE_ID}`;
const AP_SECRET_NAME = "vms-colo-manage";

function transactionSql(sql) {
    return sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK";
}

function setupColoNamespaceMocks() {
    GetNamespaces.mockResolvedValue([
        {
            metadata: {
                name: COLO_NS,
                annotations: { "skupper.io/vms-controlled": "true" },
            },
        },
    ]);
}

function mockDbForReconcile() {
    mockClient.query.mockImplementation(async (sql, params) => {
        if (transactionSql(sql)) {
            return {};
        }
        if (sql.includes("FROM InteriorSites WHERE CoLocated = true AND Backbone")) {
            return {
                rowCount: 1,
                rows: [
                    {
                        id: SITE_ID,
                        name: "co-located",
                        lifecycle: "ready",
                        certificate: SITE_CERT_ID,
                    },
                ],
            };
        }
        if (
            sql.includes("FROM BackboneAccessPoints WHERE InteriorSite") &&
            sql.includes("manage")
        ) {
            return {
                rowCount: 1,
                rows: [
                    {
                        id: AP_ID,
                        lifecycle: "ready",
                        certificate: AP_CERT_ID,
                        hostname: "manage.example.com",
                        port: 5671,
                    },
                ],
            };
        }
        if (sql.includes("FROM TlsCertificates WHERE Id")) {
            const certId = params[0];
            if (certId === SITE_CERT_ID) {
                return { rows: [{ objectname: MC_SITE_SECRET_NAME }] };
            }
            if (certId === AP_CERT_ID) {
                return { rows: [{ objectname: MC_AP_SECRET_NAME }] };
            }
        }
        return { rows: [], rowCount: 0 };
    });
}

async function triggerInitialReconcile() {
    const backboneHandler = RegisterNotification.mock.calls.find((c) => c[0] === "Backbones")[1];
    await backboneHandler("EXISTS", BB_ID, "Backbones", {
        id: BB_ID,
        colocatednamespace: COLO_NS,
    });
    await backboneHandler("EXISTS_COMPLETE");
}

describe("colo-sync Start", () => {
    beforeEach(() => {
        vi.useFakeTimers();
        vi.clearAllMocks();
        mockClient.query.mockReset();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("loads namespaces and registers change handlers", async () => {
        GetNamespaces.mockResolvedValue([
            {
                metadata: {
                    name: COLO_NS,
                    annotations: { "skupper.io/vms-controlled": "true" },
                },
            },
        ]);

        await Start();

        expect(GetNamespaces).toHaveBeenCalled();
        expect(RegisterNotification).toHaveBeenCalledWith("Backbones", expect.any(Function), true);
        expect(RegisterNotification).toHaveBeenCalledWith(
            "InteriorSites",
            expect.any(Function),
            false
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "BackboneAccessPoints",
            expect.any(Function),
            false
        );
        expect(vi.getTimerCount()).toBe(2);
    });
});

describe("colo-sync TLS secret sync", () => {
    const mcSiteSecret = {
        data: { "tls.crt": "new-site-cert", "tls.key": "new-site-key", "ca.crt": "ca" },
    };
    const coloSiteSecret = {
        data: { "tls.crt": "old-site-cert", "tls.key": "old-site-key", "ca.crt": "ca" },
    };
    const mcApSecret = {
        data: { "tls.crt": "new-ap-cert", "tls.key": "new-ap-key", "ca.crt": "ca" },
    };
    const coloApSecret = {
        data: { "tls.crt": "old-ap-cert", "tls.key": "old-ap-key", "ca.crt": "ca" },
    };

    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        setupColoNamespaceMocks();
        mockDbForReconcile();
        GetSites.mockResolvedValue([{ metadata: { name: "site" } }]);
        LoadRouterAccess.mockResolvedValue({
            status: { endpoints: [{ host: "manage.example.com", port: 5671 }] },
        });
        LoadSecret.mockImplementation(async (name, ns) => {
            if (name === MC_SITE_SECRET_NAME) {
                return mcSiteSecret;
            }
            if (name === MC_AP_SECRET_NAME) {
                return mcApSecret;
            }
            if (name === SITE_SECRET_NAME && ns === COLO_NS) {
                return coloSiteSecret;
            }
            if (name === AP_SECRET_NAME && ns === COLO_NS) {
                return coloApSecret;
            }
            return undefined;
        });
    });

    it("replaces site and accesspoint secrets when MC source hash differs", async () => {
        await Start();
        await triggerInitialReconcile();

        expect(ReplaceSecret).toHaveBeenCalledTimes(2);
        expect(ReplaceSecret).toHaveBeenCalledWith(
            SITE_SECRET_NAME,
            expect.objectContaining({
                kind: "Secret",
                data: mcSiteSecret.data,
                metadata: expect.objectContaining({ name: SITE_SECRET_NAME }),
            }),
            COLO_NS
        );
        expect(ReplaceSecret).toHaveBeenCalledWith(
            AP_SECRET_NAME,
            expect.objectContaining({
                kind: "Secret",
                data: mcApSecret.data,
                metadata: expect.objectContaining({ name: AP_SECRET_NAME }),
            }),
            COLO_NS
        );
        expect(ApplyObject).not.toHaveBeenCalled();
    });

    it("applies secrets when missing in the colo namespace", async () => {
        LoadSecret.mockImplementation(async (name, ns) => {
            if (name === MC_SITE_SECRET_NAME) {
                return mcSiteSecret;
            }
            if (name === MC_AP_SECRET_NAME) {
                return mcApSecret;
            }
            if (ns === COLO_NS) {
                return undefined;
            }
            return undefined;
        });

        await Start();
        await triggerInitialReconcile();

        expect(ApplyObject).toHaveBeenCalledTimes(2);
        expect(ReplaceSecret).not.toHaveBeenCalled();
        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                kind: "Secret",
                data: mcSiteSecret.data,
                metadata: expect.objectContaining({ name: SITE_SECRET_NAME }),
            }),
            COLO_NS
        );
        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                kind: "Secret",
                data: mcApSecret.data,
                metadata: expect.objectContaining({ name: AP_SECRET_NAME }),
            }),
            COLO_NS
        );
    });

    it("does not replace secrets when colo data matches MC source", async () => {
        LoadSecret.mockImplementation(async (name, ns) => {
            if (name === MC_SITE_SECRET_NAME) {
                return mcSiteSecret;
            }
            if (name === MC_AP_SECRET_NAME) {
                return mcApSecret;
            }
            if (name === SITE_SECRET_NAME && ns === COLO_NS) {
                return mcSiteSecret;
            }
            if (name === AP_SECRET_NAME && ns === COLO_NS) {
                return mcApSecret;
            }
            return undefined;
        });

        await Start();
        await triggerInitialReconcile();

        expect(ReplaceSecret).not.toHaveBeenCalled();
        expect(ApplyObject).not.toHaveBeenCalled();
    });

    it("drops the access-point TLS cert when the colo hostname changes", async () => {
        DeleteSecret.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
        LoadRouterAccess.mockResolvedValue({
            status: { endpoints: [{ host: "new.example.com", port: 5671 }] },
        });
        mockClient.query.mockImplementation(async (sql, params) => {
            if (transactionSql(sql)) {
                return {};
            }
            if (sql.includes("FROM InteriorSites WHERE CoLocated = true AND Backbone")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: SITE_ID,
                            name: "co-located",
                            lifecycle: "ready",
                            certificate: SITE_CERT_ID,
                        },
                    ],
                };
            }
            if (
                sql.includes("FROM BackboneAccessPoints WHERE InteriorSite") &&
                sql.includes("manage")
            ) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: AP_ID,
                            lifecycle: "ready",
                            certificate: AP_CERT_ID,
                            hostname: "manage.example.com",
                            port: 5671,
                        },
                    ],
                };
            }
            if (sql.includes("FROM CertificateRequests WHERE AccessPoint")) {
                return { rows: [] };
            }
            if (sql.includes("SELECT Certificate FROM BackboneAccessPoints")) {
                return { rows: [{ certificate: AP_CERT_ID }] };
            }
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("FROM TlsCertificates WHERE ObjectName")) {
                return { rowCount: 1, rows: [{ id: AP_CERT_ID }] };
            }
            if (sql.includes("FROM TlsCertificates WHERE Id")) {
                const certId = params[0];
                if (certId === SITE_CERT_ID) {
                    return {
                        rowCount: 1,
                        rows: [{ id: SITE_CERT_ID, objectname: MC_SITE_SECRET_NAME }],
                    };
                }
                if (certId === AP_CERT_ID) {
                    return {
                        rowCount: 1,
                        rows: [{ id: AP_CERT_ID, objectname: MC_AP_SECRET_NAME }],
                    };
                }
            }
            if (sql.includes("UPDATE BackboneAccessPoints SET Certificate = NULL")) {
                return { rowCount: 1 };
            }
            if (sql.includes("DELETE FROM TlsCertificates")) {
                return { rowCount: 1 };
            }
            if (sql.includes("UPDATE BackboneAccessPoints SET hostname")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: AP_ID,
                            lifecycle: "new",
                            certificate: null,
                            hostname: "new.example.com",
                            port: 5671,
                        },
                    ],
                };
            }
            return { rows: [], rowCount: 0 };
        });

        await Start();
        await triggerInitialReconcile();

        expect(mockClient.query).toHaveBeenCalledWith("DELETE FROM TlsCertificates WHERE Id = $1", [
            AP_CERT_ID,
        ]);
        expect(mockClient.query).toHaveBeenCalledWith(expect.stringContaining("lifecycle = $4"), [
            AP_ID,
            "new.example.com",
            5671,
            "new",
        ]);
        expect(DeleteSecret).toHaveBeenCalledWith(MC_AP_SECRET_NAME);
        expect(DeleteCertificate).toHaveBeenCalledWith(MC_AP_SECRET_NAME);
    });
});
