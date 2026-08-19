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
import request from "supertest";
import { createMockClient, TEST_UUIDS } from "./test-helpers/mock-db.js";
import { buildApiApp } from "./test-helpers/build-api-app.js";
import { SiteDeleted, SiteIngressChanged } from "./sync-management.js";
import { PruneNow, deleteUnreferencedKubeTls } from "./prune.js";

const mockClient = createMockClient();
let mockFormFields = {};

vi.mock("formidable", () => ({
    IncomingForm: class {
        parse() {
            return Promise.resolve([mockFormFields, {}]);
        }
    },
}));

vi.mock("./watch-server.js", () => ({
    WatchNotify: vi.fn(),
}));

vi.mock("./sync-management.js", () => ({
    SiteDeleted: vi.fn(),
    SiteIngressChanged: vi.fn(),
    LinkChanged: vi.fn(),
}));

vi.mock("./site-deployment-state.js", () => ({
    ManageIngressAdded: vi.fn(),
    LinkAddedOrDeleted: vi.fn(),
    ManageIngressDeleted: vi.fn(),
}));

vi.mock("./prune.js", () => ({
    PruneNow: vi.fn(async () => {}),
    deleteUnreferencedKubeTls: vi.fn(async () => {}),
}));

vi.mock("./db.js", async (importOriginal) => {
    const actual = await importOriginal();
    return {
        ...actual,
        ClientFromPool: vi.fn(async () => mockClient),
    };
});

describe("api-admin", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("INSERT INTO Users")) {
                return { rows: [{ id: "internal-user-1" }] };
            }
            if (sql.includes("set_config")) {
                return {};
            }
            if (
                sql.includes(
                    "SELECT Id, Name, Lifecycle, Failure, OwnerGroup FROM Backbones WHERE Id"
                )
            ) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: TEST_UUIDS.backbone,
                            name: "backbone-a",
                            lifecycle: "ready",
                            failure: null,
                            ownergroup: "",
                        },
                    ],
                };
            }
            if (sql.includes("SELECT Id, Name, Lifecycle, Failure, OwnerGroup FROM Backbones")) {
                return {
                    rows: [
                        {
                            id: TEST_UUIDS.backbone,
                            name: "backbone-a",
                            lifecycle: "ready",
                            failure: null,
                            ownergroup: "",
                        },
                    ],
                };
            }
            return { rows: [], rowCount: 0 };
        });
    });

    it("GET /backbones returns backbone list when authenticated", async () => {
        const { app } = await buildApiApp({ includeUser: false });

        const res = await request(app)
            .get("/api/v1alpha1/backbones")
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.body).toEqual([
            {
                id: TEST_UUIDS.backbone,
                name: "backbone-a",
                lifecycle: "ready",
                failure: null,
                ownergroup: "",
            },
        ]);
    });

    it("GET /backbones/:bid returns a single backbone", async () => {
        const { app } = await buildApiApp({ includeUser: false });

        const res = await request(app)
            .get(`/api/v1alpha1/backbones/${TEST_UUIDS.backbone}`)
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.body.id).toBe(TEST_UUIDS.backbone);
    });

    it("GET /backbones/:bid rejects malformed ids", async () => {
        const { app } = await buildApiApp({ includeUser: false });

        const res = await request(app)
            .get("/api/v1alpha1/backbones/not-a-uuid")
            .set("x-test-auth", "1")
            .expect(400);

        expect(res.text).toContain("not a valid uuid");
    });

    it("GET /backbones returns 401 without authentication", async () => {
        const { app } = await buildApiApp({ includeUser: false });

        const res = await request(app).get("/api/v1alpha1/backbones");

        expect(res.status).toBe(401);
    });

    it("GET /backbones returns 403 without list role", async () => {
        const { app } = await buildApiApp({
            includeUser: false,
            roles: ["viewer"],
        });

        const res = await request(app).get("/api/v1alpha1/backbones").set("x-test-auth", "1");

        expect(res.status).toBe(403);
    });

    it("POST /backbones creates a backbone", async () => {
        mockFormFields = { name: "new-backbone" };
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("INSERT INTO Users")) {
                return { rows: [{ id: "internal-user-1" }] };
            }
            if (sql.includes("set_config")) {
                return {};
            }
            if (sql.includes("INSERT INTO Backbones")) {
                return { rows: [{ id: TEST_UUIDS.backbone }] };
            }
            return { rows: [], rowCount: 0 };
        });

        const { app } = await buildApiApp({ includeUser: false });

        const res = await request(app)
            .post("/api/v1alpha1/backbones")
            .set("x-test-auth", "1")
            .field("name", "new-backbone")
            .expect(201);

        expect(res.body).toEqual({ id: TEST_UUIDS.backbone });
    });

    it("DELETE /backbonesites/:sid removes kube tls objects and prunes", async () => {
        const apCertId = "00000000-0000-4000-8000-000000000008";
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("INSERT INTO Users")) {
                return { rows: [{ id: "internal-user-1" }] };
            }
            if (sql.includes("set_config")) {
                return {};
            }
            if (sql.includes("FROM InteriorSites LEFT JOIN TlsCertificates")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            certificate: TEST_UUIDS.cert,
                            colocated: false,
                            objectname: "vms-interior-site-1",
                        },
                    ],
                };
            }
            if (sql.includes("FROM BackboneAccessPoints LEFT JOIN TlsCertificates")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: TEST_UUIDS.accessPoint,
                            certificate: apCertId,
                            objectname: "vms-access-ap-1",
                        },
                    ],
                };
            }
            return { rows: [], rowCount: 1 };
        });

        const { app } = await buildApiApp({ includeUser: false });

        await request(app)
            .delete(`/api/v1alpha1/backbonesites/${TEST_UUIDS.site}`)
            .set("x-test-auth", "1")
            .expect(204);

        expect(SiteDeleted).toHaveBeenCalledWith(TEST_UUIDS.site, [TEST_UUIDS.accessPoint]);
        expect(deleteUnreferencedKubeTls).toHaveBeenCalledWith([
            "vms-interior-site-1",
            "vms-access-ap-1",
        ]);
        expect(PruneNow).toHaveBeenCalled();
    });

    it("DELETE /backbonesites/:sid does not prune a colocated site", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("INSERT INTO Users")) {
                return { rows: [{ id: "internal-user-1" }] };
            }
            if (sql.includes("set_config")) {
                return {};
            }
            if (sql.includes("FROM InteriorSites LEFT JOIN TlsCertificates")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            certificate: TEST_UUIDS.cert,
                            colocated: true,
                            objectname: "vms-interior-colo",
                        },
                    ],
                };
            }
            return { rows: [], rowCount: 0 };
        });

        const { app } = await buildApiApp({ includeUser: false });

        await request(app)
            .delete(`/api/v1alpha1/backbonesites/${TEST_UUIDS.site}`)
            .set("x-test-auth", "1")
            .expect(400);

        expect(deleteUnreferencedKubeTls).not.toHaveBeenCalled();
        expect(PruneNow).not.toHaveBeenCalled();
        expect(SiteDeleted).not.toHaveBeenCalled();
    });

    it("DELETE /accesspoints/:apid prunes after deleting the access point", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("INSERT INTO Users")) {
                return { rows: [{ id: "internal-user-1" }] };
            }
            if (sql.includes("set_config")) {
                return {};
            }
            if (sql.includes("SELECT BackboneAccessPoints.Kind, InteriorSites.CoLocated")) {
                return {
                    rowCount: 1,
                    rows: [{ kind: "member", colocated: false }],
                };
            }
            if (sql.includes("DELETE FROM BackboneAccessPoints WHERE Id")) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            certificate: TEST_UUIDS.cert,
                            kind: "member",
                            interiorsite: TEST_UUIDS.site,
                        },
                    ],
                };
            }
            return { rows: [], rowCount: 1 };
        });

        const { app } = await buildApiApp({ includeUser: false });

        await request(app)
            .delete(`/api/v1alpha1/accesspoints/${TEST_UUIDS.accessPoint}`)
            .set("x-test-auth", "1")
            .expect(204);

        expect(PruneNow).toHaveBeenCalled();
        expect(SiteIngressChanged).toHaveBeenCalledWith(TEST_UUIDS.site, TEST_UUIDS.accessPoint);
    });
});
