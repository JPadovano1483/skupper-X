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
import { RotateCertificate } from "./certs.js";

const mockClient = createMockClient();
let mockFormFields = {};

vi.mock("formidable", () => {
    class MockForm {
        parse() {
            return Promise.resolve([mockFormFields, {}]);
        }
    }
    const formidable = () => new MockForm();
    formidable.IncomingForm = MockForm;
    return {
        default: formidable,
        IncomingForm: MockForm,
    };
});

vi.mock("./watch-server.js", () => ({
    WatchNotify: vi.fn(),
}));

vi.mock("./certs.js", () => ({
    RotateCertificate: vi.fn(),
}));

vi.mock("./sync-management.js", async (importOriginal) => {
    const actual = await importOriginal();
    return {
        ...actual,
    };
});

vi.mock("./db.js", async (importOriginal) => {
    const actual = await importOriginal();
    return {
        ...actual,
        ClientFromPool: vi.fn(async () => mockClient),
    };
});

describe("mc-apiserver routes", () => {
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
            if (sql.includes("SELECT ShortName, LongName FROM TargetPlatforms")) {
                return {
                    rows: [{ shortname: "sk2", longname: "Skupper 2" }],
                };
            }
            if (sql.includes("SELECT VanId FROM ApplicationNetworks")) {
                return {
                    rowCount: 1,
                    rows: [{ vanid: "van-network-id" }],
                };
            }
            if (
                sql.includes("SELECT Id, Lifecycle, Hostname, Port, Kind FROM BackboneAccessPoints")
            ) {
                return {
                    rowCount: 1,
                    rows: [
                        {
                            id: TEST_UUIDS.accessPoint,
                            lifecycle: "partial",
                            hostname: null,
                            port: null,
                            kind: "peer",
                        },
                    ],
                };
            }
            if (sql.includes("UPDATE BackboneAccessPoints SET Hostname")) {
                return { rowCount: 1 };
            }
            if (sql.includes("InterRouterLinks")) {
                return {
                    rows: [
                        {
                            id: "link-1",
                            hostname: "router.example.com",
                            port: 5671,
                            cost: 1,
                        },
                    ],
                };
            }
            return { rows: [], rowCount: 0 };
        });
    });

    it("GET /targetplatforms returns platform list", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .get("/api/v1alpha1/targetplatforms")
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.body).toEqual([{ shortname: "sk2", longname: "Skupper 2" }]);
    });

    it("GET /user/profile returns authenticated user name", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .get("/api/v1alpha1/user/profile")
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.body).toEqual({ name: "Test User" });
    });

    it("GET /user/groups returns client groups", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .get("/api/v1alpha1/user/groups")
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.body).toEqual([{ id: "group-a", name: "group-a" }]);
    });

    it("GET /certs rejects malformed signedby query", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .get("/api/v1alpha1/certs")
            .query({ signedby: "not-a-uuid" })
            .set("x-test-auth", "1")
            .expect(400);

        expect(res.text).toContain("Malformed signedby reference");
    });

    it("GET /certs adds expiresWithin filter to the query", async () => {
        let certsSql;
        let certsParams;
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("INSERT INTO Users")) {
                return { rows: [{ id: "internal-user-1" }] };
            }
            if (sql.includes("set_config")) {
                return {};
            }
            if (sql.includes("FROM tlsCertificates WHERE signedBy IS NULL")) {
                certsSql = sql;
                certsParams = params;
                return { rows: [], rowCount: 0 };
            }
            return { rows: [], rowCount: 0 };
        });

        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        await request(app)
            .get("/api/v1alpha1/certs")
            .query({ expiresWithin: "30" })
            .set("x-test-auth", "1")
            .expect(200);

        expect(certsSql).toContain("expiration <= NOW()");
        expect(certsParams).toEqual([30]);
    });

    it("GET /vans/:vid/config/nonconnecting returns network yaml", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .get(`/api/v1alpha1/vans/${TEST_UUIDS.van}/config/nonconnecting`)
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.text).toContain("van-network-id");
    });

    it("GET /backbonesite/:bsid/links/outgoing/kube returns outgoing links as a ConfigMap manifest", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .get(`/api/v1alpha1/backbonesite/${TEST_UUIDS.site}/links/outgoing/kube`)
            .set("x-test-auth", "1")
            .expect(200);

        expect(res.text).toContain("kind: ConfigMap");
        expect(res.text).toContain("router.example.com");
        expect(res.text).toContain("5671");
    });

    it("POST /backbonesite/:bsid/ingress updates partial access points", async () => {
        mockFormFields = {
            [TEST_UUIDS.accessPoint]: {
                host: "ingress.example.com",
                port: "5671",
            },
        };
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .post(`/api/v1alpha1/backbonesite/${TEST_UUIDS.site}/ingress`)
            .set("x-test-auth", "1")
            .expect(201);

        expect(res.body).toEqual({ processed: 1 });
    });

    it("POST /certs/:cid/rotate returns 202 and cert metadata", async () => {
        const cert = {
            id: TEST_UUIDS.cert,
            objectname: "vms-interior-cert-1",
            label: "site-a",
            isca: false,
        };
        RotateCertificate.mockResolvedValue(cert);

        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .post(`/api/v1alpha1/certs/${TEST_UUIDS.cert}/rotate`)
            .set("x-test-auth", "1")
            .expect(202);

        expect(RotateCertificate).toHaveBeenCalledWith(TEST_UUIDS.cert, { rotateKey: false });
        expect(res.body).toEqual(cert);
    });

    it("POST /certs/:cid/rotate?rotateKey=true forwards rotateKey", async () => {
        const cert = {
            id: TEST_UUIDS.cert,
            objectname: "vms-bb-ca-1",
            label: "backbone-ca",
            isca: true,
            keyRotation: { newCertificateId: "new-ca", children: [] },
        };
        RotateCertificate.mockResolvedValue(cert);

        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .post(`/api/v1alpha1/certs/${TEST_UUIDS.cert}/rotate?rotateKey=true`)
            .set("x-test-auth", "1")
            .expect(202);

        expect(RotateCertificate).toHaveBeenCalledWith(TEST_UUIDS.cert, { rotateKey: true });
        expect(res.body).toEqual(cert);
    });

    it("POST /certs/:cid/rotate maps statusCode from RotateCertificate", async () => {
        const error = new Error("Certificate not found");
        error.statusCode = 404;
        RotateCertificate.mockRejectedValue(error);

        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
        });

        const res = await request(app)
            .post(`/api/v1alpha1/certs/${TEST_UUIDS.cert}/rotate`)
            .set("x-test-auth", "1")
            .expect(404);

        expect(res.text).toBe("Certificate not found");
    });

    it("POST /certs/:cid/rotate requires certificate-manager", async () => {
        const { app } = await buildApiApp({
            includeAdmin: false,
            includeUser: false,
            includeMcRoutes: true,
            roles: ["admin"],
        });

        await request(app)
            .post(`/api/v1alpha1/certs/${TEST_UUIDS.cert}/rotate`)
            .set("x-test-auth", "1")
            .expect(403);

        expect(RotateCertificate).not.toHaveBeenCalled();
    });
});
