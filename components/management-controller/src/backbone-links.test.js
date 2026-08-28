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

const mockClient = {
    query: vi.fn(),
    release: vi.fn(),
};

vi.mock("@vms/modules/kube", () => ({
    LoadSecret: vi.fn(),
}));

vi.mock("@vms/modules/amqp", () => ({
    OpenConnection: vi.fn(() => ({ id: "mock-conn" })),
    CloseConnection: vi.fn(),
    OnConnectionClosed: vi.fn(),
}));

vi.mock("./db.js", () => ({
    ClientFromPool: vi.fn(async () => mockClient),
}));

vi.mock("./notify.js", () => ({
    NotifyTransaction: class {
        add() {}
        async commit() {}
    },
    RegisterNotification: vi.fn(),
}));

import { LoadSecret } from "@vms/modules/kube";
import { OpenConnection, CloseConnection, OnConnectionClosed } from "@vms/modules/amqp";
import { RegisterNotification } from "./notify.js";

const notificationHandlers = {};

function mockReadyControllerQueries(overrides = {}) {
    const certificateId = overrides.certificateId ?? "cert-1";
    const secretName = overrides.secretName ?? "tls-secret";
    return async (sql) => {
        if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
            return {};
        }
        if (sql.includes("SELECT * FROM ManagementControllers WHERE Name = $1 and LifeCycle")) {
            return {
                rowCount: 1,
                rows: [{ name: "test-controller", certificate: certificateId }],
            };
        }
        if (sql.includes("SELECT * FROM ManagementControllers WHERE Name")) {
            return {
                rowCount: 1,
                rows: [{ name: "test-controller", certificate: certificateId }],
            };
        }
        if (sql.includes("SELECT ObjectName FROM TlsCertificates")) {
            return { rowCount: 1, rows: [{ objectname: secretName }] };
        }
        if (sql.includes("BackboneAccessPoints AS ap")) {
            return {
                rows: [
                    {
                        id: "ap-1",
                        hostname: "router.example.com",
                        port: 5671,
                        certificate: "ap-cert-1",
                        colocated: false,
                    },
                ],
            };
        }
        return { rows: [] };
    };
}

function captureNotificationHandlers() {
    RegisterNotification.mockImplementation((tableName, handler) => {
        notificationHandlers[tableName] = handler;
    });
}

describe("RegisterHandler", () => {
    let Start;
    let RegisterHandler;

    beforeEach(async () => {
        vi.useFakeTimers();
        vi.clearAllMocks();
        mockClient.query.mockReset();
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        captureNotificationHandlers();
        vi.resetModules();
        ({ Start, RegisterHandler } = await import("./backbone-links.js"));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("notifies registered handlers for existing and new backbone connections", async () => {
        const onAdded = vi.fn();
        const onDeleted = vi.fn();

        LoadSecret.mockResolvedValue({
            data: {
                "ca.crt": Buffer.from("ca").toString("base64"),
                "tls.crt": Buffer.from("cert").toString("base64"),
                "tls.key": Buffer.from("key").toString("base64"),
            },
        });

        mockClient.query.mockImplementation(mockReadyControllerQueries());

        await Start("test-controller");
        await vi.runOnlyPendingTimersAsync();
        await vi.runOnlyPendingTimersAsync();

        await RegisterHandler(onAdded, onDeleted);

        expect(onAdded).toHaveBeenCalledWith("ap-1", expect.objectContaining({ id: "mock-conn" }));
        expect(onDeleted).not.toHaveBeenCalled();
    });
});

describe("resolveControllerRecord (via Start)", () => {
    let Start;

    beforeEach(async () => {
        vi.useFakeTimers();
        vi.clearAllMocks();
        mockClient.query.mockReset();
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        captureNotificationHandlers();
        vi.resetModules();
        ({ Start } = await import("./backbone-links.js"));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("inserts a management controller record when none exists", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("SELECT * FROM ManagementControllers WHERE Name")) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("INSERT INTO ManagementControllers")) {
                return { rows: [{ id: "mc-id-1" }] };
            }
            return {};
        });

        await Start("test-controller");

        expect(mockClient.query).toHaveBeenCalledWith(
            "INSERT INTO ManagementControllers (Name) VALUES ($1) RETURNING Id",
            ["test-controller"]
        );
        expect(mockClient.release).toHaveBeenCalled();
        expect(RegisterNotification).toHaveBeenCalledWith(
            "BackboneAccessPoints",
            expect.any(Function),
            false
        );
        expect(RegisterNotification).toHaveBeenCalledWith(
            "TlsCertificates",
            expect.any(Function),
            false
        );
        expect(vi.getTimerCount()).toBe(2);
    });

    it("schedules TLS resolution immediately when controller record exists", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("SELECT * FROM ManagementControllers WHERE Name")) {
                return { rowCount: 1, rows: [{ name: "test-controller", certificate: "cert-1" }] };
            }
            return {};
        });

        await Start("test-controller");

        expect(mockClient.query).not.toHaveBeenCalledWith(
            "INSERT INTO ManagementControllers (Name) VALUES ($1) RETURNING Id",
            expect.anything()
        );
        expect(mockClient.release).toHaveBeenCalled();
        expect(vi.getTimerCount()).toBe(2);
    });

    it("reschedules on error and rolls back the transaction", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN") {
                return {};
            }
            if (sql.includes("SELECT * FROM ManagementControllers WHERE Name")) {
                throw new Error("database unavailable");
            }
            if (sql === "ROLLBACK") {
                return {};
            }
            return {};
        });

        await Start("test-controller");

        expect(mockClient.query).toHaveBeenCalledWith("ROLLBACK");
        expect(mockClient.release).toHaveBeenCalled();
        expect(vi.getTimerCount()).toBe(2);

        await vi.advanceTimersByTimeAsync(10000);
        expect(mockClient.query).toHaveBeenCalledWith("BEGIN");
    });

    it("chains through resolveTLSData and reconcileBackboneConnections", async () => {
        LoadSecret.mockResolvedValue({
            data: {
                "ca.crt": Buffer.from("ca").toString("base64"),
                "tls.crt": Buffer.from("cert").toString("base64"),
                "tls.key": Buffer.from("key").toString("base64"),
            },
        });

        mockClient.query.mockImplementation(mockReadyControllerQueries());

        await Start("test-controller");
        await vi.runOnlyPendingTimersAsync();
        await vi.runOnlyPendingTimersAsync();

        expect(LoadSecret).toHaveBeenCalledWith("tls-secret");
        expect(OpenConnection).toHaveBeenCalledWith(
            "Backbone-management-ap-1",
            "router.example.com",
            5671,
            "tls",
            expect.any(Buffer),
            expect.any(Buffer),
            expect.any(Buffer)
        );
        expect(vi.getTimerCount()).toBeGreaterThanOrEqual(1);
    });
});

describe("onTlsCertificateChange (via Start)", () => {
    let Start;

    beforeEach(async () => {
        vi.useFakeTimers();
        vi.clearAllMocks();
        mockClient.query.mockReset();
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        captureNotificationHandlers();
        vi.resetModules();
        ({ Start } = await import("./backbone-links.js"));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("reloads TLS and reconnects manage AMQP when the management controller cert is renewed", async () => {
        LoadSecret.mockResolvedValue({
            data: {
                "ca.crt": Buffer.from("ca").toString("base64"),
                "tls.crt": Buffer.from("cert").toString("base64"),
                "tls.key": Buffer.from("key").toString("base64"),
            },
        });

        mockClient.query.mockImplementation(mockReadyControllerQueries());

        await Start("test-controller");
        await vi.runOnlyPendingTimersAsync();
        await vi.runOnlyPendingTimersAsync();

        expect(OpenConnection).toHaveBeenCalledTimes(1);
        CloseConnection.mockClear();
        OpenConnection.mockClear();
        LoadSecret.mockClear();
        LoadSecret.mockResolvedValue({
            data: {
                "ca.crt": Buffer.from("new-ca").toString("base64"),
                "tls.crt": Buffer.from("new-cert").toString("base64"),
                "tls.key": Buffer.from("new-key").toString("base64"),
            },
        });

        await notificationHandlers.TlsCertificates("UPDATE", "cert-1");

        expect(CloseConnection).toHaveBeenCalledWith({ id: "mock-conn" });
        expect(LoadSecret).toHaveBeenCalledWith("tls-secret");
        expect(OpenConnection).toHaveBeenCalledWith(
            "Backbone-management-ap-1",
            "router.example.com",
            5671,
            "tls",
            Buffer.from("new-ca"),
            Buffer.from("new-cert"),
            Buffer.from("new-key")
        );
    });

    it("ignores TlsCertificates UPDATE for unrelated certs", async () => {
        LoadSecret.mockResolvedValue({
            data: {
                "ca.crt": Buffer.from("ca").toString("base64"),
                "tls.crt": Buffer.from("cert").toString("base64"),
                "tls.key": Buffer.from("key").toString("base64"),
            },
        });

        mockClient.query.mockImplementation(mockReadyControllerQueries());

        await Start("test-controller");
        await vi.runOnlyPendingTimersAsync();
        await vi.runOnlyPendingTimersAsync();

        CloseConnection.mockClear();
        LoadSecret.mockClear();
        OpenConnection.mockClear();

        await notificationHandlers.TlsCertificates("UPDATE", "other-cert");

        expect(CloseConnection).not.toHaveBeenCalled();
        expect(LoadSecret).not.toHaveBeenCalled();
        expect(OpenConnection).not.toHaveBeenCalled();
    });
});

async function startConnectedController(Start) {
    LoadSecret.mockResolvedValue({
        data: {
            "ca.crt": Buffer.from("ca").toString("base64"),
            "tls.crt": Buffer.from("cert").toString("base64"),
            "tls.key": Buffer.from("key").toString("base64"),
        },
    });
    mockClient.query.mockImplementation(mockReadyControllerQueries());
    await Start("test-controller");
    await vi.runOnlyPendingTimersAsync();
    await vi.runOnlyPendingTimersAsync();
}

describe("onAccessPointChange (via Start)", () => {
    let Start;

    beforeEach(async () => {
        vi.useFakeTimers();
        vi.clearAllMocks();
        mockClient.query.mockReset();
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        captureNotificationHandlers();
        vi.resetModules();
        ({ Start } = await import("./backbone-links.js"));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("reconnects manage AMQP when the access point certificate changes", async () => {
        await startConnectedController(Start);
        expect(OpenConnection).toHaveBeenCalledTimes(1);
        CloseConnection.mockClear();
        OpenConnection.mockClear();

        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("BackboneAccessPoints AS ap")) {
                return {
                    rows: [
                        {
                            id: "ap-1",
                            hostname: "router.example.com",
                            port: 5671,
                            certificate: "ap-cert-2",
                            colocated: false,
                        },
                    ],
                };
            }
            return mockReadyControllerQueries()(sql);
        });

        await notificationHandlers.BackboneAccessPoints("UPDATE", "ap-1");

        expect(CloseConnection).toHaveBeenCalledWith({ id: "mock-conn" });
        expect(OpenConnection).toHaveBeenCalledWith(
            "Backbone-management-ap-1",
            "router.example.com",
            5671,
            "tls",
            expect.any(Buffer),
            expect.any(Buffer),
            expect.any(Buffer)
        );
    });

    it("reconnects manage AMQP when the access point endpoint changes", async () => {
        await startConnectedController(Start);
        CloseConnection.mockClear();
        OpenConnection.mockClear();

        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("BackboneAccessPoints AS ap")) {
                return {
                    rows: [
                        {
                            id: "ap-1",
                            hostname: "router-new.example.com",
                            port: 5671,
                            certificate: "ap-cert-1",
                            colocated: false,
                        },
                    ],
                };
            }
            return mockReadyControllerQueries()(sql);
        });

        await notificationHandlers.BackboneAccessPoints("UPDATE", "ap-1");

        expect(CloseConnection).toHaveBeenCalledTimes(1);
        expect(OpenConnection).toHaveBeenCalledWith(
            "Backbone-management-ap-1",
            "router-new.example.com",
            5671,
            "tls",
            expect.any(Buffer),
            expect.any(Buffer),
            expect.any(Buffer)
        );
    });

    it("does not reconnect when the access point is unchanged", async () => {
        await startConnectedController(Start);
        CloseConnection.mockClear();
        OpenConnection.mockClear();

        await notificationHandlers.BackboneAccessPoints("UPDATE", "ap-1");

        expect(CloseConnection).not.toHaveBeenCalled();
        expect(OpenConnection).not.toHaveBeenCalled();
    });
});

describe("unexpected manage AMQP close (via Start)", () => {
    let Start;

    beforeEach(async () => {
        vi.useFakeTimers();
        vi.clearAllMocks();
        mockClient.query.mockReset();
        for (const key of Object.keys(notificationHandlers)) {
            delete notificationHandlers[key];
        }
        captureNotificationHandlers();
        vi.resetModules();
        ({ Start } = await import("./backbone-links.js"));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("reconnects after the router closes the manage AMQP session", async () => {
        const closedHandlers = [];
        OnConnectionClosed.mockImplementation((_conn, handler) => {
            closedHandlers.push(handler);
        });

        await startConnectedController(Start);
        expect(closedHandlers).toHaveLength(1);
        CloseConnection.mockClear();
        OpenConnection.mockClear();

        await closedHandlers[0]();
        await vi.advanceTimersByTimeAsync(1000);

        expect(CloseConnection).toHaveBeenCalledWith({ id: "mock-conn" });
        expect(OpenConnection).toHaveBeenCalledWith(
            "Backbone-management-ap-1",
            "router.example.com",
            5671,
            "tls",
            expect.any(Buffer),
            expect.any(Buffer),
            expect.any(Buffer)
        );
    });

    it("does not reconnect from a stale close after an intentional reload", async () => {
        const closedHandlers = [];
        OnConnectionClosed.mockImplementation((_conn, handler) => {
            closedHandlers.push(handler);
        });

        await startConnectedController(Start);
        const staleClose = closedHandlers[0];
        OpenConnection.mockClear();

        await notificationHandlers.TlsCertificates("UPDATE", "cert-1");

        expect(OpenConnection).toHaveBeenCalledTimes(1);
        await staleClose();
        await vi.advanceTimersByTimeAsync(1000);
        expect(OpenConnection).toHaveBeenCalledTimes(1);
    });
});
