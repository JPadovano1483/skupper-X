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
import {
    deleteExpiredSupersededCertificates,
    getCurrentCertificateId,
    getTlsRotationMeta,
    retargetParentCertificateFks,
    timestampsEqual,
    TLS_CERTIFICATE_PARENT_TABLES,
} from "./tls-rotation.js";

describe("timestampsEqual", () => {
    it("treats empty values as equal", () => {
        expect(timestampsEqual(undefined, undefined)).toBe(true);
        expect(timestampsEqual(null, undefined)).toBe(true);
    });

    it("compares date instants", () => {
        expect(
            timestampsEqual(new Date("2026-10-12T12:00:00.000Z"), "2026-10-12T12:00:00.000Z")
        ).toBe(true);
        expect(
            timestampsEqual(new Date("2026-10-12T12:00:00.000Z"), "2026-09-01T12:00:00.000Z")
        ).toBe(false);
    });
});

describe("getTlsRotationMeta", () => {
    const client = { query: vi.fn() };

    beforeEach(() => {
        client.query.mockReset();
    });

    it("returns null when no rows exist for the object name", async () => {
        client.query.mockResolvedValue({ rowCount: 0, rows: [] });

        await expect(getTlsRotationMeta(client, "vms-site-1")).resolves.toBeNull();
    });

    it("returns null when the result has empty rows without rowCount", async () => {
        client.query.mockResolvedValue({ rows: [] });

        await expect(getTlsRotationMeta(client, "vms-site-1")).resolves.toBeNull();
    });

    it("returns the current ordinal and oldest unexpired lastValid", async () => {
        client.query.mockResolvedValue({
            rowCount: 2,
            rows: [
                { rotationordinal: 0, expiration: new Date("2099-01-01T00:00:00.000Z") },
                { rotationordinal: 1, expiration: new Date("2099-06-01T00:00:00.000Z") },
            ],
        });

        await expect(getTlsRotationMeta(client, "vms-site-1")).resolves.toEqual({
            ordinal: 1,
            lastValid: 0,
        });
    });

    it("bumps lastValid past expired predecessors", async () => {
        client.query.mockResolvedValue({
            rowCount: 2,
            rows: [
                { rotationordinal: 0, expiration: new Date("2020-01-01T00:00:00.000Z") },
                { rotationordinal: 1, expiration: new Date("2099-06-01T00:00:00.000Z") },
            ],
        });

        await expect(getTlsRotationMeta(client, "vms-site-1")).resolves.toEqual({
            ordinal: 1,
            lastValid: 1,
        });
    });

    it("bumps lastValid past revoked predecessors", async () => {
        client.query.mockResolvedValue({
            rowCount: 2,
            rows: [
                {
                    rotationordinal: 0,
                    expiration: new Date("2099-01-01T00:00:00.000Z"),
                    revoked: true,
                },
                {
                    rotationordinal: 1,
                    expiration: new Date("2099-06-01T00:00:00.000Z"),
                    revoked: false,
                },
            ],
        });

        await expect(getTlsRotationMeta(client, "vms-site-1")).resolves.toEqual({
            ordinal: 1,
            lastValid: 1,
        });
        expect(client.query).toHaveBeenCalledWith(expect.stringContaining("TlsClientRevocations"), [
            "vms-site-1",
        ]);
    });
});

describe("getCurrentCertificateId", () => {
    it("selects the highest rotation ordinal", async () => {
        const client = {
            query: vi.fn(async () => ({ rows: [{ id: "current-id" }] })),
        };

        await expect(getCurrentCertificateId(client, "vms-site-1")).resolves.toBe("current-id");
        expect(client.query).toHaveBeenCalledWith(
            expect.stringContaining("ORDER BY RotationOrdinal DESC"),
            ["vms-site-1"]
        );
    });
});

describe("retargetParentCertificateFks", () => {
    it("updates every parent table and notifies changed rows", async () => {
        const notify = { update: vi.fn() };
        const client = {
            query: vi.fn(async (sql) => {
                if (sql.includes("UPDATE InteriorSites")) {
                    return { rows: [{ id: "site-1" }] };
                }
                return { rows: [] };
            }),
        };

        await retargetParentCertificateFks(client, notify, "old-id", "new-id");

        expect(client.query).toHaveBeenCalledTimes(TLS_CERTIFICATE_PARENT_TABLES.length);
        expect(notify.update).toHaveBeenCalledWith("InteriorSites", "site-1");
    });
});

describe("deleteExpiredSupersededCertificates", () => {
    it("nulls Supercedes then deletes expired predecessors", async () => {
        const notify = { delete: vi.fn() };
        const client = {
            query: vi.fn(async (sql) => {
                if (sql.includes("SELECT c.Id, c.ObjectName")) {
                    return { rows: [{ id: "old-id", objectname: "vms-site-1" }] };
                }
                return {};
            }),
        };

        await expect(deleteExpiredSupersededCertificates(client, notify)).resolves.toEqual([
            "vms-site-1",
        ]);
        expect(client.query).toHaveBeenCalledWith(
            "UPDATE TlsCertificates SET Supercedes = NULL WHERE Supercedes = $1",
            ["old-id"]
        );
        expect(client.query).toHaveBeenCalledWith("DELETE FROM TlsCertificates WHERE Id = $1", [
            "old-id",
        ]);
        expect(notify.delete).toHaveBeenCalledWith("TlsCertificates", "old-id");
    });
});
