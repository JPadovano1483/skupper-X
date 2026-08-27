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

vi.mock("@vms/modules/kube", async (importOriginal) => {
    const actual = await importOriginal();
    return {
        ...actual,
        ApplyObject: vi.fn(),
        LoadCertificate: vi.fn(),
        LoadSecret: vi.fn(),
        ReplaceCertificate: vi.fn(),
        TriggerCertificateRenewal: vi.fn(),
        DeleteCertificate: vi.fn(),
        DeleteIssuer: vi.fn(),
        DeleteSecret: vi.fn(),
    };
});

vi.mock("./db.js", () => ({
    ClientFromPool: vi.fn(async () => mockClient),
}));

vi.mock("./notify.js", () => ({
    NotifyTransaction: class {
        add() {}
        update() {}
        delete() {}
        async commit() {}
    },
}));

import {
    ApplyObject,
    LoadCertificate,
    LoadSecret,
    ReplaceCertificate,
    TriggerCertificateRenewal,
    DeleteCertificate,
    DeleteIssuer,
    DeleteSecret,
} from "@vms/modules/kube";
import {
    certIdsToRefreshAfterIssuerCutover,
    joinPemBundle,
    nextCaObjectName,
    overlayDualTrustCa,
    rotateCaKey,
} from "./tls-ca-cascade.js";

const OLD_CA = "00000000-0000-4000-8000-000000000010";
const NEW_CA = "00000000-0000-4000-8000-000000000014";
const LEAF = "00000000-0000-4000-8000-000000000011";
const VAN_CA = "00000000-0000-4000-8000-000000000012";
const MEMBER = "00000000-0000-4000-8000-000000000013";
const NEW_VAN = "00000000-0000-4000-8000-000000000015";

function pem(label) {
    return `-----BEGIN CERTIFICATE-----\n${label}\n-----END CERTIFICATE-----`;
}

function b64(text) {
    return Buffer.from(text).toString("base64");
}

function caRow(id, objectname, extra = {}) {
    return {
        id,
        isca: true,
        objectname,
        signedby: extra.signedby ?? null,
        supercedes: extra.supercedes ?? null,
        expiration: extra.expiration ?? new Date("2027-01-01T00:00:00.000Z"),
        renewaltime: extra.renewaltime ?? new Date("2026-12-01T00:00:00.000Z"),
        rotationordinal: extra.rotationordinal ?? 0,
        label: extra.label ?? "Backbone: test",
    };
}

function leafRow(id, objectname, signedby, extra = {}) {
    return {
        id,
        isca: false,
        objectname,
        signedby,
        supercedes: extra.supercedes ?? null,
        expiration: extra.expiration ?? new Date("2026-10-01T00:00:00.000Z"),
        renewaltime: extra.renewaltime ?? new Date("2026-09-01T00:00:00.000Z"),
        rotationordinal: extra.rotationordinal ?? 0,
        label: extra.label ?? "site",
    };
}

describe("nextCaObjectName", () => {
    it("replaces a trailing UUID in the existing object name", () => {
        expect(nextCaObjectName(`vms-bb-ca-${OLD_CA}`, NEW_CA)).toBe(`vms-bb-ca-${NEW_CA}`);
        expect(nextCaObjectName(`vms-van-ca-${VAN_CA}`, NEW_VAN)).toBe(`vms-van-ca-${NEW_VAN}`);
    });

    it("appends the new id when the name has no UUID suffix", () => {
        expect(nextCaObjectName("vms-root-ca", NEW_CA)).toBe(`vms-root-ca-${NEW_CA}`);
        expect(nextCaObjectName(null, NEW_CA)).toBe(`vms-ca-${NEW_CA}`);
    });
});

describe("joinPemBundle", () => {
    it("joins PEM blocks with a trailing newline", () => {
        expect(joinPemBundle([pem("OLD"), pem("NEW")])).toBe(`${pem("OLD")}\n${pem("NEW")}\n`);
        expect(joinPemBundle(["", "  "])).toBe("");
    });
});

describe("overlayDualTrustCa", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
    });

    it("concatenates old then new CA PEMs while a successor has a different object name", async () => {
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql.includes("FROM TlsCertificates WHERE Id = $1")) {
                if (params[0] === LEAF) {
                    return { rows: [leafRow(LEAF, "vms-interior-leaf", OLD_CA)] };
                }
                if (params[0] === OLD_CA) {
                    return { rows: [caRow(OLD_CA, "vms-bb-ca-old")] };
                }
            }
            if (sql.includes("WHERE Supercedes = $1")) {
                return { rows: [{ id: NEW_CA, objectname: "vms-bb-ca-new" }] };
            }
            return { rows: [], rowCount: 0 };
        });
        LoadSecret.mockImplementation(async (name) => {
            if (name === "vms-bb-ca-old") {
                return { data: { "tls.crt": b64(pem("OLD")) } };
            }
            if (name === "vms-bb-ca-new") {
                return { data: { "tls.crt": b64(pem("NEW")) } };
            }
            return undefined;
        });

        const result = await overlayDualTrustCa(mockClient, LEAF, {
            "tls.crt": "leaf",
            "ca.crt": b64("old-only"),
        });

        expect(Buffer.from(result["ca.crt"], "base64").toString("utf-8")).toBe(
            `${pem("OLD")}\n${pem("NEW")}\n`
        );
        expect(result["tls.crt"]).toBe("leaf");
    });

    it("leaves ca.crt unchanged when there is no key-rotation successor", async () => {
        const original = { "tls.crt": "leaf", "ca.crt": b64("issuer") };
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql.includes("FROM TlsCertificates WHERE Id = $1")) {
                if (params[0] === LEAF) {
                    return { rows: [leafRow(LEAF, "vms-interior-leaf", OLD_CA)] };
                }
                if (params[0] === OLD_CA) {
                    return { rows: [caRow(OLD_CA, "vms-bb-ca-old")] };
                }
            }
            return { rows: [], rowCount: 0 };
        });

        await expect(overlayDualTrustCa(mockClient, LEAF, original)).resolves.toBe(original);
        expect(LoadSecret).not.toHaveBeenCalled();
    });

    it("includes the predecessor while live children remain on the old CA", async () => {
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql.includes("FROM TlsCertificates WHERE Id = $1")) {
                if (params[0] === LEAF) {
                    return { rows: [leafRow(LEAF, "vms-interior-leaf", NEW_CA)] };
                }
                if (params[0] === NEW_CA) {
                    return { rows: [caRow(NEW_CA, "vms-bb-ca-new", { supercedes: OLD_CA })] };
                }
                if (params[0] === OLD_CA) {
                    return { rows: [caRow(OLD_CA, "vms-bb-ca-old")] };
                }
            }
            if (sql.includes("WHERE SignedBy = $1")) {
                return {
                    rowCount: params[0] === OLD_CA ? 1 : 0,
                    rows: params[0] === OLD_CA ? [{}] : [],
                };
            }
            return { rows: [], rowCount: 0 };
        });
        LoadSecret.mockImplementation(async (name) => ({
            data: { "tls.crt": b64(pem(name)) },
        }));

        const result = await overlayDualTrustCa(mockClient, LEAF, { "tls.crt": "leaf" });
        expect(Buffer.from(result["ca.crt"], "base64").toString("utf-8")).toBe(
            `${pem("vms-bb-ca-old")}\n${pem("vms-bb-ca-new")}\n`
        );
    });

    it("drops the predecessor after the last live child has moved", async () => {
        const original = { "tls.crt": "leaf", "ca.crt": b64("new-only") };
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql.includes("FROM TlsCertificates WHERE Id = $1")) {
                if (params[0] === LEAF) {
                    return { rows: [leafRow(LEAF, "vms-interior-leaf", NEW_CA)] };
                }
                if (params[0] === NEW_CA) {
                    return { rows: [caRow(NEW_CA, "vms-bb-ca-new", { supercedes: OLD_CA })] };
                }
                if (params[0] === OLD_CA) {
                    return { rows: [caRow(OLD_CA, "vms-bb-ca-old")] };
                }
            }
            if (sql.includes("WHERE SignedBy = $1")) {
                return { rowCount: 0, rows: [] };
            }
            return { rows: [], rowCount: 0 };
        });

        await expect(overlayDualTrustCa(mockClient, LEAF, original)).resolves.toBe(original);
    });
});

describe("certIdsToRefreshAfterIssuerCutover", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
    });

    it("returns current leaf children of the new CA once the old CA has none", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("WHERE SignedBy = $1") && sql.includes("LIMIT 1")) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("WHERE SignedBy = $1")) {
                return {
                    rowCount: 1,
                    rows: [leafRow(LEAF, "vms-interior-leaf", NEW_CA)],
                };
            }
            return { rows: [], rowCount: 0 };
        });

        await expect(certIdsToRefreshAfterIssuerCutover(NEW_CA, OLD_CA)).resolves.toEqual([LEAF]);
        expect(mockClient.query).toHaveBeenCalledWith(expect.stringContaining("LIMIT 1"), [OLD_CA]);
        expect(mockClient.release).toHaveBeenCalled();
    });

    it("returns no ids while the old CA still has live children", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql.includes("WHERE SignedBy = $1")) {
                return { rowCount: 1, rows: [{}] };
            }
            return { rows: [], rowCount: 0 };
        });

        await expect(certIdsToRefreshAfterIssuerCutover(NEW_CA, OLD_CA)).resolves.toEqual([]);
    });
});

describe("rotateCaKey", () => {
    const oldCa = caRow(OLD_CA, `vms-bb-ca-${OLD_CA}`);
    const leaf = leafRow(LEAF, "vms-interior-leaf", OLD_CA);
    const missingCerts = new Set();
    const childrenByCa = new Map();
    const certsById = new Map();

    function installQuery() {
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("WHERE SignedBy = $1")) {
                const kids = childrenByCa.get(params[0]) || [];
                return { rowCount: kids.length, rows: kids };
            }
            if (sql.includes("FROM TlsClientRevocations WHERE")) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("INSERT INTO TlsCertificates")) {
                return { rowCount: 1, rows: [] };
            }
            if (sql.includes("SET Certificate = $1 WHERE Certificate = $2")) {
                return { rows: [] };
            }
            if (sql.includes("FROM TlsCertificates WHERE Id = $1")) {
                const row = certsById.get(params[0]);
                return row ? { rowCount: 1, rows: [row] } : { rowCount: 0, rows: [] };
            }
            return { rows: [], rowCount: 0 };
        });
    }

    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        missingCerts.clear();
        childrenByCa.clear();
        certsById.clear();
        certsById.set(OLD_CA, oldCa);
        certsById.set(LEAF, leaf);
        childrenByCa.set(OLD_CA, [leaf]);
        installQuery();
        ApplyObject.mockResolvedValue({ metadata: { name: "created" } });
        ReplaceCertificate.mockResolvedValue({});
        TriggerCertificateRenewal.mockResolvedValue({});
        DeleteCertificate.mockResolvedValue({});
        DeleteIssuer.mockResolvedValue({});
        DeleteSecret.mockResolvedValue({});
        LoadCertificate.mockImplementation(async (name) => {
            if (missingCerts.has(name)) {
                const err = new Error("not found");
                err.statusCode = 404;
                throw err;
            }
            return {
                metadata: { name },
                spec: {
                    duration: "8760h",
                    issuerRef: {
                        name: name === oldCa.objectname ? "vms-root" : oldCa.objectname,
                        kind: "Issuer",
                        group: "cert-manager.io",
                    },
                    privateKey: { algorithm: "RSA", encoding: "PKCS1", size: 2048 },
                    secretTemplate: {
                        annotations: { "skupper.io/vms-issuerlink": OLD_CA },
                    },
                },
                status: {
                    notAfter: "2027-08-21T00:00:00.000Z",
                    renewalTime: "2027-07-21T00:00:00.000Z",
                },
            };
        });
        LoadSecret.mockResolvedValue({
            data: { "tls.crt": b64(pem("ca")) },
        });
    });

    it("issues a new CA and Issuer, then re-issues live leaves against them", async () => {
        const result = await rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 1000 });

        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                kind: "Certificate",
                metadata: expect.objectContaining({ name: `vms-bb-ca-${NEW_CA}` }),
                spec: expect.objectContaining({
                    isCA: true,
                    secretName: `vms-bb-ca-${NEW_CA}`,
                    issuerRef: expect.objectContaining({ name: "vms-root" }),
                    privateKey: expect.objectContaining({ rotationPolicy: "Never" }),
                }),
            })
        );
        const newCaCert = ApplyObject.mock.calls.find(([obj]) => obj.kind === "Certificate")[0];
        expect(newCaCert.spec).not.toHaveProperty("renewBefore");
        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                kind: "Issuer",
                metadata: expect.objectContaining({ name: `vms-bb-ca-${NEW_CA}` }),
            })
        );
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            [
                NEW_CA,
                `vms-bb-ca-${NEW_CA}`,
                null,
                expect.any(Date),
                expect.any(Date),
                1,
                OLD_CA,
                oldCa.label,
            ]
        );
        expect(ReplaceCertificate).toHaveBeenCalledWith(
            expect.objectContaining({
                spec: expect.objectContaining({
                    issuerRef: expect.objectContaining({ name: `vms-bb-ca-${NEW_CA}` }),
                }),
            })
        );
        expect(TriggerCertificateRenewal).toHaveBeenCalledWith("vms-interior-leaf");
        expect(result.keyRotation).toEqual({
            newCertificateId: NEW_CA,
            objectName: `vms-bb-ca-${NEW_CA}`,
            children: [
                {
                    id: LEAF,
                    objectname: "vms-interior-leaf",
                    isca: false,
                    action: "reissue",
                },
            ],
        });
        expect(result.refreshCertIds).toEqual([LEAF]);
        expect(DeleteCertificate).not.toHaveBeenCalled();
    });

    it("refuses the cascade before creating objects when a child Certificate is missing", async () => {
        missingCerts.add("vms-interior-leaf");

        await expect(rotateCaKey(OLD_CA, { newId: NEW_CA })).rejects.toMatchObject({
            statusCode: 409,
            message: "Cannot rotate CA key: certificate object vms-interior-leaf is missing",
        });
        expect(ApplyObject).not.toHaveBeenCalled();
    });

    it("refuses key rotation of a leaf certificate", async () => {
        certsById.set(LEAF, leaf);

        await expect(rotateCaKey(LEAF)).rejects.toMatchObject({
            statusCode: 409,
            message: "CA key rotation is only supported for certificate authorities",
        });
        expect(ApplyObject).not.toHaveBeenCalled();
    });

    it("refuses when the CA has already been superseded", async () => {
        mockClient.query.mockImplementation(async (sql) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("FROM TlsClientRevocations")) {
                return { rowCount: 0, rows: [] };
            }
            if (sql.includes("WHERE Supercedes = $1")) {
                return { rowCount: 1, rows: [{ id: NEW_CA, objectname: `vms-bb-ca-${NEW_CA}` }] };
            }
            if (sql.includes("FROM TlsCertificates WHERE Id = $1")) {
                return { rowCount: 1, rows: [oldCa] };
            }
            return { rows: [], rowCount: 0 };
        });

        await expect(rotateCaKey(OLD_CA)).rejects.toMatchObject({
            statusCode: 409,
            message: "Certificate has been superseded",
        });
        expect(ApplyObject).not.toHaveBeenCalled();
    });

    it("returns 404 when the CA row is missing", async () => {
        mockClient.query.mockResolvedValue({ rowCount: 0, rows: [] });

        await expect(rotateCaKey(OLD_CA)).rejects.toMatchObject({
            statusCode: 404,
            message: "Certificate not found",
        });
        expect(ApplyObject).not.toHaveBeenCalled();
    });

    it("recurses into nested CAs with the new parent issuer", async () => {
        const vanCa = caRow(VAN_CA, `vms-van-ca-${VAN_CA}`, {
            signedby: OLD_CA,
            label: "VAN: test",
        });
        const member = leafRow(MEMBER, "vms-member-leaf", VAN_CA, { label: "member" });
        certsById.set(VAN_CA, vanCa);
        certsById.set(MEMBER, member);
        childrenByCa.set(OLD_CA, [vanCa, leaf]);
        childrenByCa.set(VAN_CA, [member]);

        const result = await rotateCaKey(OLD_CA, {
            newId: NEW_CA,
            secretTimeoutMs: 1000,
        });

        const vanCertApply = ApplyObject.mock.calls.find(
            ([obj]) => obj.kind === "Certificate" && obj.metadata.name.startsWith("vms-van-ca-")
        );
        expect(vanCertApply).toBeTruthy();
        expect(vanCertApply[0].spec.issuerRef.name).toBe(`vms-bb-ca-${NEW_CA}`);
        expect(vanCertApply[0].spec).not.toHaveProperty("renewBefore");
        expect(TriggerCertificateRenewal).toHaveBeenCalledWith("vms-interior-leaf");
        expect(TriggerCertificateRenewal).toHaveBeenCalledWith("vms-member-leaf");
        expect(result.keyRotation.children).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ id: LEAF, action: "reissue" }),
                expect.objectContaining({
                    id: VAN_CA,
                    action: "cascade",
                    keyRotation: expect.objectContaining({
                        children: [expect.objectContaining({ id: MEMBER, action: "reissue" })],
                    }),
                }),
            ])
        );
        expect(result.refreshCertIds).toEqual(expect.arrayContaining([LEAF, MEMBER]));
    });

    it("cleans up the new CA objects when waiting for the secret times out", async () => {
        LoadSecret.mockResolvedValue(undefined);

        await expect(
            rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 0, secretIntervalMs: 0 })
        ).rejects.toMatchObject({
            statusCode: 504,
            message: `Timed out waiting for CA secret vms-bb-ca-${NEW_CA}`,
        });
        expect(DeleteIssuer).toHaveBeenCalledWith(`vms-bb-ca-${NEW_CA}`);
        expect(DeleteCertificate).toHaveBeenCalledWith(`vms-bb-ca-${NEW_CA}`);
        expect(DeleteSecret).toHaveBeenCalledWith(`vms-bb-ca-${NEW_CA}`);
        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            expect.anything()
        );
    });
});
