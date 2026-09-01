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
const AP = "00000000-0000-4000-8000-000000000016";

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
        expect(nextCaObjectName(`vms-interior-${LEAF}`, NEW_CA)).toBe(`vms-interior-${NEW_CA}`);
    });

    it("appends the new id when the name has no UUID suffix", () => {
        expect(nextCaObjectName("vms-root-ca", NEW_CA)).toBe(`vms-root-ca-${NEW_CA}`);
        expect(nextCaObjectName("vms-interior-leaf", NEW_CA)).toBe(`vms-interior-leaf-${NEW_CA}`);
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
    const manageCertIds = new Set();

    function installQuery() {
        mockClient.query.mockImplementation(async (sql, params) => {
            if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
                return {};
            }
            if (sql.includes("Kind = 'manage'")) {
                return {
                    rows: [...manageCertIds].map((certificate) => ({ certificate })),
                };
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

    function appliedLeafCertificates() {
        return ApplyObject.mock.calls
            .map(([obj]) => obj)
            .filter((obj) => obj.kind === "Certificate" && obj.spec?.isCA !== true);
    }

    beforeEach(() => {
        vi.clearAllMocks();
        mockClient.query.mockReset();
        missingCerts.clear();
        childrenByCa.clear();
        certsById.clear();
        manageCertIds.clear();
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
            const isBackboneCa = name.startsWith("vms-bb-ca-");
            return {
                metadata: { name },
                spec: {
                    duration: "8760h",
                    commonName: name,
                    issuerRef: {
                        name: isBackboneCa ? "vms-root" : oldCa.objectname,
                        kind: "Issuer",
                        group: "cert-manager.io",
                    },
                    privateKey: { algorithm: "RSA", encoding: "PKCS1", size: 2048 },
                    secretTemplate: {
                        annotations: { "skupper.io/vms-issuerlink": OLD_CA },
                    },
                    usages: name.includes("access") ? ["server auth"] : ["client auth"],
                    ...(name.includes("access") ? { dnsNames: ["ap.example.com"] } : {}),
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

    it("issues a new CA and Issuer, then new Certificate objects for live leaves", async () => {
        const result = await rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 1000 });

        expect(ApplyObject).toHaveBeenCalledWith(
            expect.objectContaining({
                kind: "Certificate",
                metadata: expect.objectContaining({ name: `vms-bb-ca-${NEW_CA}` }),
                spec: expect.objectContaining({
                    isCA: true,
                    secretName: `vms-bb-ca-${NEW_CA}`,
                    issuerRef: expect.objectContaining({ name: "vms-root" }),
                    privateKey: expect.objectContaining({ algorithm: "RSA" }),
                }),
            })
        );
        const newCaCert = ApplyObject.mock.calls.find(([obj]) => obj.kind === "Certificate")[0];
        expect(newCaCert.spec).not.toHaveProperty("renewBefore");
        expect(newCaCert.spec.privateKey).not.toHaveProperty("rotationPolicy");
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
        const leafCerts = appliedLeafCertificates();
        expect(leafCerts).toHaveLength(1);
        expect(leafCerts[0].metadata.name).toMatch(/^vms-interior-leaf-/);
        expect(leafCerts[0].spec.isCA).toBe(false);
        expect(leafCerts[0].spec.secretName).toBe(leafCerts[0].metadata.name);
        expect(leafCerts[0].spec.issuerRef.name).toBe(`vms-bb-ca-${NEW_CA}`);
        expect(leafCerts[0].spec.secretTemplate.annotations["skupper.io/vms-issuerlink"]).toBe(
            NEW_CA
        );
        expect(ReplaceCertificate).not.toHaveBeenCalled();
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
        const issued = result.keyRotation.children[0];
        expect(issued).toEqual({
            id: expect.any(String),
            previousId: LEAF,
            objectname: leafCerts[0].metadata.name,
            isca: false,
            action: "reissue",
        });
        expect(issued.id).not.toBe(LEAF);
        expect(result.keyRotation.newCertificateId).toBe(NEW_CA);
        expect(result.keyRotation.objectName).toBe(`vms-bb-ca-${NEW_CA}`);
        expect(result.refreshCertIds).toEqual([issued.id]);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            [
                issued.id,
                issued.objectname,
                NEW_CA,
                expect.any(Date),
                expect.any(Date),
                1,
                LEAF,
                leaf.label,
            ]
        );
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("SET Certificate = $1 WHERE Certificate = $2"),
            [issued.id, LEAF]
        );
        expect(DeleteCertificate).not.toHaveBeenCalledWith("vms-interior-leaf");
        expect(DeleteSecret).not.toHaveBeenCalledWith("vms-interior-leaf");
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
        const leafNames = appliedLeafCertificates().map((obj) => obj.metadata.name);
        expect(leafNames).toEqual(
            expect.arrayContaining([
                expect.stringMatching(/^vms-interior-leaf-/),
                expect.stringMatching(/^vms-member-leaf-/),
            ])
        );
        expect(
            appliedLeafCertificates().find((obj) =>
                obj.metadata.name.startsWith("vms-interior-leaf-")
            ).spec.issuerRef.name
        ).toBe(`vms-bb-ca-${NEW_CA}`);
        expect(
            appliedLeafCertificates().find((obj) =>
                obj.metadata.name.startsWith("vms-member-leaf-")
            ).spec.issuerRef.name
        ).toMatch(/^vms-van-ca-/);
        expect(ReplaceCertificate).not.toHaveBeenCalled();
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
        expect(result.keyRotation.children).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ previousId: LEAF, action: "reissue" }),
                expect.objectContaining({
                    id: VAN_CA,
                    action: "cascade",
                    keyRotation: expect.objectContaining({
                        children: [
                            expect.objectContaining({ previousId: MEMBER, action: "reissue" }),
                        ],
                    }),
                }),
            ])
        );
        expect(result.refreshCertIds).toHaveLength(2);
        expect(result.refreshCertIds).not.toContain(LEAF);
        expect(result.refreshCertIds).not.toContain(MEMBER);
    });

    it("issues new leaf objects again when the successor CA is rotated", async () => {
        const first = await rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 1000 });
        const firstLeaf = first.keyRotation.children[0];
        const NEXT_CA = "00000000-0000-4000-8000-000000000018";
        certsById.set(NEW_CA, caRow(NEW_CA, `vms-bb-ca-${NEW_CA}`));
        certsById.set(
            firstLeaf.id,
            leafRow(firstLeaf.id, firstLeaf.objectname, NEW_CA, {
                supercedes: LEAF,
                rotationordinal: 1,
            })
        );
        childrenByCa.set(OLD_CA, []);
        childrenByCa.set(NEW_CA, [certsById.get(firstLeaf.id)]);
        ApplyObject.mockClear();

        const second = await rotateCaKey(NEW_CA, { newId: NEXT_CA, secretTimeoutMs: 1000 });

        const secondLeaf = second.keyRotation.children[0];
        expect(secondLeaf.previousId).toBe(firstLeaf.id);
        expect(secondLeaf.objectname).not.toBe(firstLeaf.objectname);
        expect(secondLeaf.objectname).toMatch(/^vms-interior-leaf-/);
        const leafCert = appliedLeafCertificates().find(
            (obj) => obj.metadata.name === secondLeaf.objectname
        );
        expect(leafCert.spec.issuerRef.name).toBe(`vms-bb-ca-${NEXT_CA}`);
        expect(ReplaceCertificate).not.toHaveBeenCalled();
        expect(TriggerCertificateRenewal).not.toHaveBeenCalled();
        expect(DeleteCertificate).not.toHaveBeenCalledWith(firstLeaf.objectname);
    });

    it("re-issues leaves still signed by a superseded predecessor CA", async () => {
        const liveCa = caRow(NEW_CA, `vms-bb-ca-${NEW_CA}`, {
            supercedes: OLD_CA,
            rotationordinal: 1,
        });
        const NEXT_CA = "00000000-0000-4000-8000-000000000018";
        certsById.set(NEW_CA, liveCa);
        childrenByCa.set(NEW_CA, []);
        childrenByCa.set(OLD_CA, [leaf]);

        const result = await rotateCaKey(NEW_CA, { newId: NEXT_CA, secretTimeoutMs: 1000 });

        expect(result.keyRotation.children).toEqual([
            expect.objectContaining({ previousId: LEAF, action: "reissue" }),
        ]);
        const leafCert = appliedLeafCertificates().find((obj) =>
            obj.metadata.name.startsWith("vms-interior-leaf-")
        );
        expect(leafCert.spec.issuerRef.name).toBe(`vms-bb-ca-${NEXT_CA}`);
    });

    it("copies access-point dnsNames onto the new leaf Certificate", async () => {
        const ap = leafRow(AP, "vms-access-leaf", OLD_CA, { label: "access" });
        certsById.set(AP, ap);
        childrenByCa.set(OLD_CA, [ap]);

        await rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 1000 });

        const accessCert = appliedLeafCertificates().find((obj) =>
            obj.metadata.name.startsWith("vms-access-leaf-")
        );
        expect(accessCert.spec.dnsNames).toEqual(["ap.example.com"]);
        expect(accessCert.spec.usages).toEqual(["server auth"]);
        expect(accessCert.spec.issuerRef.name).toBe(`vms-bb-ca-${NEW_CA}`);
    });

    it("re-issues manage access-point certs after other live leaves", async () => {
        const ap = leafRow(AP, "vms-access-leaf", OLD_CA, { label: "access" });
        certsById.set(AP, ap);
        childrenByCa.set(OLD_CA, [ap, leaf]);
        manageCertIds.add(AP);

        await rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 1000 });

        const leafApplies = appliedLeafCertificates();
        const interiorIdx = leafApplies.findIndex((obj) =>
            obj.metadata.name.startsWith("vms-interior-leaf-")
        );
        const accessIdx = leafApplies.findIndex((obj) =>
            obj.metadata.name.startsWith("vms-access-leaf-")
        );
        expect(interiorIdx).toBeGreaterThanOrEqual(0);
        expect(accessIdx).toBeGreaterThan(interiorIdx);
    });

    it("re-issues remaining leaves when one leaf Certificate create fails", async () => {
        const ap = leafRow(AP, "vms-access-leaf", OLD_CA, { label: "access" });
        certsById.set(AP, ap);
        childrenByCa.set(OLD_CA, [leaf, ap]);
        ApplyObject.mockImplementation(async (obj) => {
            if (obj.kind === "Certificate" && obj.spec?.isCA !== true) {
                if (obj.metadata.name.startsWith("vms-interior-leaf-")) {
                    const err = new Error("apply failed");
                    err.statusCode = 500;
                    throw err;
                }
            }
            return { metadata: { name: "created" } };
        });

        await expect(
            rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 1000 })
        ).rejects.toMatchObject({
            statusCode: 500,
            message: expect.stringContaining("vms-interior-leaf"),
        });
        expect(
            appliedLeafCertificates().some((obj) =>
                obj.metadata.name.startsWith("vms-access-leaf-")
            )
        ).toBe(true);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            expect.arrayContaining([NEW_CA, `vms-bb-ca-${NEW_CA}`])
        );
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            expect.arrayContaining([NEW_CA, expect.stringMatching(/^vms-access-leaf-/), AP])
        );
        expect(mockClient.query).not.toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            expect.arrayContaining([LEAF])
        );
    });

    it("cleans up a new leaf when waiting for its secret times out", async () => {
        LoadSecret.mockImplementation(async (name) => {
            if (name.startsWith("vms-bb-ca-")) {
                return { data: { "tls.crt": b64(pem("ca")) } };
            }
            return undefined;
        });

        await expect(
            rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 0, secretIntervalMs: 0 })
        ).rejects.toMatchObject({
            statusCode: 504,
            message: expect.stringMatching(
                /Timed out waiting for certificate secret vms-interior-leaf-/
            ),
        });
        const leafName = appliedLeafCertificates()[0].metadata.name;
        expect(DeleteCertificate).toHaveBeenCalledWith(leafName);
        expect(DeleteSecret).toHaveBeenCalledWith(leafName);
        expect(DeleteIssuer).not.toHaveBeenCalledWith(leafName);
        expect(DeleteCertificate).not.toHaveBeenCalledWith(`vms-bb-ca-${NEW_CA}`);
        expect(mockClient.query).toHaveBeenCalledWith(
            expect.stringContaining("INSERT INTO TlsCertificates"),
            expect.arrayContaining([NEW_CA, `vms-bb-ca-${NEW_CA}`])
        );
    });

    it("cleans up the new CA objects when waiting for the secret times out", async () => {
        LoadSecret.mockResolvedValue(undefined);

        await expect(
            rotateCaKey(OLD_CA, { newId: NEW_CA, secretTimeoutMs: 0, secretIntervalMs: 0 })
        ).rejects.toMatchObject({
            statusCode: 504,
            message: `Timed out waiting for certificate secret vms-bb-ca-${NEW_CA}`,
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
