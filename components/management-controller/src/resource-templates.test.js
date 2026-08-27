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

import { describe, it, expect, vi } from "vitest";

vi.mock("./config.js", () => ({
    SiteControllerImage: () => "quay.io/skupper/vms-site-controller:test",
}));

import {
    HashOfData,
    HashOfConfigMap,
    HashOfObjectNoChildren,
    HashOfSecret,
    Secret,
    BackboneSite,
    NetworkCR,
    NetworkLinkCR,
    AccessPointCR,
    Deployment,
} from "./resource-templates.js";

describe("resource-templates", () => {
    it("HashOfData is stable regardless of key order", () => {
        const a = HashOfData({ b: "2", a: "1" });
        const b = HashOfData({ a: "1", b: "2" });
        expect(a).toBe(b);
        expect(a).toMatch(/^[a-f0-9]{40}$/);
    });

    it("HashOfConfigMap hashes data map", () => {
        const hash = HashOfConfigMap({ data: { key: "value" } });
        expect(hash).toBe(HashOfData({ key: "value" }));
    });

    it("HashOfObjectNoChildren ignores nested objects", () => {
        const hash = HashOfObjectNoChildren({ name: "site", spec: { nested: true } });
        expect(hash).toBe(HashOfData({ name: "site" }));
    });

    it("HashOfSecret includes tls ordinal annotations in the hash", () => {
        const data = { "tls.crt": "cert", "tls.key": "key" };
        const withoutMeta = HashOfSecret({ data });
        const withMeta = HashOfSecret({
            data,
            metadata: {
                annotations: {
                    "vms/tls-ordinal": "1",
                    "vms/tls-last-valid": "0",
                },
            },
        });
        expect(withMeta).not.toBe(withoutMeta);
        expect(withMeta).toBe(HashOfData({ ...data, ordinal: "1", lastValid: "0" }));
    });

    it("Secret annotates distributed TLS profiles with ordinal and lastValid", () => {
        const secret = Secret(
            { data: { "tls.crt": "cert", "tls.key": "key" } },
            "vms-site-1",
            "site",
            "tls-site-1",
            { ordinal: 1, lastValid: 0 }
        );
        expect(secret.metadata.annotations["vms/tls-ordinal"]).toBe("1");
        expect(secret.metadata.annotations["vms/tls-last-valid"]).toBe("0");
        expect(secret.metadata.annotations["vms/state-hash"]).toBe(
            HashOfSecret({
                data: secret.data,
                metadata: { annotations: secret.metadata.annotations },
            })
        );
    });

    it("BackboneSite produces expected CR shape", () => {
        const site = BackboneSite("backbone-a", "site-uuid-123");
        expect(site.kind).toBe("Site");
        expect(site.metadata.name).toBe("backbone-a");
        expect(site.spec.linkAccess).toBe("none");
    });

    it("NetworkCR embeds network id", () => {
        const cr = NetworkCR("van-network-id");
        expect(cr.kind).toBe("Network");
        expect(cr.spec.networkId).toBe("van-network-id");
    });

    it("NetworkLinkCR parses port as integer", () => {
        const cr = NetworkLinkCR("router.example.com", "443", "tls-secret");
        expect(cr.spec.port).toBe(443);
        expect(cr.spec.hostname).toBe("router.example.com");
    });

    it("AccessPointCR for van kind produces NetworkAccess", () => {
        const cr = AccessPointCR("ap-1", { kind: "van" });
        expect(cr.kind).toBe("NetworkAccess");
    });

    it("AccessPointCR for member kind produces RouterAccess with edge role", () => {
        const cr = AccessPointCR("ap-2", { kind: "member" });
        expect(cr.kind).toBe("RouterAccess");
        expect(cr.spec.roles[0].name).toBe("edge");
    });

    it("Deployment uses SiteControllerImage and Always pull policy by default", () => {
        const deployment = Deployment("site-uuid-1", true, "sk2");

        expect(deployment.kind).toBe("Deployment");
        expect(deployment.spec.template.spec.containers[0].image).toBe(
            "quay.io/skupper/vms-site-controller:test"
        );
        expect(deployment.spec.template.spec.containers[0].imagePullPolicy).toBe("Always");
        expect(deployment.spec.template.spec.containers[0].env).toContainEqual({
            name: "VMS_SITE_ID",
            value: "site-uuid-1",
        });
        expect(deployment.spec.template.spec.containers[0].env).toContainEqual({
            name: "VMS_BACKBONE",
            value: "YES",
        });
    });

    it("Deployment honors imageOverride with IfNotPresent pull policy", () => {
        const deployment = Deployment(
            "site-uuid-2",
            false,
            "sk2",
            "localhost:5001/vms-site-controller:kind-test"
        );

        expect(deployment.spec.template.spec.containers[0].image).toBe(
            "localhost:5001/vms-site-controller:kind-test"
        );
        expect(deployment.spec.template.spec.containers[0].imagePullPolicy).toBe("IfNotPresent");
        expect(deployment.spec.template.spec.containers[0].env).toContainEqual({
            name: "VMS_BACKBONE",
            value: "NO",
        });
    });
});
