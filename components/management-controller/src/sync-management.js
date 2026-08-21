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

"use strict";

//
// This module is the state-sync endpoint for the management controller.
//
// The responsibility of this module is to track connected sites and synchronize their state to and from
// the database.
//

import { Log } from "@vms/modules/log";
import { API_CONTROLLER_ADDRESS } from "@vms/modules/common";
import { ClientFromPool } from "./db.js";
import { LoadSecret } from "@vms/modules/kube";
import {
    CLASS_MEMBER,
    CLASS_BACKBONE,
    AddConnection,
    DeleteConnection,
    UpdateLocalState,
    Start as StateSyncStart,
    CLASS_MANAGEMENT,
    DeletePeer,
} from "@vms/modules/state-sync";
import { RegisterHandler } from "./backbone-links.js";
import { HashOfSecret, HashOfData, HashOfTlsPayload, tlsSyncData } from "./resource-templates.js";
import { SiteLifecycleChanged_TX } from "./site-deployment-state.js";
import { NotifyTransaction, RegisterNotification } from "./notify.js";
import { isRevoked, dropAccessPointCertificate, deleteKubeTlsObjectList } from "./tls-revoke.js";
import { getTlsRotationMeta } from "./tls-rotation.js";

const peers = {}; // {peerId: {pClass: <>, stuff}}

async function hashIfLiveTls(client, certId, objectName, expired = false) {
    if (expired || !certId || !objectName || (await isRevoked(client, certId))) {
        return [null, null];
    }
    const secret = await LoadSecret(objectName);
    if (!secret?.data) {
        return [null, null];
    }
    const tlsMeta = await getTlsRotationMeta(client, objectName);
    if (tlsMeta) {
        return [HashOfTlsPayload(secret.data, tlsMeta), tlsSyncData(secret.data, tlsMeta)];
    }
    return [HashOfSecret(secret), secret.data];
}

export async function GetBackboneLinks_TX(client, siteId) {
    const result = await client.query(
        "SELECT InterRouterLinks.Id, InterRouterLinks.Cost, BackboneAccessPoints.Hostname, BackboneAccessPoints.Port FROM InterRouterLinks " +
            "JOIN BackboneAccessPoints ON BackboneAccessPoints.Id = InterRouterLinks.AccessPoint " +
            "WHERE ConnectingInteriorSite = $1",
        [siteId]
    );
    const links = {};
    for (const link of result.rows) {
        if (link.hostname) {
            links[link.id] = {
                host: link.hostname,
                port: link.port,
                cost: link.cost.toString(),
            };
        }
    }
    return links;
}

export async function GetBackboneAccessPoints_TX(client, siteId, initialOnly = false) {
    const data = {};
    const result = await client.query(
        "SELECT ap.Id, ap.Kind, ap.BindHost, ap.AccessType, s.CoLocated AS colocated FROM BackboneAccessPoints ap " +
            "JOIN InteriorSites s ON s.Id = ap.InteriorSite WHERE ap.InteriorSite = $1",
        [siteId]
    );
    for (const ap of result.rows) {
        if (!initialOnly || ap.kind == "manage") {
            data[ap.id] = {
                kind: ap.kind,
            };
            if (ap.bindhost) {
                data[ap.id].bindhost = ap.bindhost;
            }
            if (ap.accesstype) {
                data[ap.id].accessType = ap.accesstype;
            }
        }
    }
    return data;
}

//=========================================================================================================================
// Backbone Site Handlers
//=========================================================================================================================
async function onNewBackboneSite(peerId) {
    //
    // peerId identifies the row in InteriorSites
    //
    // Local state:
    //   - tls-site-<id>   - The client certificate/ca for the backbone router            [ id => Site ]
    //   - tls-server-<id> - Certificates/CAs for the backbone's access points            [ id => AccessPoint ]
    //   - access-<id>     - Access point {kind: <>, bindHost?: <>, accessType?: <>, tls: <server-tls-id>}  [ id => AccessPoint ]
    //   - link-<id>       - Link {host: <>, port: <>, cost: <>}                          [ id => InterRouterLink ]
    //   - van-<id>        - VAN Endpoints (van-id)  [ only sent to co-located bb sites ] [ id => ApplicationNetwork ]
    //
    // Remote state:
    //   - accessstatus-<id> - Host/Port for an access point  {host: <>, port: <>}
    //
    Log(`Detected backbone site: ${peerId}`);
    const localState = {};
    const remoteState = {};
    const client = await ClientFromPool("system");
    const notify = new NotifyTransaction();
    try {
        await client.query("BEGIN");

        //
        // Query for the site's client certificate
        //
        const siteResult = await client.query(
            "SELECT S.Lifecycle, S.FirstActiveTime, S.Certificate, S.CoLocated, S.Backbone, C.ObjectName " +
                "FROM InteriorSites AS S " +
                "JOIN TlsCertificates AS C ON C.Id = S.Certificate " +
                "WHERE S.Id = $1",
            [peerId]
        );
        if (siteResult.rowCount != 1) {
            throw new Error(`InteriorSite not found using id ${peerId}`);
        }
        const site = siteResult.rows[0];
        if (!site.colocated) {
            // Don't sync the site secret to colocated sites.
            const [hash] = await hashIfLiveTls(client, site.certificate, site.objectname);
            localState[`tls-site-${peerId}`] = hash;
        } else {
            // Do sync the list of managed VANs on the site's backbone
            const vanResult = await client.query(
                "SELECT Id, VanId FROM ApplicationNetworks WHERE Backbone = $1",
                [site.backbone]
            );
            for (const van of vanResult.rows) {
                localState[`van-${van.id}`] = HashOfData({ vanid: van.vanid });
            }
        }

        peers[peerId].colocated = site.colocated;

        //
        // Find all of the access points associated with this backbone site.
        // If the access point is 'ready', include its certificate and include remote state for its host/port.
        //
        const accessResult = await client.query(
            "SELECT Id, Lifecycle, Certificate, Kind, BindHost, AccessType, Hostname, Port FROM BackboneAccessPoints WHERE InteriorSite = $1",
            [peerId]
        );
        for (const accessPoint of accessResult.rows) {
            if (accessPoint.kind == "manage" && site.colocated) {
                // Don't sync the manage access point to colocated sites.
                continue;
            }
            const apData = {
                kind: accessPoint.kind,
            };
            if (accessPoint.bindhost) {
                apData.bindhost = accessPoint.bindhost;
            }
            if (accessPoint.accesstype) {
                apData.accessType = accessPoint.accesstype;
            }
            if (accessPoint.lifecycle == "ready") {
                const tlsResult = await client.query(
                    "SELECT ObjectName FROM TlsCertificates WHERE Id = $1",
                    [accessPoint.certificate]
                );
                if (tlsResult.rowCount != 1) {
                    throw new Error(
                        `Access point in ready state does not have a TlsCertificate - ${accessPoint.id}`
                    );
                }
                const [hash] = await hashIfLiveTls(
                    client,
                    accessPoint.certificate,
                    tlsResult.rows[0].objectname
                );
                localState[`tls-server-${accessPoint.id}`] = hash;
                remoteState[`accessstatus-${accessPoint.id}`] = HashOfData({
                    host: accessPoint.hostname,
                    port: accessPoint.port,
                });
            }
            localState[`access-${accessPoint.id}`] = HashOfData(apData);
        }

        //
        // Find the links from this backbone site.
        //
        const linkResult = await client.query(
            "SELECT InterRouterLinks.Id, Cost, BackboneAccessPoints.Lifecycle, BackboneAccessPoints.Hostname, BackboneAccessPoints.Port FROM InterRouterLinks " +
                "JOIN BackboneAccessPoints ON BackboneAccessPoints.Id = AccessPoint " +
                "WHERE ConnectingInteriorSite = $1 AND Lifecycle = 'ready'",
            [peerId]
        );
        for (const link of linkResult.rows) {
            localState[`link-${link.id}`] = HashOfData({
                host: link.hostname,
                port: link.port,
                cost: link.cost,
            });
        }

        //
        // Update the timestamps and lifecycle on the interior site
        //
        if (site.lifecycle == "ready") {
            await client.query(
                "UPDATE InteriorSites SET FirstActiveTime = CURRENT_TIMESTAMP, LastHeartbeat = CURRENT_TIMESTAMP, LifeCycle = 'active' WHERE Id = $1",
                [peerId]
            );
            await SiteLifecycleChanged_TX(client, notify, peerId, "active");
        } else {
            await client.query(
                "UPDATE InteriorSites SET LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1",
                [peerId]
            );
        }
        notify.update("InteriorSites", peerId);

        await client.query("COMMIT");
        await notify.commit();
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in onNewBackboneSite processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [localState, remoteState];
}

async function onLostBackbone(_peerId) {
    // Nothing to do here - Consider adding status to the schema to indicate a stale site
}

async function onStateChangeBackbone(peerId, stateKey, hash, data) {
    if (stateKey.substring(0, 13) != "accessstatus-") {
        Log(`Unexpected state-key ${stateKey} in onStateChangeBackbone`);
        return;
    }

    const accessId = stateKey.substring(13);
    const client = await ClientFromPool("system");
    const notify = new NotifyTransaction();
    let droppedObjectNames = [];
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT Id, Lifecycle, Hostname, Port, Certificate FROM BackboneAccessPoints " +
                "WHERE Id = $1 AND InteriorSite = $2",
            [accessId, peerId]
        );
        if (result.rowCount != 1) {
            await client.query("COMMIT");
            return;
        }
        const accessPoint = result.rows[0];

        if (!hash) {
            droppedObjectNames = await dropAccessPointCertificate(client, notify, accessId);
            await client.query(
                "UPDATE BackboneAccessPoints SET Hostname = NULL, Port = NULL, Certificate = NULL, Lifecycle = 'partial' " +
                    "WHERE Id = $1",
                [accessId]
            );
            notify.update("BackboneAccessPoints", accessId);
        } else {
            const unchanged =
                accessPoint.lifecycle != "partial" &&
                accessPoint.hostname == data.host &&
                String(accessPoint.port ?? "") === String(data.port ?? "");
            if (!unchanged) {
                droppedObjectNames = await dropAccessPointCertificate(client, notify, accessId);
                await client.query(
                    "UPDATE BackboneAccessPoints SET Hostname = $1, Port = $2, Certificate = NULL, Lifecycle = 'new' " +
                        "WHERE Id = $3",
                    [data.host, data.port, accessId]
                );
                notify.update("BackboneAccessPoints", accessId);
            }
        }

        await client.query("COMMIT");
        await notify.commit();
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in onStateChangeBackbone processing: ${error.message}`);
        Log(error.stack);
        droppedObjectNames = [];
    } finally {
        client.release();
    }

    await deleteKubeTlsObjectList(droppedObjectNames);
    if (droppedObjectNames.length > 0) {
        await UpdateLocalState(peerId, `tls-server-${accessId}`, null);
    }
}

async function getStateTlsBackboneSite(siteId) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT TlsCertificates.Id, TlsCertificates.ObjectName FROM InteriorSites " +
                "JOIN TlsCertificates ON TlsCertificates.Id = Certificate " +
                "WHERE InteriorSites.Id = $1",
            [siteId]
        );
        if (result.rowCount == 1) {
            [hash, data] = await hashIfLiveTls(
                client,
                result.rows[0].id,
                result.rows[0].objectname
            );
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in getStateTlsSite processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function getStateTlsMemberSite(siteId) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT MemberSites.Lifecycle, MemberSites.Certificate, TlsCertificates.ObjectName FROM MemberSites " +
                "LEFT JOIN TlsCertificates ON TlsCertificates.Id = MemberSites.Certificate " +
                "WHERE MemberSites.Id = $1",
            [siteId]
        );
        if (result.rowCount == 1) {
            const site = result.rows[0];
            [hash, data] = await hashIfLiveTls(
                client,
                site.certificate,
                site.objectname,
                site.lifecycle == "expired"
            );
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in getStateTlsSite processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function getStateTlsServer(apid) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT TlsCertificates.Id, TlsCertificates.ObjectName FROM BackboneAccessPoints " +
                "JOIN TlsCertificates ON TlsCertificates.Id = Certificate " +
                "WHERE BackboneAccessPoints.Id = $1",
            [apid]
        );
        if (result.rowCount == 1) {
            [hash, data] = await hashIfLiveTls(
                client,
                result.rows[0].id,
                result.rows[0].objectname
            );
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in getStateTls processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function getStateAccessPoint(apId) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT Kind, Bindhost FROM BackboneAccessPoints WHERE Id = $1",
            [apId]
        );
        if (result.rowCount == 1) {
            const accessPoint = result.rows[0];
            data = {
                kind: accessPoint.kind,
            };
            if (accessPoint.bindhost) {
                data.bindhost = accessPoint.bindhost;
            }
            hash = HashOfData(data);
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in getStateTls processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function getStateBackboneLink(linkId) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT Cost, BackboneAccessPoints.Hostname, BackboneAccessPoints.Port FROM InterRouterLinks " +
                "JOIN BackboneAccessPoints ON BackboneAccessPoints.Id = AccessPoint " +
                "WHERE InterRouterLinks.Id = $1 AND Lifecycle = 'ready'",
            [linkId]
        );
        if (result.rowCount == 1) {
            const link = result.rows[0];
            data = {
                host: link.hostname,
                port: link.port,
                cost: link.cost,
            };
            hash = HashOfData(data);
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in getStateBackboneLink processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function getStateMemberLink(linkId) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT BackboneAccessPoints.Hostname, BackboneAccessPoints.Port FROM EdgeLinks " +
                "JOIN BackboneAccessPoints ON BackboneAccessPoints.Id = AccessPoint " +
                "WHERE EdgeLinks.Id = $1 AND Lifecycle = 'ready'",
            [linkId]
        );
        if (result.rowCount == 1) {
            const link = result.rows[0];
            data = {
                host: link.hostname,
                port: link.port,
                cost: "1",
            };
            hash = HashOfData(data);
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in getStateMemberLink processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function getStateVanIds(vid) {
    let hash = null;
    let data = null;
    const client = await ClientFromPool("system");
    try {
        const vanResult = await client.query(
            "SELECT VanId FROM ApplicationNetworks WHERE Id = $1",
            [vid]
        );
        if (vanResult.rowCount == 1) {
            data = {
                vanid: vanResult.rows[0].vanid,
            };
            hash = HashOfData(data);
        }
    } catch (error) {
        Log(`Exception in getStateVanIds: ${error.stack}`);
    } finally {
        client.release();
    }
    return [hash, data];
}

async function onStateRequestBackbone(peerId, stateKey) {
    let hash = null;
    let data = null;

    if (stateKey.substring(0, 9) == "tls-site-") {
        [hash, data] = await getStateTlsBackboneSite(stateKey.substring(9));
    } else if (stateKey.substring(0, 11) == "tls-server-") {
        [hash, data] = await getStateTlsServer(stateKey.substring(11));
    } else if (stateKey.substring(0, 7) == "access-") {
        [hash, data] = await getStateAccessPoint(stateKey.substring(7));
    } else if (stateKey.substring(0, 5) == "link-") {
        [hash, data] = await getStateBackboneLink(stateKey.substring(5));
    } else if (stateKey.substring(0, 4) == "van-") {
        [hash, data] = await getStateVanIds(stateKey.substring(4));
    } else {
        Log(`Invalid stateKey for onStateRequestBackbone processing: ${stateKey}`);
    }

    return [hash, data];
}

//=========================================================================================================================
// Member Site Handlers
//=========================================================================================================================
async function onNewMember(peerId) {
    //
    // peerId identifies the row in MemberSites
    //
    // Local state:
    //   - tls-site-<id>   - The client certificate/ca for the backbone router            [ id => Site ]
    //   - link-<id>       - Link {host: <>, port: <>, cost: <>}                          [ id => InterRouterLink ]
    //
    // Remote state: none
    //
    Log(`Detected member site: ${peerId}`);
    const localState = {};
    const remoteState = {};
    const client = await ClientFromPool("system");
    const notify = new NotifyTransaction();
    try {
        await client.query("BEGIN");

        //
        // Query for the site's client certificate
        //
        const siteResult = await client.query(
            "SELECT Lifecycle, FirstActiveTime, Certificate, TlsCertificates.ObjectName FROM MemberSites " +
                "LEFT JOIN TlsCertificates ON TlsCertificates.Id = MemberSites.Certificate " +
                "WHERE MemberSites.Id = $1",
            [peerId]
        );
        if (siteResult.rowCount != 1) {
            throw new Error(`MemberSite not found using id ${peerId}`);
        }
        const site = siteResult.rows[0];
        // Expired, revoked, and missing secrets must not be served or promoted to active.
        const [tlsHash] = await hashIfLiveTls(
            client,
            site.certificate,
            site.objectname,
            site.lifecycle == "expired"
        );
        localState[`tls-site-${peerId}`] = tlsHash;

        //
        // Find the links from this member site.
        //
        const linkResult = await client.query(
            "SELECT EdgeLinks.Id, BackboneAccessPoints.Lifecycle, BackboneAccessPoints.Hostname, BackboneAccessPoints.Port FROM EdgeLinks " +
                "JOIN BackboneAccessPoints ON BackboneAccessPoints.Id = AccessPoint " +
                "JOIN MemberSites ON MemberSites.Invitation = EdgeToken " +
                "WHERE MemberSites.Id = $1 AND BackboneAccessPoints.Lifecycle = 'ready'",
            [peerId]
        );
        for (const link of linkResult.rows) {
            localState[`link-${link.id}`] = HashOfData({
                host: link.hostname,
                port: link.port,
                cost: "1",
            });
        }

        //
        // Update the timestamps and lifecycle on the member site
        //
        if (site.lifecycle == "ready" && tlsHash) {
            await client.query(
                "UPDATE MemberSites SET FirstActiveTime = CURRENT_TIMESTAMP, LastHeartbeat = CURRENT_TIMESTAMP, LifeCycle = 'active' WHERE Id = $1",
                [peerId]
            );
        } else {
            await client.query(
                "UPDATE MemberSites SET LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1",
                [peerId]
            );
        }
        notify.update("MemberSites", peerId);

        await client.query("COMMIT");
        await notify.commit();
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in onNewMember processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }

    return [localState, remoteState];
}

async function onLostMember(peerId) {
    const client = await ClientFromPool("system");
    const notify = new NotifyTransaction();
    try {
        await client.query("BEGIN");
        await client.query(
            "UPDATE MemberSites SET LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1",
            [peerId]
        );
        notify.update("MemberSites", peerId);
        await client.query("COMMIT");
        await notify.commit();
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in onLostMember processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
}

async function onStateChangeMember(_peerId, _stateKey, _hash, _data) {
    // There is no local state on a member site
}

async function onStateRequestMember(peerId, stateKey) {
    let hash = null;
    let data = null;

    if (stateKey.substring(0, 9) == "tls-site-") {
        [hash, data] = await getStateTlsMemberSite(stateKey.substring(9));
    } else if (stateKey.substring(0, 5) == "link-") {
        [hash, data] = await getStateMemberLink(stateKey.substring(5));
    }

    return [hash, data];
}

//=========================================================================================================================
// Sync Handlers
//=========================================================================================================================
async function onNewPeer(peerId, peerClass) {
    let localState;
    let remoteState;
    peers[peerId] = {
        pClass: peerClass,
    };

    if (peerClass == CLASS_MEMBER) {
        [localState, remoteState] = await onNewMember(peerId);
    } else if (peerClass == CLASS_BACKBONE) {
        [localState, remoteState] = await onNewBackboneSite(peerId);
    }

    return [localState, remoteState];
}

async function onPeerLost(peerId) {
    const peer = peers[peerId];
    if (peer) {
        if (peer.pClass == CLASS_MEMBER) {
            await onLostMember(peerId);
        } else if (peer.pClass == CLASS_BACKBONE) {
            await onLostBackbone(peerId);
        }

        delete peers[peerId];
    }
}

async function onStateChange(peerId, stateKey, hash, data) {
    const peer = peers[peerId];
    if (peer) {
        if (peer.pClass == CLASS_MEMBER) {
            await onStateChangeMember(peerId, stateKey, hash, data);
        } else if (peer.pClass == CLASS_BACKBONE) {
            await onStateChangeBackbone(peerId, stateKey, hash, data);
        }
    }
}

async function onStateRequest(peerId, stateKey) {
    let hash = null;
    let data = null;
    const peer = peers[peerId];
    if (peer) {
        if (peer.pClass == CLASS_MEMBER) {
            [hash, data] = await onStateRequestMember(peerId, stateKey);
        } else if (peer.pClass == CLASS_BACKBONE) {
            [hash, data] = await onStateRequestBackbone(peerId, stateKey);
        }
    }
    return [hash, data];
}

async function onPing(peerId) {
    const client = await ClientFromPool("system");
    const notify = new NotifyTransaction();
    try {
        await client.query("BEGIN");
        const peer = peers[peerId];
        if (peer.pClass == CLASS_BACKBONE) {
            await client.query(
                "UPDATE InteriorSites SET LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1",
                [peerId]
            );
            notify.update("InteriorSites", peerId);
        } else if (peer.pClass == CLASS_MEMBER) {
            await client.query(
                "UPDATE MemberSites SET LastHeartbeat = CURRENT_TIMESTAMP WHERE Id = $1",
                [peerId]
            );
            notify.update("MemberSites", peerId);
        }
        await client.query("COMMIT");
        await notify.commit();
    } catch (error) {
        await client.query("ROLLBACK");
        Log(`Exception in onPing processing: ${error.message}`);
        Log(error.stack);
    } finally {
        client.release();
    }
}

//=========================================================================================================================
// Backbone Link Handlers
//=========================================================================================================================
async function onLinkAdded(key, conn) {
    await AddConnection(key, conn);
}

async function onLinkDeleted(key) {
    await DeleteConnection(key);
}

//=========================================================================================================================
// Database change notifications that affect local state
//=========================================================================================================================
export async function SiteCertificateChanged(certId) {
    //
    // Update the tls-site-<id> hash for the one affected site
    //
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT InteriorSites.Id, TlsCertificates.ObjectName FROM InteriorSites " +
                "JOIN TlsCertificates ON TlsCertificates.Id = InteriorSites.Certificate " +
                "WHERE Certificate = $1 " +
                "UNION " +
                "SELECT MemberSites.Id, TlsCertificates.ObjectName FROM MemberSites " +
                "JOIN TlsCertificates ON TlsCertificates.Id = MemberSites.Certificate " +
                "WHERE Certificate = $1",
            [certId]
        );
        for (const site of result.rows) {
            if (!peers[site.id]) {
                continue;
            }
            const secret = await LoadSecret(site.objectname);
            const tlsMeta = await getTlsRotationMeta(client, site.objectname);
            const hash = tlsMeta ? HashOfTlsPayload(secret.data, tlsMeta) : HashOfSecret(secret);
            await UpdateLocalState(site.id, `tls-site-${site.id}`, hash);
        }
        await client.query("COMMIT");
    } catch (error) {
        Log(`Exception in SiteCertificateChanged: ${error.message}`);
        await client.query("ROLLBACK");
    } finally {
        client.release();
    }
}

export async function AccessCertificateChanged(certId) {
    //
    // Update the tls-server-<id> hashes for the one affected site
    //
    const client = await ClientFromPool("system");
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT BackboneAccessPoints.Id as apid, InteriorSites.Id, TlsCertificates.ObjectName FROM BackboneAccessPoints " +
                "JOIN InteriorSites ON InteriorSites.id = InteriorSite " +
                "JOIN TlsCertificates ON TlsCertificates.Id = BackboneAccessPoints.Certificate " +
                "WHERE BackboneAccessPoints.Certificate = $1",
            [certId]
        );
        if (result.rowCount == 1) {
            const row = result.rows[0];
            if (peers[row.id]) {
                const secret = await LoadSecret(row.objectname);
                const tlsMeta = await getTlsRotationMeta(client, row.objectname);
                const hash = tlsMeta
                    ? HashOfTlsPayload(secret.data, tlsMeta)
                    : HashOfSecret(secret);
                await UpdateLocalState(row.id, `tls-server-${row.apid}`, hash);
            }
        }
        await client.query("COMMIT");
    } catch (error) {
        Log(`Exception in AccessCertificateChanged: ${error.message}`);
        await client.query("ROLLBACK");
    } finally {
        client.release();
    }
}

export async function SiteIngressChanged(siteId, accessPointId) {
    //
    // Update the access-<id> hash for the one affected site
    //
    if (peers[siteId]) {
        const client = await ClientFromPool("system");
        try {
            await client.query("BEGIN");
            const result = await client.query(
                "SELECT BackboneAccessPoints.Kind, BackboneAccessPoints.BindHost, BackboneAccessPoints.AccessType, BackboneAccessPoints.Certificate, BackboneAccessPoints.Lifecycle,  InteriorSites.CoLocated " +
                    "FROM BackboneAccessPoints JOIN InteriorSites ON InteriorSites.Id = BackboneAccessPoints.InteriorSite WHERE BackboneAccessPoints.Id = $1",
                [accessPointId]
            );
            if (result.rowCount == 1) {
                const row = result.rows[0];
                const ap = { kind: row.kind };
                if (row.bindhost) {
                    ap.bindhost = row.bindhost;
                }
                if (row.accesstype) {
                    ap.accessType = row.accesstype;
                }
                const hash = HashOfData(ap);
                await UpdateLocalState(siteId, `access-${accessPointId}`, hash);
            } else {
                await UpdateLocalState(siteId, `access-${accessPointId}`, null);
                await UpdateLocalState(siteId, `tls-server-${accessPointId}`, null);
            }
            await client.query("COMMIT");
        } catch (error) {
            Log(`Exception in SiteIngressChanged: ${error.message}`);
            await client.query("ROLLBACK");
        } finally {
            client.release();
        }
    }
}

export async function LinkChanged(connectingSiteId, linkId) {
    //
    // Update the link-<id> hash for the one affected connecting site
    //
    if (peers[connectingSiteId]) {
        const client = await ClientFromPool("system");
        try {
            let hash = null;
            await client.query("BEGIN");
            const result = await client.query(
                "SELECT Cost, BackboneAccessPoints.Hostname, BackboneAccessPoints.Port FROM InterRouterLinks " +
                    "JOIN BackboneAccessPoints ON BackboneAccessPoints.Id = AccessPoint " +
                    "WHERE InterRouterLinks.Id = $1",
                [linkId]
            );
            if (result.rowCount == 1) {
                const row = result.rows[0];
                const link = {
                    host: row.hostname,
                    port: row.port,
                    cost: row.cost,
                };
                hash = HashOfData(link);
            }
            await UpdateLocalState(connectingSiteId, `link-${linkId}`, hash);
            await client.query("COMMIT");
        } catch (error) {
            Log(`Exception in LinkChanged: ${error.message}`);
            await client.query("ROLLBACK");
        } finally {
            client.release();
        }
    }
}

async function onApplicationNetworkChange(action, id) {
    let hash = null;
    let doUpdate = false;

    if (action == "ADD") {
        const client = await ClientFromPool("system");
        try {
            const result = await client.query(
                "SELECT vanId FROM ApplicationNetworks WHERE Id = $1",
                [id]
            );
            if (result.rowCount == 1) {
                hash = HashOfData({ vanid: result.rows[0].vanid });
            }
        } catch (error) {
            Log(`Exception in onApplicationNetworkChange: ${error.stack}`);
        } finally {
            client.release();
        }
        doUpdate = true;
    } else if (action == "DELETE") {
        doUpdate = true;
    }

    if (doUpdate) {
        for (const [peerId, peerData] of Object.entries(peers)) {
            if (peerData.colocated) {
                await UpdateLocalState(peerId, `van-${id}`, hash);
            }
        }
    }
}

async function listAccessPointIds(siteId) {
    const client = await ClientFromPool("system");
    try {
        const result = await client.query(
            "SELECT Id FROM BackboneAccessPoints WHERE InteriorSite = $1",
            [siteId]
        );
        return result.rows.map((row) => row.id);
    } finally {
        client.release();
    }
}

export async function SiteDeleted(siteId, accessPointIds) {
    await UpdateLocalState(siteId, `tls-site-${siteId}`, null);
    let serverIds = accessPointIds;
    if (serverIds === undefined) {
        try {
            serverIds = await listAccessPointIds(siteId);
        } catch (error) {
            Log(`Exception in SiteDeleted processing: ${error.message}`);
            Log(error.stack);
            serverIds = [];
        }
    }
    for (const apId of serverIds) {
        await UpdateLocalState(siteId, `tls-server-${apId}`, null);
    }
    await DeletePeer(siteId);
}

export async function MemberEvicted(memberId) {
    await UpdateLocalState(memberId, `tls-site-${memberId}`, null);
}

export async function Start() {
    await StateSyncStart(
        CLASS_MANAGEMENT,
        "mc",
        API_CONTROLLER_ADDRESS,
        onNewPeer,
        onPeerLost,
        onStateChange,
        onStateRequest,
        onPing
    );
    await RegisterHandler(onLinkAdded, onLinkDeleted);
    await RegisterNotification("ApplicationNetworks", onApplicationNetworkChange, false);
}

/** @internal Exported for unit tests */
export function _registerPeerForTest(peerId, peerClass = CLASS_BACKBONE) {
    peers[peerId] = { pClass: peerClass };
}

/** @internal Exported for unit tests */
export {
    onNewMember as _onNewMemberForTest,
    onLostMember as _onLostMemberForTest,
    getStateTlsMemberSite as _getStateTlsMemberSiteForTest,
    onStateChangeBackbone as _onStateChangeBackboneForTest,
};
