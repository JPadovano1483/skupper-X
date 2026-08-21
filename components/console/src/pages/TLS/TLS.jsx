import React, { useState, useEffect, useCallback } from "react";
import {
    Breadcrumb,
    BreadcrumbItem,
    Table,
    TableHead,
    TableRow,
    TableHeader,
    TableBody,
    TableCell,
    TableContainer,
    TableExpandRow,
    TableExpandedRow,
    TableExpandHeader,
    Tag,
    InlineNotification,
    Loading,
    OverflowMenu,
    OverflowMenuItem,
    Modal,
    Select,
    SelectItem,
} from "@carbon/react";
import { Certificate, DocumentSigned } from "@carbon/icons-react";

const CA_REVOKE_UNAVAILABLE = "CA certificate revocation is not supported";

const certsUrl = ({ signedBy, expiresWithin } = {}) => {
    const params = new URLSearchParams();
    if (signedBy) {
        params.set("signedby", signedBy);
    }
    if (expiresWithin) {
        params.set("expiresWithin", String(expiresWithin));
    }
    const qs = params.toString();
    return qs ? `/api/v1alpha1/certs?${qs}` : "/api/v1alpha1/certs";
};

const postCertAction = async (certId, action, query) => {
    const qs = query ? `?${new URLSearchParams(query)}` : "";
    const response = await fetch(`/api/v1alpha1/certs/${certId}/${action}${qs}`, {
        method: "POST",
    });
    if (!response.ok) {
        const text = await response.text();
        const error = new Error(text || `HTTP error! status: ${response.status}`);
        error.status = response.status;
        throw error;
    }
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }
    return null;
};

const TLS = () => {
    const [certificates, setCertificates] = useState([]);
    const [childCerts, setChildCerts] = useState({});
    const [loadingChildren, setLoadingChildren] = useState({});
    const [expandedRows, setExpandedRows] = useState({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [expiresWithin, setExpiresWithin] = useState("");
    const [actionNotice, setActionNotice] = useState(null);
    const [actionBusy, setActionBusy] = useState(false);
    const [certToRevoke, setCertToRevoke] = useState(null);
    const [certToRotateKey, setCertToRotateKey] = useState(null);
    const [revokeError, setRevokeError] = useState(null);
    const [rotateKeyError, setRotateKeyError] = useState(null);

    const fetchCertificates = useCallback(
        async ({ showLoading = true } = {}) => {
            try {
                if (showLoading) {
                    setLoading(true);
                }
                setError(null);
                const response = await fetch(certsUrl({ expiresWithin }));

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();
                setCertificates(data);
            } catch (err) {
                setError(err.message);
                console.error("Error fetching certificates:", err);
            } finally {
                if (showLoading) {
                    setLoading(false);
                }
            }
        },
        [expiresWithin]
    );

    useEffect(() => {
        setExpandedRows({});
        setChildCerts({});
        fetchCertificates();
    }, [fetchCertificates]);

    const fetchChildCertificates = async (issuerId, { force = false } = {}) => {
        if (!force && childCerts[issuerId]) {
            return;
        }

        try {
            setLoadingChildren((prev) => ({ ...prev, [issuerId]: true }));
            const response = await fetch(certsUrl({ signedBy: issuerId, expiresWithin }));

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            setChildCerts((prev) => ({ ...prev, [issuerId]: data }));
        } catch (err) {
            console.error("Error fetching child certificates:", err);
        } finally {
            setLoadingChildren((prev) => ({ ...prev, [issuerId]: false }));
        }
    };

    const refreshCertificates = async () => {
        await fetchCertificates({ showLoading: false });
        const issuerIds = Object.keys(childCerts);
        await Promise.all(
            issuerIds.map((issuerId) => fetchChildCertificates(issuerId, { force: true }))
        );
    };

    const formatDate = (dateString) => {
        if (!dateString) return "N/A";
        const date = new Date(dateString);
        return date.toLocaleString();
    };

    const formatRelativeTime = (dateString) => {
        if (!dateString) return "N/A";
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = date - now;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffDays < 0) return "Expired";
        if (diffDays === 0) return "Today";
        if (diffDays === 1) return "Tomorrow";
        return `${diffDays} days`;
    };

    const getExpirationTagType = (expirationDate) => {
        if (!expirationDate) return "gray";
        const date = new Date(expirationDate);
        const now = new Date();
        const diffDays = Math.floor((date - now) / (1000 * 60 * 60 * 24));

        if (diffDays < 0) return "red";
        if (diffDays <= 7) return "red";
        if (diffDays <= 14) return "yellow";
        return "green";
    };

    const renderIcon = (isCA) => {
        return isCA ? (
            <Certificate size={20} style={{ marginRight: "0.5rem" }} />
        ) : (
            <DocumentSigned size={20} style={{ marginRight: "0.5rem" }} />
        );
    };

    const handleRotate = async (cert) => {
        try {
            setActionBusy(true);
            setActionNotice(null);
            await postCertAction(cert.id, "rotate");
            setActionNotice({
                kind: "success",
                title: "Certificate rotation requested",
                subtitle: cert.label || cert.id,
            });
            await refreshCertificates();
        } catch (err) {
            setActionNotice({
                kind: "error",
                title:
                    err.status === 409 ? "Cannot rotate certificate" : "Error rotating certificate",
                subtitle: err.message,
            });
        } finally {
            setActionBusy(false);
        }
    };

    const openRotateKeyModal = (cert) => {
        if (!cert.isca) {
            return;
        }
        setCertToRotateKey(cert);
        setRotateKeyError(null);
    };

    const handleRotateKey = async () => {
        if (!certToRotateKey?.isca) {
            return;
        }
        try {
            setActionBusy(true);
            setRotateKeyError(null);
            await postCertAction(certToRotateKey.id, "rotate", { rotateKey: "true" });
            setActionNotice({
                kind: "success",
                title: "CA key rotation requested",
                subtitle: certToRotateKey.label || certToRotateKey.id,
            });
            setCertToRotateKey(null);
            await refreshCertificates();
        } catch (err) {
            setRotateKeyError(err.message);
        } finally {
            setActionBusy(false);
        }
    };

    const openRevokeModal = (cert) => {
        if (cert.isca) {
            return;
        }
        setCertToRevoke(cert);
        setRevokeError(null);
    };

    const handleRevoke = async () => {
        if (!certToRevoke || certToRevoke.isca) {
            return;
        }
        try {
            setActionBusy(true);
            setRevokeError(null);
            await postCertAction(certToRevoke.id, "revoke");
            setActionNotice({
                kind: "success",
                title: "Certificate revoked",
                subtitle: certToRevoke.label || certToRevoke.id,
            });
            setCertToRevoke(null);
            await refreshCertificates();
        } catch (err) {
            setRevokeError(err.message);
        } finally {
            setActionBusy(false);
        }
    };

    const renderCertActions = (cert) => (
        <OverflowMenu size="sm" flipped>
            <OverflowMenuItem
                itemText="Rotate"
                disabled={actionBusy}
                onClick={() => handleRotate(cert)}
            />
            {cert.isca && (
                <OverflowMenuItem
                    itemText="Rotate CA key"
                    disabled={actionBusy}
                    onClick={() => openRotateKeyModal(cert)}
                />
            )}
            <OverflowMenuItem
                itemText="Revoke"
                isDelete
                disabled={cert.isca || actionBusy}
                requireTitle={cert.isca}
                title={cert.isca ? CA_REVOKE_UNAVAILABLE : undefined}
                onClick={() => openRevokeModal(cert)}
            />
        </OverflowMenu>
    );

    const headers = [
        { key: "type", header: "Type" },
        { key: "label", header: "Label" },
        { key: "expiration", header: "Expiration" },
        { key: "renewaltime", header: "Renewal Time" },
        { key: "rotationordinal", header: "Gen" },
        { key: "actions", header: "" },
    ];

    // Recursive component to render certificate rows at any depth
    const CertificateRow = ({ cert, level = 0 }) => {
        const isExpanded = expandedRows[cert.id] || false;
        const children = childCerts[cert.id] || [];
        const isLoadingChildren = loadingChildren[cert.id] || false;

        const handleExpand = () => {
            setExpandedRows((prev) => ({
                ...prev,
                [cert.id]: !prev[cert.id],
            }));

            if (!childCerts[cert.id] && !isExpanded) {
                fetchChildCertificates(cert.id);
            }
        };

        const indentStyle = {
            paddingLeft: `${level * 2}rem`,
        };

        if (cert.isca) {
            // CA certificates - use TableExpandRow
            return (
                <React.Fragment key={cert.id}>
                    <TableExpandRow isExpanded={isExpanded} onExpand={handleExpand}>
                        <TableCell>
                            <div style={{ display: "flex", alignItems: "center", ...indentStyle }}>
                                {renderIcon(true)}
                                Certificate Authority
                            </div>
                        </TableCell>
                        <TableCell>{cert.label}</TableCell>
                        <TableCell>
                            <Tag type={getExpirationTagType(cert.expiration)}>
                                {formatRelativeTime(cert.expiration)}
                            </Tag>
                        </TableCell>
                        <TableCell>{formatDate(cert.renewaltime)}</TableCell>
                        <TableCell>{cert.rotationordinal}</TableCell>
                        <TableCell>{renderCertActions(cert)}</TableCell>
                    </TableExpandRow>
                    {isExpanded && isLoadingChildren && (
                        <TableExpandedRow colSpan={headers.length + 1}>
                            <div style={{ padding: "1rem" }}>
                                <Loading description="Loading signed certificates..." small />
                            </div>
                        </TableExpandedRow>
                    )}
                    {isExpanded && !isLoadingChildren && children.length === 0 && (
                        <TableExpandedRow colSpan={headers.length + 1}>
                            <div style={{ padding: "1rem", color: "var(--cds-text-secondary)" }}>
                                No certificates signed by this CA
                            </div>
                        </TableExpandedRow>
                    )}
                    {isExpanded &&
                        !isLoadingChildren &&
                        children.length > 0 &&
                        children.map((childCert) => (
                            <CertificateRow key={childCert.id} cert={childCert} level={level + 1} />
                        ))}
                </React.Fragment>
            );
        } else {
            // Non-CA certificates - always need empty cell for expand column
            return (
                <TableRow key={cert.id}>
                    <TableCell />
                    <TableCell>
                        <div style={{ display: "flex", alignItems: "center", ...indentStyle }}>
                            {renderIcon(false)}
                            Certificate
                        </div>
                    </TableCell>
                    <TableCell>{cert.label}</TableCell>
                    <TableCell>
                        <Tag type={getExpirationTagType(cert.expiration)}>
                            {formatRelativeTime(cert.expiration)}
                        </Tag>
                    </TableCell>
                    <TableCell>{formatDate(cert.renewaltime)}</TableCell>
                    <TableCell>{cert.rotationordinal}</TableCell>
                    <TableCell>{renderCertActions(cert)}</TableCell>
                </TableRow>
            );
        }
    };

    return (
        <div className="page-container">
            <Breadcrumb>
                <BreadcrumbItem href="/">Dashboard</BreadcrumbItem>
                <BreadcrumbItem href="/tls" isCurrentPage>
                    TLS
                </BreadcrumbItem>
            </Breadcrumb>

            <div className="page-header">
                <h1>TLS Certificates</h1>
                <p>
                    Manage Transport Layer Security certificates and certificate authorities. Click
                    on CAs to view signed certificates.
                </p>
            </div>

            <div style={{ marginBottom: "1rem", maxWidth: "300px" }}>
                <Select
                    id="tls-expires-within"
                    labelText="Expiration"
                    value={expiresWithin}
                    onChange={(e) => setExpiresWithin(e.target.value)}
                >
                    <SelectItem value="" text="All certificates" />
                    <SelectItem value="7" text="Expiring within 7 days" />
                    <SelectItem value="14" text="Expiring within 14 days" />
                    <SelectItem value="30" text="Expiring within 30 days" />
                </Select>
            </div>

            {loading && <Loading description="Loading certificates..." withOverlay={false} />}

            {error && (
                <InlineNotification
                    kind="error"
                    title="Error loading certificates"
                    subtitle={error}
                    onCloseButtonClick={() => setError(null)}
                    style={{ marginBottom: "1rem" }}
                />
            )}

            {actionNotice && (
                <InlineNotification
                    kind={actionNotice.kind}
                    title={actionNotice.title}
                    subtitle={actionNotice.subtitle}
                    onCloseButtonClick={() => setActionNotice(null)}
                    style={{ marginBottom: "1rem" }}
                />
            )}

            {!loading && !error && certificates.length === 0 && (
                <InlineNotification
                    kind="info"
                    title="No certificates found"
                    subtitle={
                        expiresWithin
                            ? "No certificates expire within the selected window."
                            : "There are currently no certificates configured."
                    }
                    hideCloseButton
                    style={{ marginBottom: "1rem" }}
                />
            )}

            {!loading && !error && certificates.length > 0 && (
                <TableContainer
                    title="Certificates"
                    description="Hierarchical view of certificate authorities and certificates"
                >
                    <Table>
                        <TableHead>
                            <TableRow>
                                <TableExpandHeader enableToggle />
                                {headers.map((header) => (
                                    <TableHeader key={header.key}>{header.header}</TableHeader>
                                ))}
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {certificates.map((cert) => (
                                <CertificateRow key={cert.id} cert={cert} level={0} />
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            )}

            <Modal
                open={Boolean(certToRotateKey)}
                danger
                modalHeading="Rotate CA key"
                primaryButtonText="Rotate key"
                secondaryButtonText="Cancel"
                onRequestClose={() => {
                    setCertToRotateKey(null);
                    setRotateKeyError(null);
                }}
                onRequestSubmit={handleRotateKey}
                primaryButtonDisabled={actionBusy || !certToRotateKey?.isca}
            >
                {rotateKeyError && (
                    <InlineNotification
                        kind="error"
                        title="Cannot rotate CA key"
                        subtitle={rotateKeyError}
                        onCloseButtonClick={() => setRotateKeyError(null)}
                        style={{ marginBottom: "1rem" }}
                    />
                )}

                <p>
                    Rotate the key for{" "}
                    <strong>{certToRotateKey?.label || certToRotateKey?.id}</strong>? This issues a
                    new CA and Issuer, re-issues every signed certificate, and keeps dual trust
                    until cutover. This cannot be undone.
                </p>
            </Modal>

            <Modal
                open={Boolean(certToRevoke)}
                danger
                modalHeading="Revoke certificate"
                primaryButtonText="Revoke"
                secondaryButtonText="Cancel"
                onRequestClose={() => {
                    setCertToRevoke(null);
                    setRevokeError(null);
                }}
                onRequestSubmit={handleRevoke}
                primaryButtonDisabled={actionBusy || !certToRevoke || certToRevoke.isca}
            >
                {revokeError && (
                    <InlineNotification
                        kind="error"
                        title="Cannot revoke certificate"
                        subtitle={revokeError}
                        onCloseButtonClick={() => setRevokeError(null)}
                        style={{ marginBottom: "1rem" }}
                    />
                )}

                <p>
                    Are you sure you want to revoke{" "}
                    <strong>{certToRevoke?.label || certToRevoke?.id}</strong>? This action cannot
                    be undone.
                </p>
            </Modal>
        </div>
    );
};

export default TLS;

// Made with Bob
