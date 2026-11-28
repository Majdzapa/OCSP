import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
    Container,
    Paper,
    Title,
    Text,
    Group,
    Stack,
    Button,
    Badge,
    Table,
    ActionIcon,
    Modal,
    Select,
    Textarea,
    PasswordInput,
    Switch,
    Alert,
    Loader,
    Tooltip,
    Code,
    Box,
    SimpleGrid,
    CopyButton,
    FileButton,
    Divider,
    ThemeIcon,
} from '@mantine/core';
import {
    IconArrowLeft,
    IconKey,
    IconCpu,
    IconCertificate,
    IconFileCertificate,
    IconRefresh,
    IconPlus,
    IconCheck,
    IconAlertCircle,
    IconLock,
    IconLockOpen,
    IconEye,
    IconTrash,
    IconCopy,
    IconDownload,
    IconUpload,
    IconShieldCheck,
    IconPlayerPlay,
    IconPlayerPause,
    IconDatabaseImport,
    IconHierarchy2,
    IconLink,
    IconUnlink,
} from '@tabler/icons-react';
import {
    getSignerById,
    getOcspKeys,
    getCryptoDevices,
    generateSignerCsr,
    attachKeyToSigner,
    linkTokenToSigner,
    unlinkTokenFromSigner,
    importSignerKeyCertificate,
    activateSignerKey,
    deleteSignerKey,
    activateSigner,
    deactivateSigner,
    activateCryptoDevice,
    deactivateCryptoDevice,
    syncCryptoDeviceKeys,
} from '../api/client';
import { useAuth } from '../context/AuthContext';

function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function KeyStatusBadge({ status }) {
    if (status === 'ACTIVE') return <Badge color="green" variant="filled" size="sm">ACTIVE</Badge>;
    if (status === 'READY') return <Badge color="teal" variant="light" size="sm">READY</Badge>;
    if (status === 'CSR_PENDING') return <Badge color="cyan" variant="outline" size="sm">CSR PENDING</Badge>;
    if (status === 'INACTIVE') return <Badge color="gray" variant="light" size="sm">STANDBY</Badge>;
    if (status === 'EXPIRED') return <Badge color="red" variant="filled" size="sm">EXPIRED</Badge>;
    return <Badge color="orange" variant="outline" size="sm">UNAVAILABLE</Badge>;
}

function SignerStatusBadge({ status }) {
    if (status === 'ACTIVE') return <Badge color="green" variant="filled" size="md">ACTIVE</Badge>;
    if (status === 'TOKEN_LOCKED') return <Badge color="orange" variant="filled" size="md">TOKEN DEACTIVATED</Badge>;
    if (status === 'CERT_IMPORTED') return <Badge color="teal" variant="light" size="md">CERT IMPORTED</Badge>;
    if (status === 'CSR_GENERATED') return <Badge color="cyan" variant="light" size="md">CSR READY</Badge>;
    if (status === 'EXPIRED') return <Badge color="red" variant="filled" size="md">EXPIRED</Badge>;
    return <Badge color="gray" variant="light" size="md">{status || 'DRAFT'}</Badge>;
}

function shortLabel(text, max = 22) {
    if (!text) return '—';
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * Interactive SVG Architecture Graph:
 *   Column 1: OCSP Signer (Key Binding)
 *   Column 2: Bound HSM Crypto Tokens (PRIMARY / FAILOVER, ACTIVE / DEACTIVATED)
 *   Column 3: Cryptographic Keys (ocsp_keys: ACTIVE / READY / CSR_PENDING / UNAVAILABLE)
 *   Column 4: X.509 Certificates (VALID / EXPIRED / AWAITING CERT)
 */
function SignerArchitectureGraph({ signer, selectedKeyId, onSelectKey, onSelectToken }) {
    const tokens = signer.tokens || [];
    const keys = signer.keys || (signer.key ? [signer.key] : []);

    const colX = { signer: 24, token: 300, key: 585, cert: 875 };
    const boxW = { signer: 210, token: 215, key: 220, cert: 215 };
    const nodeH = 74;
    const gapY = 22;

    const maxRows = Math.max(1, tokens.length, keys.length);
    const totalHeight = Math.max(260, 68 + maxRows * (nodeH + gapY) + 20);
    const viewW = 1115;

    const centerY = (count, idx) => {
        const blockH = count * nodeH + (count - 1) * gapY;
        const startY = Math.max(56, (totalHeight - blockH) / 2);
        return startY + idx * (nodeH + gapY);
    };

    const signerY = centerY(1, 0);
    const tokenPositions = tokens.map((t, i) => ({
        token: t,
        x: colX.token,
        y: centerY(tokens.length, i),
    }));
    const keyPositions = keys.map((k, i) => ({
        key: k,
        x: colX.key,
        y: centerY(keys.length, i),
    }));

    const bezier = (x1, y1, x2, y2) => {
        const mx = (x1 + x2) / 2;
        return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
    };

    const statusStroke = (status) => {
        if (status === 'ACTIVE') return '#22c55e';
        if (status === 'READY') return '#14b8a6';
        if (status === 'CSR_PENDING') return '#38bdf8';
        if (status === 'EXPIRED') return '#ef4444';
        if (status === 'UNAVAILABLE' || status === 'TOKEN_LOCKED') return '#f97316';
        return '#64748b';
    };

    const signerBorder = statusStroke(signer.status);

    return (
        <Box style={{ width: '100%', overflowX: 'auto' }}>
            <svg
                viewBox={`0 0 ${viewW} ${totalHeight}`}
                style={{ width: '100%', minWidth: 880, height: 'auto', display: 'block' }}
            >
                <defs>
                    <filter id="glowGreen" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="3" result="blur" />
                        <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                        </feMerge>
                    </filter>
                    <marker id="arrowGreen" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#22c55e" />
                    </marker>
                    <marker id="arrowTeal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#14b8a6" />
                    </marker>
                    <marker id="arrowCyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
                    </marker>
                    <marker id="arrowOrange" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#f97316" />
                    </marker>
                    <marker id="arrowMuted" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
                    </marker>
                </defs>

                {/* Column Header Labels */}
                <text x={colX.signer + boxW.signer / 2} y={28} textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="700" letterSpacing="1">
                    1. OCSP SIGNER (BINDING)
                </text>
                <text x={colX.token + boxW.token / 2} y={28} textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="700" letterSpacing="1">
                    2. HSM CRYPTO TOKENS ({tokens.length})
                </text>
                <text x={colX.key + boxW.key / 2} y={28} textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="700" letterSpacing="1">
                    3. KEYS IN TOKEN ({keys.length})
                </text>
                <text x={colX.cert + boxW.cert / 2} y={28} textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="700" letterSpacing="1">
                    4. X.509 CERTIFICATES
                </text>

                {/* Edges: Signer -> Tokens */}
                {tokenPositions.map(({ token, x, y }) => {
                    const isUp = token.activationState === 'ACTIVE';
                    const isPrimary = token.role === 'PRIMARY';
                    const stroke = isUp ? (isPrimary ? '#22c55e' : '#38bdf8') : '#f97316';
                    const marker = isUp ? (isPrimary ? 'url(#arrowGreen)' : 'url(#arrowCyan)') : 'url(#arrowOrange)';
                    return (
                        <path
                            key={`e-s-t-${token.deviceId}`}
                            d={bezier(colX.signer + boxW.signer, signerY + nodeH / 2, x, y + nodeH / 2)}
                            fill="none"
                            stroke={stroke}
                            strokeWidth={isPrimary && isUp ? 2.6 : 1.6}
                            strokeDasharray={isPrimary && isUp ? undefined : '6 4'}
                            markerEnd={marker}
                            opacity={isUp ? 0.95 : 0.65}
                        />
                    );
                })}

                {/* Edges: Tokens -> Keys */}
                {keyPositions.map(({ key, x, y }) => {
                    const parentToken = tokenPositions.find((tp) => tp.token.deviceId === key.tokenDeviceCode) || tokenPositions[0];
                    if (!parentToken) return null;
                    const stroke = statusStroke(key.status);
                    const isActive = key.status === 'ACTIVE';
                    const marker = isActive
                        ? 'url(#arrowGreen)'
                        : key.status === 'READY'
                            ? 'url(#arrowTeal)'
                            : key.status === 'CSR_PENDING'
                                ? 'url(#arrowCyan)'
                                : key.status === 'UNAVAILABLE'
                                    ? 'url(#arrowOrange)'
                                    : 'url(#arrowMuted)';
                    return (
                        <path
                            key={`e-t-k-${key.id}`}
                            d={bezier(parentToken.x + boxW.token, parentToken.y + nodeH / 2, x, y + nodeH / 2)}
                            fill="none"
                            stroke={stroke}
                            strokeWidth={isActive ? 2.6 : 1.6}
                            strokeDasharray={isActive ? undefined : '5 4'}
                            markerEnd={marker}
                            opacity={key.tokenActive ? 0.95 : 0.55}
                        />
                    );
                })}

                {/* Edges: Keys -> Certificates */}
                {keyPositions.map(({ key, x, y }) => {
                    const isActive = key.status === 'ACTIVE';
                    const stroke = key.hasCertificate
                        ? (isActive ? '#22c55e' : (key.status === 'EXPIRED' ? '#ef4444' : '#14b8a6'))
                        : (key.hasCsr ? '#38bdf8' : '#475569');
                    const marker = key.hasCertificate
                        ? (isActive ? 'url(#arrowGreen)' : 'url(#arrowTeal)')
                        : (key.hasCsr ? 'url(#arrowCyan)' : 'url(#arrowMuted)');
                    return (
                        <path
                            key={`e-k-c-${key.id}`}
                            d={bezier(x + boxW.key, y + nodeH / 2, colX.cert, y + nodeH / 2)}
                            fill="none"
                            stroke={stroke}
                            strokeWidth={isActive ? 2.6 : 1.6}
                            strokeDasharray={key.hasCertificate && isActive ? undefined : '5 4'}
                            markerEnd={marker}
                            opacity={key.tokenActive ? 0.95 : 0.55}
                        />
                    );
                })}

                {/* Column 1 Node: Signer */}
                <g transform={`translate(${colX.signer}, ${signerY})`}>
                    <rect
                        width={boxW.signer}
                        height={nodeH}
                        rx="10"
                        fill="#0f172a"
                        stroke={signerBorder}
                        strokeWidth="2.2"
                        filter={signer.status === 'ACTIVE' ? 'url(#glowGreen)' : undefined}
                    />
                    <rect x="0" y="0" width="6" height={nodeH} rx="3" fill={signerBorder} />
                    <text x="16" y="22" fill="#f8fafc" fontSize="13" fontWeight="700">
                        {shortLabel(signer.name, 22)}
                    </text>
                    <text x="16" y="40" fill={signerBorder} fontSize="10" fontWeight="700">
                        {signer.status} · ID #{signer.id}
                    </text>
                    <text x="16" y="58" fill="#94a3b8" fontSize="10" fontFamily="monospace">
                        {signer.keyAlgorithm} {signer.keySize} · {shortLabel(signer.signatureAlgorithm, 16)}
                    </text>
                </g>

                {/* Column 2 Nodes: HSM Tokens */}
                {tokenPositions.map(({ token, x, y }) => {
                    const isUp = token.activationState === 'ACTIVE';
                    const border = isUp ? '#22c55e' : '#f97316';
                    const tokenKeyCount = keys.filter((k) => k.tokenDeviceCode === token.deviceId).length;
                    return (
                        <g
                            key={`n-t-${token.deviceId}`}
                            transform={`translate(${x}, ${y})`}
                            style={{ cursor: 'pointer' }}
                            onClick={() => onSelectToken && onSelectToken(token)}
                        >
                            <rect
                                width={boxW.token}
                                height={nodeH}
                                rx="10"
                                fill={isUp ? '#0b1f1a' : '#1f140d'}
                                stroke={border}
                                strokeWidth={token.role === 'PRIMARY' ? 2.2 : 1.5}
                            />
                            <circle cx="18" cy="20" r="5" fill={border} />
                            <text x="30" y="24" fill="#f8fafc" fontSize="12" fontWeight="700" fontFamily="monospace">
                                {shortLabel(token.deviceId, 19)}
                            </text>
                            <text x="16" y="42" fill={border} fontSize="10" fontWeight="700">
                                {token.role} · {isUp ? 'ACTIVE (UNLOCKED)' : 'DEACTIVATED (LOCKED)'}
                            </text>
                            <text x="16" y="59" fill="#94a3b8" fontSize="10">
                                {shortLabel(token.tokenLabel || `slot ${token.slotId ?? '?'}`, 18)} · {tokenKeyCount} key{tokenKeyCount === 1 ? '' : 's'}
                            </text>
                        </g>
                    );
                })}

                {/* Column 3 Nodes: Keys */}
                {keyPositions.length === 0 ? (
                    <g transform={`translate(${colX.key}, ${signerY})`}>
                        <rect width={boxW.key} height={nodeH} rx="10" fill="#0f172a" stroke="#475569" strokeDasharray="5 4" strokeWidth="1.5" />
                        <text x={boxW.key / 2} y="34" textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="600">
                            No Keys Generated Yet
                        </text>
                        <text x={boxW.key / 2} y="52" textAnchor="middle" fill="#64748b" fontSize="10">
                            Click &quot;Generate Next Key &amp; CSR&quot;
                        </text>
                    </g>
                ) : (
                    keyPositions.map(({ key, x, y }) => {
                        const border = statusStroke(key.status);
                        const isSelected = selectedKeyId === key.id;
                        const isActive = key.status === 'ACTIVE';
                        return (
                            <g
                                key={`n-k-${key.id}`}
                                transform={`translate(${x}, ${y})`}
                                style={{ cursor: 'pointer', opacity: key.tokenActive ? 1 : 0.65 }}
                                onClick={() => onSelectKey && onSelectKey(key)}
                            >
                                <rect
                                    width={boxW.key}
                                    height={nodeH}
                                    rx="10"
                                    fill={isSelected ? '#1e1b4b' : (isActive ? '#0b1f1a' : '#0f172a')}
                                    stroke={isSelected ? '#818cf8' : border}
                                    strokeWidth={isSelected || isActive ? 2.4 : 1.5}
                                    filter={isActive ? 'url(#glowGreen)' : undefined}
                                />
                                <text x="14" y="22" fill="#f8fafc" fontSize="11.5" fontWeight="700" fontFamily="monospace">
                                    #{key.id} · {shortLabel(key.keyLabel, 18)}
                                </text>
                                <text x="14" y="40" fill={border} fontSize="10" fontWeight="700">
                                    {key.status}{!key.tokenActive ? ' (TOKEN LOCKED)' : ''}
                                </text>
                                <text x="14" y="58" fill="#94a3b8" fontSize="10">
                                    {key.keyAlgorithm} {key.keySize} · SKI {shortLabel(key.publicKeySha1, 12)}
                                </text>
                            </g>
                        );
                    })
                )}

                {/* Column 4 Nodes: X.509 Certificates */}
                {keyPositions.length === 0 ? (
                    <g transform={`translate(${colX.cert}, ${signerY})`}>
                        <rect width={boxW.cert} height={nodeH} rx="10" fill="#0f172a" stroke="#475569" strokeDasharray="5 4" strokeWidth="1.5" />
                        <text x={boxW.cert / 2} y="41" textAnchor="middle" fill="#64748b" fontSize="11">
                            No Certificate
                        </text>
                    </g>
                ) : (
                    keyPositions.map(({ key, y }) => {
                        const isActive = key.status === 'ACTIVE';
                        const border = key.hasCertificate
                            ? (key.status === 'EXPIRED' ? '#ef4444' : (isActive ? '#22c55e' : '#14b8a6'))
                            : (key.hasCsr ? '#38bdf8' : '#475569');
                        return (
                            <g
                                key={`n-c-${key.id}`}
                                transform={`translate(${colX.cert}, ${y})`}
                                style={{ cursor: 'pointer', opacity: key.tokenActive ? 1 : 0.7 }}
                                onClick={() => onSelectKey && onSelectKey(key)}
                            >
                                <rect
                                    width={boxW.cert}
                                    height={nodeH}
                                    rx="10"
                                    fill={key.hasCertificate ? '#0f172a' : '#0b1120'}
                                    stroke={border}
                                    strokeWidth={isActive ? 2.2 : 1.4}
                                    strokeDasharray={key.hasCertificate ? undefined : '5 4'}
                                />
                                {key.hasCertificate ? (
                                    <>
                                        <text x="14" y="22" fill="#f8fafc" fontSize="11" fontWeight="700">
                                            X.509 OCSP Signer Cert
                                        </text>
                                        <text x="14" y="40" fill={border} fontSize="10" fontWeight="700">
                                            {key.status === 'EXPIRED'
                                                ? 'EXPIRED'
                                                : `VALID (${key.certDaysUntilExpiry ?? '?'}d left)`}
                                        </text>
                                        <text x="14" y="58" fill="#94a3b8" fontSize="9.5" fontFamily="monospace">
                                            SN: {shortLabel(key.certSerialNumber, 20)}
                                        </text>
                                    </>
                                ) : key.hasCsr ? (
                                    <>
                                        <text x="14" y="28" fill="#38bdf8" fontSize="11" fontWeight="700">
                                            PKCS#10 CSR Ready
                                        </text>
                                        <text x="14" y="48" fill="#94a3b8" fontSize="10">
                                            Sign in CA &amp; Import Cert
                                        </text>
                                    </>
                                ) : (
                                    <text x={boxW.cert / 2} y="41" textAnchor="middle" fill="#64748b" fontSize="11">
                                        No CSR / Cert
                                    </text>
                                )}
                            </g>
                        );
                    })
                )}
            </svg>
        </Box>
    );
}

export const SignerDetailPage = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const { user } = useAuth();
    const roleNames = (user?.roles ?? []).map((r) => (typeof r === 'string' ? r : r?.authority ?? ''));
    const isAdmin = roleNames.includes('ROLE_ADMIN');
    const canOperate = isAdmin || roleNames.includes('ROLE_AGENT');

    const [signer, setSigner] = useState(null);
    const [allKeys, setAllKeys] = useState([]);
    const [allDevices, setAllDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [syncingDeviceId, setSyncingDeviceId] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    const [selectedKeyId, setSelectedKeyId] = useState(null);

    // Modals
    const [attachKeyModalOpen, setAttachKeyModalOpen] = useState(false);
    const [attachKeyId, setAttachKeyId] = useState('');
    const [linkTokenModalOpen, setLinkTokenModalOpen] = useState(false);
    const [linkTokenDeviceId, setLinkTokenDeviceId] = useState('');
    const [viewKeyModal, setViewKeyModal] = useState(null);
    const [csrModalData, setCsrModalData] = useState(null);
    const [certModalKey, setCertModalKey] = useState(null);
    const [certPemInput, setCertPemInput] = useState('');
    const [certActivateNow, setCertActivateNow] = useState(false);
    const [certLoading, setCertLoading] = useState(false);
    const [unlockDeviceId, setUnlockDeviceId] = useState(null);
    const [unlockPin, setUnlockPin] = useState('');

    const fetchSigner = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const [data, keysList, devicesList] = await Promise.all([
                getSignerById(id),
                getOcspKeys().catch(() => []),
                getCryptoDevices().catch(() => []),
            ]);
            setSigner(data);
            setAllKeys(keysList || []);
            setAllDevices(devicesList || []);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to load OCSP Signer');
        } finally {
            setLoading(false);
        }
    }, [id]);

    useEffect(() => {
        fetchSigner();
    }, [fetchSigner]);

    const signerKeys = useMemo(
        () => (signer ? (signer.keys || (signer.key ? [signer.key] : [])) : []),
        [signer]
    );
    const selectedKey = useMemo(
        () => signerKeys.find((k) => k.id === selectedKeyId) || null,
        [signerKeys, selectedKeyId]
    );
    const anyTokenActive = useMemo(
        () => Boolean(signer && (signer.tokens || []).some((t) => t.activationState === 'ACTIVE')),
        [signer]
    );

    const handleGenerateNextKeyCsr = async () => {
        if (!signer) return;
        try {
            setSaving(true);
            setError(null);
            const res = await generateSignerCsr(signer.id, { reuseExistingKey: false });
            setCsrModalData(res);
            setSuccess(`Generated new key '${res.keyLabel}' (Key #${res.keyId}) & CSR on Token '${res.tokenDeviceId}'.`);
            await fetchSigner();
            if (res.keyId) setSelectedKeyId(res.keyId);
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to generate key & CSR');
        } finally {
            setSaving(false);
        }
    };

    const handleImportKeyCert = async (e) => {
        e.preventDefault();
        if (!signer || !certModalKey || !certPemInput.trim()) return;
        try {
            setCertLoading(true);
            setError(null);
            await importSignerKeyCertificate(signer.id, certModalKey.id, {
                certificatePem: certPemInput.trim(),
                signatureAlgorithm: signer.signatureAlgorithm,
                activateImmediately: isAdmin ? certActivateNow : false,
            });
            setSuccess(`Imported X.509 certificate onto Key #${certModalKey.id} ('${certModalKey.keyLabel}')${isAdmin && certActivateNow ? ' and activated' : ' (status: READY)'}.`);
            setCertModalKey(null);
            setCertPemInput('');
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to import certificate');
        } finally {
            setCertLoading(false);
        }
    };

    const handleActivateKey = async (keyObj) => {
        try {
            setSaving(true);
            setError(null);
            await activateSignerKey(signer.id, keyObj.id);
            setSuccess(`Activated Key #${keyObj.id} ('${keyObj.keyLabel}') — any previously active key on this signer/token was deactivated.`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to activate key');
        } finally {
            setSaving(false);
        }
    };

    const handleDeleteKey = async (keyObj) => {
        if (!window.confirm(`Delete inactive key '${keyObj.keyLabel}' (Key #${keyObj.id})?`)) return;
        try {
            setSaving(true);
            setError(null);
            await deleteSignerKey(signer.id, keyObj.id);
            if (selectedKeyId === keyObj.id) setSelectedKeyId(null);
            setSuccess(`Deleted inactive Key #${keyObj.id} ('${keyObj.keyLabel}').`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to delete key');
        } finally {
            setSaving(false);
        }
    };

    const handleToggleSignerActive = async () => {
        if (!signer) return;
        try {
            setSaving(true);
            setError(null);
            if (signer.active) {
                await deactivateSigner(signer.id);
                setSuccess(`Signer '${signer.name}' deactivated.`);
            } else {
                await activateSigner(signer.id);
                setSuccess(`Signer '${signer.name}' activated.`);
            }
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to toggle signer');
        } finally {
            setSaving(false);
        }
    };

    const handleUnlockToken = async (e) => {
        e.preventDefault();
        if (!unlockDeviceId || !unlockPin) return;
        const pin = unlockPin;
        setUnlockPin('');
        try {
            setSaving(true);
            setError(null);
            await activateCryptoDevice(unlockDeviceId, pin);
            setUnlockDeviceId(null);
            setSuccess(`Crypto Token '${unlockDeviceId}' activated (unlocked via C_Login).`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to unlock Crypto Token');
        } finally {
            setSaving(false);
        }
    };

    const handleLockToken = async (deviceId) => {
        if (!window.confirm(`Deactivate (lock) Crypto Token '${deviceId}'? All keys inside it will become UNAVAILABLE.`)) return;
        try {
            setSaving(true);
            setError(null);
            await deactivateCryptoDevice(deviceId);
            setSuccess(`Crypto Token '${deviceId}' deactivated (LOCKED). All keys inside it are now UNAVAILABLE.`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to deactivate Crypto Token');
        } finally {
            setSaving(false);
        }
    };

    const handleSyncTokenKeys = async (deviceId) => {
        try {
            setSyncingDeviceId(deviceId);
            setError(null);
            const synced = await syncCryptoDeviceKeys(deviceId);
            setSuccess(`Synchronized ${synced.length} key(s) from HSM Token '${deviceId}'.`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to sync keys');
        } finally {
            setSyncingDeviceId(null);
        }
    };

    const availableKeysToAttach = useMemo(() => {
        if (!signer) return [];
        const ownedIds = new Set(signerKeys.map((k) => k.id));
        return allKeys
            .filter((k) => !ownedIds.has(k.id) && !(k.boundSignerId && k.boundSignerId !== signer.id && k.active))
            .map((k) => ({
                value: String(k.id),
                label: `#${k.id} · ${k.keyLabel} (${k.keyAlgorithm} ${k.keySize} · Token: ${k.tokenDeviceCode || 'HSM'} · ${k.status}${k.boundSignerName ? ' · currently on ' + k.boundSignerName : ''})`,
            }));
    }, [allKeys, signer, signerKeys]);

    const availableTokensToLink = useMemo(() => {
        if (!signer) return [];
        const boundIds = new Set((signer.tokens || []).map((t) => t.deviceId));
        return allDevices
            .filter((d) => !boundIds.has(d.deviceId))
            .map((d) => ({
                value: d.deviceId,
                label: `${d.deviceId} (${d.providerCode} · ${d.tokenLabel || 'slot ' + d.slotId} · ${d.activationState})`,
            }));
    }, [allDevices, signer]);

    const handleAttachExistingKey = async (e) => {
        e.preventDefault();
        if (!signer || !attachKeyId) return;
        try {
            setSaving(true);
            setError(null);
            await attachKeyToSigner(signer.id, Number(attachKeyId));
            setAttachKeyModalOpen(false);
            setAttachKeyId('');
            setSuccess(`Attached Key #${attachKeyId} to signer '${signer.name}'.`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to attach existing key');
        } finally {
            setSaving(false);
        }
    };

    const handleLinkToken = async (e) => {
        e.preventDefault();
        if (!signer || !linkTokenDeviceId) return;
        try {
            setSaving(true);
            setError(null);
            await linkTokenToSigner(signer.id, linkTokenDeviceId);
            setLinkTokenModalOpen(false);
            setLinkTokenDeviceId('');
            setSuccess(`Linked HSM Token '${linkTokenDeviceId}' to signer '${signer.name}'.`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to link HSM Token');
        } finally {
            setSaving(false);
        }
    };

    const handleUnlinkToken = async (deviceId) => {
        if (!window.confirm(`Unlink HSM Token '${deviceId}' from signer '${signer.name}'?`)) return;
        try {
            setSaving(true);
            setError(null);
            await unlinkTokenFromSigner(signer.id, deviceId);
            setSuccess(`Unlinked HSM Token '${deviceId}' from signer '${signer.name}'.`);
            await fetchSigner();
        } catch (err) {
            setError(err?.response?.data?.error || err?.message || 'Failed to unlink HSM Token');
        } finally {
            setSaving(false);
        }
    };

    if (loading && !signer) {
        return (
            <Container size="xl" py="xl">
                <Group justify="center" p="xl"><Loader size="md" /></Group>
            </Container>
        );
    }

    if (!signer) {
        return (
            <Container size="xl" py="md">
                <Stack gap="md">
                    <Button variant="subtle" leftSection={<IconArrowLeft size={16} />} onClick={() => navigate('/signers')} w="fit-content">
                        Back to OCSP Signers
                    </Button>
                    <Alert color="red" icon={<IconAlertCircle size={18} />} title="Signer Not Found">
                        {error || `OCSP Signer #${id} could not be loaded.`}
                    </Alert>
                </Stack>
            </Container>
        );
    }

    return (
        <Container size="xl" py="md">
            <Stack gap="md">
                {/* Top Breadcrumb + Header */}
                <Group justify="space-between" align="flex-start" wrap="wrap">
                    <Stack gap={6}>
                        <Button
                            variant="subtle"
                            size="compact-sm"
                            leftSection={<IconArrowLeft size={15} />}
                            onClick={() => navigate('/signers')}
                            w="fit-content"
                            px={4}
                        >
                            Back to OCSP Signers
                        </Button>
                        <Group gap="xs" wrap="wrap">
                            <ThemeIcon size={34} radius="md" variant="gradient" gradient={{ from: 'indigo', to: 'teal' }}>
                                <IconHierarchy2 size={20} />
                            </ThemeIcon>
                            <Title order={2} c="white">{signer.name}</Title>
                            <SignerStatusBadge status={signer.status} />
                            <Code>{signer.code}</Code>
                        </Group>
                        <Text size="xs" c="dimmed">
                            Subject DN: <b>{signer.subjectDn}</b> · Policy: <Code>{signer.keyAlgorithm} {signer.keySize}</Code> / <Code>{signer.signatureAlgorithm}</Code>
                        </Text>
                    </Stack>

                    <Group gap="xs" wrap="wrap">
                        <Button variant="default" size="sm" leftSection={<IconRefresh size={15} />} onClick={fetchSigner} loading={loading}>
                            Refresh
                        </Button>
                        {canOperate && (
                            <Button
                                variant="light"
                                color="cyan"
                                size="sm"
                                leftSection={<IconPlus size={15} />}
                                disabled={!anyTokenActive}
                                loading={saving}
                                onClick={handleGenerateNextKeyCsr}
                            >
                                Generate Next Key &amp; CSR
                            </Button>
                        )}
                        {isAdmin && signer.hasCertificate && (
                            <Button
                                size="sm"
                                variant={signer.active ? 'light' : 'filled'}
                                color={signer.active ? 'orange' : 'green'}
                                leftSection={signer.active ? <IconPlayerPause size={15} /> : <IconPlayerPlay size={15} />}
                                disabled={!signer.active && !anyTokenActive}
                                loading={saving}
                                onClick={handleToggleSignerActive}
                            >
                                {signer.active ? 'Deactivate Signer' : 'Activate Signer'}
                            </Button>
                        )}
                    </Group>
                </Group>

                {error && (
                    <Alert icon={<IconAlertCircle size={18} />} title="Error" color="red" withCloseButton onClose={() => setError(null)}>
                        {error}
                    </Alert>
                )}
                {success && (
                    <Alert icon={<IconCheck size={18} />} title="Success" color="teal" withCloseButton onClose={() => setSuccess(null)}>
                        {success}
                    </Alert>
                )}

                {/* ============================================================= */}
                {/* INTERACTIVE ARCHITECTURE GRAPH                                */}
                {/* ============================================================= */}
                <Paper withBorder p="md" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.6)' }}>
                    <Group justify="space-between" mb="sm" wrap="wrap">
                        <Group gap="xs">
                            <IconHierarchy2 size={18} color="#818cf8" />
                            <Text fw={700} size="sm" c="white">Signer Architecture Graph (Live Topology)</Text>
                            <Badge size="xs" color="indigo" variant="light">CLICK NODES TO INSPECT OR ACT</Badge>
                        </Group>
                        <Group gap="sm" wrap="wrap">
                            <Group gap={5}><Box w={10} h={10} style={{ borderRadius: 99, background: '#22c55e' }} /><Text size="11px" c="dimmed">Active Signing Path</Text></Group>
                            <Group gap={5}><Box w={10} h={10} style={{ borderRadius: 99, background: '#14b8a6' }} /><Text size="11px" c="dimmed">Ready (Staged Next Key)</Text></Group>
                            <Group gap={5}><Box w={10} h={10} style={{ borderRadius: 99, background: '#38bdf8' }} /><Text size="11px" c="dimmed">CSR Pending / Failover</Text></Group>
                            <Group gap={5}><Box w={10} h={10} style={{ borderRadius: 99, background: '#f97316' }} /><Text size="11px" c="dimmed">Token Deactivated / Key Unavailable</Text></Group>
                        </Group>
                    </Group>

                    <SignerArchitectureGraph
                        signer={signer}
                        selectedKeyId={selectedKeyId}
                        onSelectKey={(k) => setSelectedKeyId((prev) => (prev === k.id ? null : k.id))}
                        onSelectToken={(t) => {
                            if (!isAdmin) return;
                            if (t.activationState === 'ACTIVE') {
                                handleLockToken(t.deviceId);
                            } else {
                                setUnlockPin('');
                                setUnlockDeviceId(t.deviceId);
                            }
                        }}
                    />

                    {/* Selected Key Contextual Action Bar */}
                    {selectedKey && (
                        <Paper withBorder p="sm" mt="sm" radius="sm" style={{ backgroundColor: 'rgba(30, 27, 75, 0.45)', borderColor: 'rgba(129, 140, 248, 0.45)' }}>
                            <Group justify="space-between" wrap="wrap" gap="xs">
                                <Group gap="xs">
                                    <KeyStatusBadge status={selectedKey.status} />
                                    <Text size="xs" fw={700} c="white">Selected Key #{selectedKey.id}:</Text>
                                    <Code fz={11}>{selectedKey.keyLabel}</Code>
                                    <Badge size="xs" color="cyan" variant="light">{selectedKey.keyAlgorithm} {selectedKey.keySize}</Badge>
                                    <Text size="xs" c="dimmed">Token: <Code fz={11}>{selectedKey.tokenDeviceCode || 'HSM'}</Code></Text>
                                </Group>
                                <Group gap="xs">
                                    <Button size="compact-xs" variant="light" color="cyan" leftSection={<IconEye size={13} />} onClick={() => setViewKeyModal(selectedKey)}>
                                        Public Key
                                    </Button>
                                    {selectedKey.hasCsr && (
                                        <Button
                                            size="compact-xs"
                                            variant="light"
                                            color="blue"
                                            leftSection={<IconFileCertificate size={13} />}
                                            onClick={() => setCsrModalData({
                                                tokenDeviceId: selectedKey.tokenDeviceCode,
                                                keyId: selectedKey.id,
                                                keyLabel: selectedKey.keyLabel,
                                                keyAlgorithm: selectedKey.keyAlgorithm,
                                                keySize: selectedKey.keySize,
                                                signatureAlgorithm: signer.signatureAlgorithm,
                                                csrPem: selectedKey.csrPem,
                                            })}
                                        >
                                            View CSR
                                        </Button>
                                    )}
                                    {canOperate && (
                                        <Button
                                            size="compact-xs"
                                            variant="light"
                                            color="indigo"
                                            leftSection={<IconCertificate size={13} />}
                                            onClick={() => { setCertModalKey(selectedKey); setCertPemInput(''); setCertActivateNow(false); }}
                                        >
                                            {selectedKey.hasCertificate ? 'View / Replace Cert' : 'Import Cert'}
                                        </Button>
                                    )}
                                    {isAdmin && selectedKey.hasCertificate && selectedKey.status !== 'ACTIVE' && (
                                        <Button
                                            size="compact-xs"
                                            variant="filled"
                                            color="green"
                                            disabled={!selectedKey.tokenActive}
                                            loading={saving}
                                            onClick={() => handleActivateKey(selectedKey)}
                                        >
                                            Set Active
                                        </Button>
                                    )}
                                </Group>
                            </Group>
                        </Paper>
                    )}
                </Paper>

                {/* ============================================================= */}
                {/* BOUND TOKENS TABLE                                            */}
                {/* ============================================================= */}
                <Paper withBorder p="md" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.5)' }}>
                    <Group justify="space-between" mb="sm">
                        <Group gap="xs">
                            <IconCpu size={18} color="#38bdf8" />
                            <Title order={4} c="white">Bound HSM Crypto Tokens ({(signer.tokens || []).length})</Title>
                        </Group>
                        <Group gap="xs">
                            <Text size="xs" c="dimmed">Deactivating a token disables all keys inside it</Text>
                            {canOperate && (
                                <Button
                                    size="compact-xs"
                                    variant="light"
                                    color="blue"
                                    leftSection={<IconLink size={13} />}
                                    disabled={availableTokensToLink.length === 0}
                                    onClick={() => {
                                        setLinkTokenDeviceId(availableTokensToLink[0]?.value || '');
                                        setLinkTokenModalOpen(true);
                                    }}
                                >
                                    Link Token
                                </Button>
                            )}
                        </Group>
                    </Group>

                    <Table.ScrollContainer minWidth={720}>
                        <Table verticalSpacing="xs" highlightOnHover>
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Role</Table.Th>
                                    <Table.Th>Token Device ID</Table.Th>
                                    <Table.Th>Provider</Table.Th>
                                    <Table.Th>Token Label / Slot</Table.Th>
                                    <Table.Th>Status</Table.Th>
                                    <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                                {(signer.tokens || []).map((t) => {
                                    const isUp = t.activationState === 'ACTIVE';
                                    return (
                                        <Table.Tr key={t.deviceId}>
                                            <Table.Td>
                                                <Badge size="xs" color={t.role === 'PRIMARY' ? 'blue' : 'gray'} variant="filled">{t.role}</Badge>
                                            </Table.Td>
                                            <Table.Td><Code>{t.deviceId}</Code></Table.Td>
                                            <Table.Td><Text size="xs">{t.providerName} (<Code fz={10}>{t.wrapperType}</Code>)</Text></Table.Td>
                                            <Table.Td>
                                                <Text size="xs" c="dimmed">
                                                    <Code fz={11}>{t.tokenLabel || 'n/a'}</Code>
                                                    {t.slotId != null ? <> · Slot <Code fz={11}>{t.slotId}</Code></> : null}
                                                </Text>
                                            </Table.Td>
                                            <Table.Td>
                                                <Badge size="sm" color={isUp ? 'green' : 'orange'} variant="dot">
                                                    {isUp ? 'ACTIVE' : 'DEACTIVATED (LOCKED)'}
                                                </Badge>
                                            </Table.Td>
                                            <Table.Td style={{ textAlign: 'right' }}>
                                                <Group justify="flex-end" gap="xs">
                                                    {isAdmin && isUp && (
                                                        <>
                                                            <Button
                                                                size="compact-xs"
                                                                variant="light"
                                                                color="cyan"
                                                                leftSection={<IconDatabaseImport size={13} />}
                                                                loading={syncingDeviceId === t.deviceId}
                                                                onClick={() => handleSyncTokenKeys(t.deviceId)}
                                                            >
                                                                Sync Keys
                                                            </Button>
                                                            <Button
                                                                size="compact-xs"
                                                                variant="light"
                                                                color="orange"
                                                                leftSection={<IconLock size={13} />}
                                                                loading={saving}
                                                                onClick={() => handleLockToken(t.deviceId)}
                                                            >
                                                                Deactivate
                                                            </Button>
                                                        </>
                                                    )}
                                                    {isAdmin && !isUp && (
                                                        <Button
                                                            size="compact-xs"
                                                            variant="filled"
                                                            color="green"
                                                            leftSection={<IconLockOpen size={13} />}
                                                            onClick={() => { setUnlockPin(''); setUnlockDeviceId(t.deviceId); }}
                                                        >
                                                            Activate (PIN)
                                                        </Button>
                                                    )}
                                                    {canOperate && (signer.tokens || []).length > 1 && (
                                                        <Tooltip label="Unlink token from this signer">
                                                            <ActionIcon
                                                                size="sm"
                                                                variant="subtle"
                                                                color="red"
                                                                loading={saving}
                                                                onClick={() => handleUnlinkToken(t.deviceId)}
                                                            >
                                                                <IconUnlink size={14} />
                                                            </ActionIcon>
                                                        </Tooltip>
                                                    )}
                                                </Group>
                                            </Table.Td>
                                        </Table.Tr>
                                    );
                                })}
                            </Table.Tbody>
                        </Table>
                    </Table.ScrollContainer>
                </Paper>

                {/* ============================================================= */}
                {/* KEYS TABLE FOR THIS SIGNER                                    */}
                {/* ============================================================= */}
                <Paper withBorder p="md" radius="md" style={{ backgroundColor: 'rgba(15, 23, 42, 0.5)' }}>
                    <Group justify="space-between" mb="sm">
                        <Group gap="xs">
                            <IconKey size={18} color="#818cf8" />
                            <Title order={4} c="white">Keys Owned by This Signer ({signerKeys.length})</Title>
                            <Badge size="xs" color="teal" variant="light">MAX 1 ACTIVE KEY</Badge>
                        </Group>
                        {canOperate && (
                            <Group gap="xs">
                                <Button
                                    size="compact-xs"
                                    variant="light"
                                    color="indigo"
                                    leftSection={<IconLink size={13} />}
                                    disabled={availableKeysToAttach.length === 0}
                                    onClick={() => {
                                        setAttachKeyId(availableKeysToAttach[0]?.value || '');
                                        setAttachKeyModalOpen(true);
                                    }}
                                >
                                    Attach Existing Key
                                </Button>
                                <Button
                                    size="compact-xs"
                                    variant="light"
                                    color="cyan"
                                    leftSection={<IconPlus size={13} />}
                                    disabled={!anyTokenActive}
                                    loading={saving}
                                    onClick={handleGenerateNextKeyCsr}
                                >
                                    Generate Next Key &amp; CSR
                                </Button>
                            </Group>
                        )}
                    </Group>

                    {signerKeys.length === 0 ? (
                        <Text size="sm" c="dimmed" py="md" ta="center">
                            No keys generated for this signer yet. Activate a bound Crypto Token and click <b>Generate Next Key &amp; CSR</b>.
                        </Text>
                    ) : (
                        <Table.ScrollContainer minWidth={840}>
                            <Table verticalSpacing="xs" highlightOnHover>
                                <Table.Thead>
                                    <Table.Tr>
                                        <Table.Th>Key Status</Table.Th>
                                        <Table.Th>Key Alias</Table.Th>
                                        <Table.Th>Token</Table.Th>
                                        <Table.Th>Algorithm</Table.Th>
                                        <Table.Th>Public Key SHA-1 (SKI)</Table.Th>
                                        <Table.Th>Certificate</Table.Th>
                                        <Table.Th style={{ textAlign: 'right' }}>Actions</Table.Th>
                                    </Table.Tr>
                                </Table.Thead>
                                <Table.Tbody>
                                    {signerKeys.map((k) => {
                                        const isKeyActive = k.status === 'ACTIVE' || k.active;
                                        return (
                                            <Table.Tr
                                                key={k.id}
                                                onClick={() => setSelectedKeyId(k.id)}
                                                style={{
                                                    cursor: 'pointer',
                                                    opacity: k.tokenActive ? 1 : 0.6,
                                                    backgroundColor: selectedKeyId === k.id
                                                        ? 'rgba(99, 102, 241, 0.14)'
                                                        : isKeyActive
                                                            ? 'rgba(34, 197, 94, 0.08)'
                                                            : undefined,
                                                }}
                                            >
                                                <Table.Td><KeyStatusBadge status={k.status} /></Table.Td>
                                                <Table.Td>
                                                    <Code fz={11}>{k.keyLabel}</Code>
                                                    <Text span size="10px" c="dimmed" ml={6}>#{k.id}</Text>
                                                </Table.Td>
                                                <Table.Td>
                                                    <Group gap={5} wrap="nowrap">
                                                        <Code fz={10}>{k.tokenDeviceCode || 'HSM'}</Code>
                                                        <Badge size="xs" color={k.tokenActive ? 'green' : 'orange'} variant="dot">{k.tokenState}</Badge>
                                                    </Group>
                                                </Table.Td>
                                                <Table.Td><Badge size="xs" color="cyan" variant="light">{k.keyAlgorithm} {k.keySize}</Badge></Table.Td>
                                                <Table.Td><Code fz={10}>{k.publicKeySha1}</Code></Table.Td>
                                                <Table.Td>
                                                    {k.hasCertificate ? (
                                                        <Group gap={5}>
                                                            <Badge size="xs" color={k.status === 'EXPIRED' ? 'red' : 'teal'} variant="light">
                                                                {k.status === 'EXPIRED' ? 'Expired' : `${k.certDaysUntilExpiry}d left`}
                                                            </Badge>
                                                            <Code fz={10}>{k.certSerialNumber}</Code>
                                                        </Group>
                                                    ) : k.hasCsr ? (
                                                        <Text size="xs" c="cyan.3">CSR ready</Text>
                                                    ) : (
                                                        <Text size="xs" c="dimmed">None</Text>
                                                    )}
                                                </Table.Td>
                                                <Table.Td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                                                    <Group justify="flex-end" gap={5} wrap="nowrap">
                                                        <Tooltip label="Inspect Public Key">
                                                            <ActionIcon size="sm" variant="subtle" color="cyan" onClick={() => setViewKeyModal(k)}>
                                                                <IconEye size={14} />
                                                            </ActionIcon>
                                                        </Tooltip>
                                                        {k.hasCsr && (
                                                            <Button
                                                                size="compact-xs"
                                                                variant="subtle"
                                                                color="cyan"
                                                                onClick={() => setCsrModalData({
                                                                    tokenDeviceId: k.tokenDeviceCode,
                                                                    keyId: k.id,
                                                                    keyLabel: k.keyLabel,
                                                                    keyAlgorithm: k.keyAlgorithm,
                                                                    keySize: k.keySize,
                                                                    signatureAlgorithm: signer.signatureAlgorithm,
                                                                    csrPem: k.csrPem,
                                                                })}
                                                            >
                                                                CSR
                                                            </Button>
                                                        )}
                                                        {canOperate && (
                                                            <Button
                                                                size="compact-xs"
                                                                variant="light"
                                                                color="indigo"
                                                                onClick={() => { setCertModalKey(k); setCertPemInput(''); setCertActivateNow(false); }}
                                                            >
                                                                {k.hasCertificate ? 'Cert' : 'Import Cert'}
                                                            </Button>
                                                        )}
                                                        {isAdmin && k.hasCertificate && !isKeyActive && (
                                                            <Button
                                                                size="compact-xs"
                                                                variant="filled"
                                                                color="green"
                                                                disabled={!k.tokenActive}
                                                                loading={saving}
                                                                onClick={() => handleActivateKey(k)}
                                                            >
                                                                Set Active
                                                            </Button>
                                                        )}
                                                        {isAdmin && !isKeyActive && (
                                                            <ActionIcon size="sm" variant="subtle" color="red" onClick={() => handleDeleteKey(k)}>
                                                                <IconTrash size={14} />
                                                            </ActionIcon>
                                                        )}
                                                    </Group>
                                                </Table.Td>
                                            </Table.Tr>
                                        );
                                    })}
                                </Table.Tbody>
                            </Table>
                        </Table.ScrollContainer>
                    )}
                </Paper>
            </Stack>

            {/* Modal: View Public Key */}
            <Modal
                opened={Boolean(viewKeyModal)}
                onClose={() => setViewKeyModal(null)}
                title={<Group gap="xs"><IconKey size={20} color="#2dd4bf" /><Text fw={700}>Key #{viewKeyModal?.id}: {viewKeyModal?.keyLabel}</Text></Group>}
                size="lg"
            >
                {viewKeyModal && (
                    <Stack gap="sm">
                        <Group gap="xs">
                            <KeyStatusBadge status={viewKeyModal.status} />
                            <Badge size="sm" color={viewKeyModal.tokenActive ? 'green' : 'orange'} variant="dot">
                                Token {viewKeyModal.tokenDeviceCode || 'HSM'}: {viewKeyModal.tokenState}
                            </Badge>
                            <Badge size="sm" color="cyan" variant="light">{viewKeyModal.keyAlgorithm} {viewKeyModal.keySize}</Badge>
                        </Group>
                        <Text size="xs">Public Key SHA-1 (SKI): <Code>{viewKeyModal.publicKeySha1}</Code></Text>
                        <Group justify="space-between">
                            <Text size="xs" c="dimmed" fw={700}>SubjectPublicKeyInfo (PEM) — 0 HSM Calls</Text>
                            <CopyButton value={viewKeyModal.publicKeyPem}>
                                {({ copied, copy }) => (
                                    <Button size="compact-xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={13} />} onClick={copy}>
                                        {copied ? 'Copied' : 'Copy Public Key'}
                                    </Button>
                                )}
                            </CopyButton>
                        </Group>
                        <Code block style={{ maxHeight: 240, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {viewKeyModal.publicKeyPem}
                        </Code>
                    </Stack>
                )}
            </Modal>

            {/* Modal: View CSR */}
            <Modal
                opened={Boolean(csrModalData)}
                onClose={() => setCsrModalData(null)}
                title={<Group gap="xs"><IconFileCertificate size={20} color="#38bdf8" /><Text fw={700}>PKCS#10 CSR · Key #{csrModalData?.keyId}</Text></Group>}
                size="lg"
            >
                {csrModalData && (
                    <Stack gap="md">
                        <Alert color="teal" variant="light">
                            Token <Code>{csrModalData.tokenDeviceId}</Code> · Key <Code>{csrModalData.keyLabel}</Code> ({csrModalData.keyAlgorithm} {csrModalData.keySize}) · <Code>{csrModalData.signatureAlgorithm}</Code>
                        </Alert>
                        <Group justify="flex-end" gap="xs">
                            <CopyButton value={csrModalData.csrPem}>
                                {({ copied, copy }) => (
                                    <Button size="xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={14} />} onClick={copy}>
                                        {copied ? 'Copied' : 'Copy CSR'}
                                    </Button>
                                )}
                            </CopyButton>
                            <Button size="xs" variant="filled" color="cyan" leftSection={<IconDownload size={14} />} onClick={() => downloadTextFile(csrModalData.csrPem, `${csrModalData.keyLabel}.csr.pem`)}>
                                Download .csr
                            </Button>
                        </Group>
                        <Code block style={{ maxHeight: 280, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {csrModalData.csrPem}
                        </Code>
                    </Stack>
                )}
            </Modal>

            {/* Modal: View / Import Key Certificate */}
            <Modal
                opened={Boolean(certModalKey)}
                onClose={() => { setCertModalKey(null); setCertPemInput(''); }}
                title={<Group gap="xs"><IconCertificate size={20} color="#6366f1" /><Text fw={700}>Certificate for Key #{certModalKey?.id}: {certModalKey?.keyLabel}</Text></Group>}
                size="lg"
            >
                {certModalKey && (
                    <Stack gap="md">
                        {certModalKey.hasCertificate && certModalKey.certificatePem && (
                            <Paper withBorder p="sm" radius="sm" style={{ backgroundColor: 'rgba(0,0,0,0.22)' }}>
                                <Group justify="space-between" mb={6}>
                                    <Group gap="xs">
                                        <Badge color={certModalKey.status === 'EXPIRED' ? 'red' : 'teal'} variant="filled">
                                            {certModalKey.status === 'EXPIRED' ? 'EXPIRED' : `VALID (${certModalKey.certDaysUntilExpiry}d left)`}
                                        </Badge>
                                        <Code>{certModalKey.certSerialNumber}</Code>
                                    </Group>
                                    <Group gap="xs">
                                        <CopyButton value={certModalKey.certificatePem}>
                                            {({ copied, copy }) => (
                                                <Button size="compact-xs" variant="light" color={copied ? 'teal' : 'indigo'} leftSection={<IconCopy size={13} />} onClick={copy}>
                                                    {copied ? 'Copied' : 'Copy PEM'}
                                                </Button>
                                            )}
                                        </CopyButton>
                                        <Button size="compact-xs" variant="light" color="cyan" leftSection={<IconDownload size={13} />} onClick={() => downloadTextFile(certModalKey.certificatePem, `${certModalKey.keyLabel}.crt.pem`)}>
                                            Download
                                        </Button>
                                    </Group>
                                </Group>
                                <Text size="xs" c="dimmed">Issuer: <b>{certModalKey.certIssuerDn}</b></Text>
                                <Code block mt="xs" style={{ maxHeight: 160, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                                    {certModalKey.certificatePem}
                                </Code>
                            </Paper>
                        )}

                        {canOperate && (
                            <>
                                <Divider label={certModalKey.hasCertificate ? 'Replace Certificate for This Key' : 'Import CA-Signed Certificate (0 HSM Calls)'} labelPosition="center" />
                                <form onSubmit={handleImportKeyCert}>
                                    <Stack gap="sm">
                                        <Group justify="space-between">
                                            <Text size="sm" fw={500}>X.509 Certificate PEM (requires id-kp-OCSPSigning EKU)</Text>
                                            <FileButton
                                                onChange={(file) => {
                                                    if (!file) return;
                                                    const r = new FileReader();
                                                    r.onload = () => { if (typeof r.result === 'string') setCertPemInput(r.result); };
                                                    r.readAsText(file);
                                                }}
                                                accept=".pem,.crt,.cer"
                                            >
                                                {(props) => <Button {...props} size="xs" variant="light" leftSection={<IconUpload size={14} />}>Upload .pem</Button>}
                                            </FileButton>
                                        </Group>
                                        <Textarea
                                            placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"
                                            minRows={5}
                                            maxRows={9}
                                            value={certPemInput}
                                            onChange={(e) => setCertPemInput(e.currentTarget.value)}
                                            required
                                        />
                                        {isAdmin && (
                                            <Switch
                                                label="Activate this key immediately after import"
                                                checked={certActivateNow}
                                                onChange={(e) => setCertActivateNow(e.currentTarget.checked)}
                                                color="green"
                                            />
                                        )}
                                        <Group justify="flex-end">
                                            <Button variant="default" onClick={() => setCertModalKey(null)}>Close</Button>
                                            <Button type="submit" color="indigo" loading={certLoading} leftSection={<IconCertificate size={15} />}>
                                                Import Certificate
                                            </Button>
                                        </Group>
                                    </Stack>
                                </form>
                            </>
                        )}
                    </Stack>
                )}
            </Modal>

            {/* Modal: Attach Existing Key to Signer */}
            <Modal
                opened={attachKeyModalOpen}
                onClose={() => setAttachKeyModalOpen(false)}
                title={<Group gap="xs"><IconKey size={20} color="#818cf8" /><Text fw={700}>Attach Existing Key to {signer.name}</Text></Group>}
                size="lg"
            >
                <form onSubmit={handleAttachExistingKey}>
                    <Stack gap="md">
                        <Alert color="indigo" variant="light">
                            Select an existing cryptographic key from <Code>ocsp_keys</Code> to add to this Signer. Its HSM Token will also be linked automatically if not already bound.
                        </Alert>
                        <Select
                            label="Available Keys (ocsp_keys)"
                            placeholder="Choose a key..."
                            data={availableKeysToAttach}
                            value={attachKeyId}
                            onChange={(val) => setAttachKeyId(val || '')}
                            searchable
                            required
                        />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setAttachKeyModalOpen(false)}>Cancel</Button>
                            <Button type="submit" color="indigo" loading={saving} leftSection={<IconLink size={15} />}>
                                Add Key to Signer
                            </Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            {/* Modal: Link HSM Token to Signer */}
            <Modal
                opened={linkTokenModalOpen}
                onClose={() => setLinkTokenModalOpen(false)}
                title={<Group gap="xs"><IconCpu size={20} color="#38bdf8" /><Text fw={700}>Link HSM Token to {signer.name}</Text></Group>}
                size="md"
            >
                <form onSubmit={handleLinkToken}>
                    <Stack gap="md">
                        <Alert color="cyan" variant="light">
                            Link another HSM Crypto Token to this Signer (added as <Code>FAILOVER</Code>, or <Code>PRIMARY</Code> if none bound yet).
                        </Alert>
                        <Select
                            label="Available HSM Crypto Tokens"
                            placeholder="Choose a token..."
                            data={availableTokensToLink}
                            value={linkTokenDeviceId}
                            onChange={(val) => setLinkTokenDeviceId(val || '')}
                            searchable
                            required
                        />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => setLinkTokenModalOpen(false)}>Cancel</Button>
                            <Button type="submit" color="blue" loading={saving} leftSection={<IconLink size={15} />}>
                                Link Token
                            </Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>

            {/* Modal: Quick Unlock Token */}
            <Modal
                opened={Boolean(unlockDeviceId)}
                onClose={() => { setUnlockPin(''); setUnlockDeviceId(null); }}
                title={<Group gap="xs"><IconLockOpen size={20} color="#22c55e" /><Text fw={700}>Activate Crypto Token: {unlockDeviceId}</Text></Group>}
            >
                <form onSubmit={handleUnlockToken}>
                    <Stack gap="md">
                        <Alert color="cyan" variant="light">
                            Enter User PIN for <Code>{unlockDeviceId}</Code>. PIN is used once for <Code>C_Login</Code> and immediately wiped from memory.
                        </Alert>
                        <PasswordInput label="PKCS#11 User PIN" placeholder="Enter PIN" value={unlockPin} onChange={(e) => setUnlockPin(e.currentTarget.value)} autoFocus required />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={() => { setUnlockPin(''); setUnlockDeviceId(null); }}>Cancel</Button>
                            <Button type="submit" color="green" loading={saving} leftSection={<IconLockOpen size={16} />}>Activate Token</Button>
                        </Group>
                    </Stack>
                </form>
            </Modal>
        </Container>
    );
};

