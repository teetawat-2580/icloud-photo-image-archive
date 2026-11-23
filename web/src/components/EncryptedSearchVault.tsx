'use client';

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from 'react';
import Link from 'next/link';
import {
  ArrowLeft,
  Calendar,
  Check,
  Copy,
  ExternalLink,
  FileText,
  HardDrive,
  Image as ImageIcon,
  Lock,
  Pencil,
  Search,
  ShieldCheck,
  Sparkles,
  Users,
  X,
} from 'lucide-react';
import {
  decryptPersonLabels,
  decryptSearchIndexBundle,
  decryptVaultBlobAesGcm,
  encryptPersonLabels,
  unlockCustomerPrivateKey,
  unwrapVaultDataKey,
  type CustomerVaultKeySetup,
  type DecryptedSearchIndex,
  type SearchVaultAsset,
  type SearchVaultMediaRef,
} from '@/lib/search-vault-crypto';
import {
  buildSafeHighlightSegments,
  getVaultAvailableTags,
  getVaultAvailableYears,
  resolvePersonDisplayName,
  resolveSafeMediaUrl,
  searchEncryptedVaultIndex,
} from '@/lib/search-vault-engine';
import {
  buildLiveZeroKnowledgeDemoVault,
  type LiveDemoVaultPayload,
} from '@/lib/search-vault-demo';
import type { SearchVaultPublicMetadata } from '@/lib/vault-auth';
import { VaultPassphraseGate } from './VaultPassphraseGate';

interface EncryptedSearchVaultProps {
  vaultId: string;
  initialToken: string;
  isDemo: boolean;
}

interface DecryptedThumbImageProps {
  thumbKey: string | null;
  alt: string;
  className?: string;
  loadThumbUrl: (thumbKey: string) => Promise<string | null>;
}

function DecryptedThumbImage({
  thumbKey,
  alt,
  className,
  loadThumbUrl,
}: DecryptedThumbImageProps) {
  const [src, setSrc] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!thumbKey) return;
    let active = true;
    let observer: IntersectionObserver | null = null;

    const triggerLoad = () => {
      loadThumbUrl(thumbKey)
        .then((url) => {
          if (!active) return;
          if (url) {
            setSrc(url);
          } else {
            setFailed(true);
          }
        })
        .catch(() => {
          if (active) setFailed(true);
        });
    };

    const el = containerRef.current;
    if (el && typeof IntersectionObserver !== 'undefined') {
      observer = new IntersectionObserver(
        (entries) => {
          if (entries.some((entry) => entry.isIntersecting)) {
            observer?.disconnect();
            triggerLoad();
          }
        },
        { rootMargin: '160px' }
      );
      observer.observe(el);
    } else {
      triggerLoad();
    }

    return () => {
      active = false;
      observer?.disconnect();
    };
  }, [thumbKey, loadThumbUrl]);

  return (
    <div
      ref={containerRef}
      className={`relative overflow-hidden bg-vault-well ${className ?? ''}`}
    >
      {src ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={src}
          alt={alt}
          loading="lazy"
          className="h-full w-full object-cover"
        />
      ) : (
        <div className="flex h-full w-full items-center justify-center text-vault-subtle">
          <ImageIcon className="h-6 w-6 opacity-50" aria-hidden="true" />
          {failed && <span className="sr-only">ไม่สามารถถอดรหัสภาพย่อได้</span>}
        </div>
      )}
    </div>
  );
}

export function EncryptedSearchVault({
  vaultId,
  initialToken,
  isDemo,
}: EncryptedSearchVaultProps) {
  const [vault, setVault] = useState<SearchVaultPublicMetadata | null>(null);
  const [loadingVault, setLoadingVault] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Live Zero-Knowledge Demo Sandbox blobs (real AES-256-GCM ciphertext in RAM)
  const demoPayloadRef = useRef<LiveDemoVaultPayload | null>(null);

  // Unlocked session state (strictly in browser RAM — wiped on Lock / unmount)
  const vaultDataKeyRef = useRef<CryptoKey | null>(null);
  const thumbUrlCacheRef = useRef<Map<string, string>>(new Map());
  const inflightThumbRef = useRef<Map<string, Promise<string | null>>>(new Map());

  const [decryptedIndex, setDecryptedIndex] = useState<DecryptedSearchIndex | null>(null);
  const [customLabels, setCustomLabels] = useState<Record<string, string>>({});
  const [unlockBusy, setUnlockBusy] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockDurationMs, setUnlockDurationMs] = useState<number | null>(null);

  // Search & Filter states
  const [query, setQuery] = useState('');
  const [selectedPersonIds, setSelectedPersonIds] = useState<string[]>([]);
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [selectedYear, setSelectedYear] = useState<number | null>(null);
  const [onlyWithOcr, setOnlyWithOcr] = useState(false);
  const [activeAsset, setActiveAsset] = useState<SearchVaultAsset | null>(null);
  const [copiedOcr, setCopiedOcr] = useState(false);

  // Inline Encrypted Person Rename state
  const [editingPersonId, setEditingPersonId] = useState<string | null>(null);
  const [editingPersonName, setEditingPersonName] = useState('');
  const [savingLabel, setSavingLabel] = useState(false);

  // Pluggable Media Source Adapter preview toggle (Google Photos today -> Home NAS / Immich tomorrow)
  const [mediaProviderOverride, setMediaProviderOverride] = useState<
    'default' | 'nas_immich'
  >('default');
  const [customNasBaseUrl, setCustomNasBaseUrl] = useState(
    'https://nas.family-home.example.com'
  );

  const revokeAllThumbUrls = useCallback(() => {
    for (const url of thumbUrlCacheRef.current.values()) {
      URL.revokeObjectURL(url);
    }
    thumbUrlCacheRef.current.clear();
    inflightThumbRef.current.clear();
  }, []);

  useEffect(() => {
    return () => {
      vaultDataKeyRef.current = null;
      revokeAllThumbUrls();
    };
  }, [revokeAllThumbUrls]);

  const fetchVaultMetadata = useCallback(async () => {
    setLoadingVault(true);
    setLoadError(null);
    try {
      if (isDemo) {
        const demo = await buildLiveZeroKnowledgeDemoVault(vaultId);
        demoPayloadRef.current = demo;
        setVault(demo.metadata);
        return;
      }

      if (!initialToken) {
        setLoadError('ไม่พบ Access Token ในลิงก์ กรุณาเปิดผ่านลิงก์ส่วนตัวที่ได้รับจาก CloudVault Concierge');
        return;
      }

      const res = await fetch(
        `/api/vaults/${encodeURIComponent(vaultId)}/metadata`,
        {
          method: 'GET',
          headers: { Authorization: `Bearer ${initialToken}` },
          cache: 'no-store',
        }
      );
      const data = (await res.json()) as {
        vault?: SearchVaultPublicMetadata;
        error?: string;
      };
      if (!res.ok || !data.vault) {
        setLoadError(data.error ?? `ไม่สามารถโหลดข้อมูลตู้นิรภัยได้ (HTTP ${res.status})`);
        return;
      }
      setVault(data.vault);
    } catch (err) {
      setLoadError(
        err instanceof Error ? err.message : 'เกิดข้อผิดพลาดในการเชื่อมต่อเซิร์ฟเวอร์'
      );
    } finally {
      setLoadingVault(false);
    }
  }, [vaultId, initialToken, isDemo]);

  useEffect(() => {
    void fetchVaultMetadata();
  }, [fetchVaultMetadata]);

  const fetchEncryptedBlobBytes = useCallback(
    async (objectKey: string): Promise<Uint8Array> => {
      if (isDemo && demoPayloadRef.current) {
        const bytes = demoPayloadRef.current.encryptedBlobs.get(objectKey);
        if (!bytes) {
          throw new Error('Encrypted demo object not found.');
        }
        return bytes;
      }

      const res = await fetch(
        `/api/vaults/${encodeURIComponent(vaultId)}/blob?key=${encodeURIComponent(objectKey)}`,
        {
          method: 'GET',
          headers: { Authorization: `Bearer ${initialToken}` },
          cache: 'no-store',
        }
      );
      if (!res.ok) {
        throw new Error(`Encrypted blob fetch failed (HTTP ${res.status}).`);
      }
      return new Uint8Array(await res.arrayBuffer());
    },
    [vaultId, initialToken, isDemo]
  );

  const handleRegisterKeys = useCallback(
    async (setup: CustomerVaultKeySetup) => {
      const res = await fetch(
        `/api/vaults/${encodeURIComponent(vaultId)}/register-keys`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${initialToken}`,
          },
          body: JSON.stringify({
            customer_public_key_pem: setup.publicKeyPem,
            customer_key_fingerprint_sha256: setup.keyFingerprintSha256,
            encrypted_private_key_blob: setup.encryptedPrivateKeyBlob,
          }),
        }
      );
      const data = (await res.json()) as { error?: string };
      if (!res.ok) {
        throw new Error(data.error ?? `ลงทะเบียนกุญแจไม่สำเร็จ (HTTP ${res.status})`);
      }
      await fetchVaultMetadata();
    },
    [vaultId, initialToken, fetchVaultMetadata]
  );

  const handleUnlock = useCallback(
    async (passphrase: string) => {
      if (!vault || !vault.encrypted_private_key_blob || !vault.wrapped_vault_key_b64 || !vault.index_object_key) {
        setUnlockError('ตู้นิรภัยนี้ยังไม่พร้อมสำหรับการปลดล็อก');
        return;
      }
      setUnlockBusy(true);
      setUnlockError(null);
      const started = performance.now();
      try {
        const privateKey = await unlockCustomerPrivateKey(
          vault.encrypted_private_key_blob,
          passphrase
        );
        const vaultDataKey = await unwrapVaultDataKey(
          vault.wrapped_vault_key_b64,
          privateKey
        );

        const encryptedBundle = await fetchEncryptedBlobBytes(vault.index_object_key);
        const index = await decryptSearchIndexBundle(
          encryptedBundle,
          vaultDataKey,
          vault.id
        );

        let labels: Record<string, string> = {};
        if (vault.encrypted_person_labels_blob) {
          try {
            labels = await decryptPersonLabels(
              vault.encrypted_person_labels_blob,
              vaultDataKey,
              vault.id
            );
          } catch {
            labels = {};
          }
        }

        vaultDataKeyRef.current = vaultDataKey;
        setCustomLabels(labels);
        setDecryptedIndex(index);
        setUnlockDurationMs(Math.round(performance.now() - started));
      } catch {
        setUnlockError(
          'รหัสผ่านไม่ถูกต้องหรือไม่สามารถถอดรหัสตู้นิรภัยได้ (WebCrypto Authentication Failed)'
        );
      } finally {
        setUnlockBusy(false);
      }
    },
    [vault, fetchEncryptedBlobBytes]
  );

  const handleLockVault = useCallback(() => {
    vaultDataKeyRef.current = null;
    revokeAllThumbUrls();
    setDecryptedIndex(null);
    setActiveAsset(null);
    setQuery('');
    setSelectedPersonIds([]);
    setSelectedTag(null);
    setSelectedYear(null);
    setOnlyWithOcr(false);
    setUnlockError(null);
  }, [revokeAllThumbUrls]);

  const loadThumbUrl = useCallback(
    async (thumbKey: string): Promise<string | null> => {
      const existing = thumbUrlCacheRef.current.get(thumbKey);
      if (existing) return existing;

      const inflight = inflightThumbRef.current.get(thumbKey);
      if (inflight) return inflight;

      const vaultDataKey = vaultDataKeyRef.current;
      if (!vaultDataKey || !vault) return null;

      const promise = (async () => {
        try {
          const encBytes = await fetchEncryptedBlobBytes(thumbKey);
          const plainBytes = await decryptVaultBlobAesGcm(
            encBytes,
            vaultDataKey,
            `${vault.id}:${thumbKey}`
          );
          const mimeType =
            isDemo && demoPayloadRef.current
              ? demoPayloadRef.current.blobMimeTypes.get(thumbKey) ?? 'image/webp'
              : 'image/webp';
          const objectUrl = URL.createObjectURL(
            new Blob([plainBytes], { type: mimeType })
          );
          thumbUrlCacheRef.current.set(thumbKey, objectUrl);
          return objectUrl;
        } catch {
          return null;
        } finally {
          inflightThumbRef.current.delete(thumbKey);
        }
      })();

      inflightThumbRef.current.set(thumbKey, promise);
      return promise;
    },
    [vault, isDemo, fetchEncryptedBlobBytes]
  );

  const handleSavePersonName = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (!editingPersonId || !vault || !vaultDataKeyRef.current) return;
      const trimmed = editingPersonName.trim();
      const nextLabels = { ...customLabels };
      if (trimmed) {
        nextLabels[editingPersonId] = trimmed;
      } else {
        delete nextLabels[editingPersonId];
      }

      setSavingLabel(true);
      try {
        const encryptedBlob = await encryptPersonLabels(
          nextLabels,
          vaultDataKeyRef.current,
          vault.id
        );
        if (!isDemo) {
          const res = await fetch(
            `/api/vaults/${encodeURIComponent(vaultId)}/person-labels`,
            {
              method: 'PATCH',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${initialToken}`,
              },
              body: JSON.stringify({ encrypted_person_labels_blob: encryptedBlob }),
            }
          );
          if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
          }
        }
        setCustomLabels(nextLabels);
        setEditingPersonId(null);
      } catch {
        // Keep modal open for retry
      } finally {
        setSavingLabel(false);
      }
    },
    [editingPersonId, editingPersonName, customLabels, vault, vaultId, initialToken, isDemo]
  );

  const togglePersonFilter = useCallback((personId: string) => {
    setSelectedPersonIds((prev) =>
      prev.includes(personId)
        ? prev.filter((id) => id !== personId)
        : [...prev, personId]
    );
  }, []);

  const availableYears = useMemo(
    () => (decryptedIndex ? getVaultAvailableYears(decryptedIndex) : []),
    [decryptedIndex]
  );
  const availableTags = useMemo(
    () => (decryptedIndex ? getVaultAvailableTags(decryptedIndex) : []),
    [decryptedIndex]
  );

  const filteredAssets = useMemo(() => {
    if (!decryptedIndex) return [];
    return searchEncryptedVaultIndex(
      decryptedIndex,
      {
        query,
        selectedPersonIds,
        selectedTag,
        selectedYear,
        onlyWithOcr,
      },
      customLabels
    );
  }, [
    decryptedIndex,
    query,
    selectedPersonIds,
    selectedTag,
    selectedYear,
    onlyWithOcr,
    customLabels,
  ]);

  const resolveAssetLink = useCallback(
    (mediaRef: SearchVaultMediaRef) =>
      resolveSafeMediaUrl(
        mediaRef,
        mediaProviderOverride === 'nas_immich'
          ? { provider: 'nas_immich', nasBaseUrl: customNasBaseUrl }
          : undefined
      ),
    [mediaProviderOverride, customNasBaseUrl]
  );

  if (loadingVault) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-vault-canvas px-4">
        <div className="rounded-2xl border border-vault-border bg-vault-surface px-8 py-6 text-center shadow-vault">
          <div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-vault-border border-t-vault-emerald" />
          <p className="mt-4 text-sm font-semibold text-vault-ink">
            {isDemo
              ? 'กำลังสร้างตู้นิรภัยจำลองและเข้ารหัส WebCrypto สดในเบราว์เซอร์…'
              : 'กำลังเชื่อมต่อตู้นิรภัย Zero-Knowledge…'}
          </p>
        </div>
      </div>
    );
  }

  if (loadError || !vault) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16">
        <div className="rounded-2xl border border-red-200 bg-vault-surface p-8 text-center shadow-vault">
          <Lock className="mx-auto h-10 w-10 text-red-600" aria-hidden="true" />
          <h1 className="mt-4 text-xl font-bold text-vault-ink">
            ไม่สามารถเปิดตู้นิรภัยค้นหาภาพได้
          </h1>
          <p className="mt-2 text-sm text-vault-muted">
            {loadError ?? 'ไม่พบข้อมูลตู้นิรภัยที่ระบุ'}
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link
              href="/vault/demo-family-archive?demo=1"
              className="inline-flex min-h-[44px] items-center gap-2 rounded-lg bg-vault-emerald px-4 py-2.5 text-sm font-semibold text-white hover:bg-teal-800"
            >
              <Sparkles className="h-4 w-4" />
              <span>ทดลองตู้นิรภัย Zero-Knowledge Sandbox</span>
            </Link>
            <Link
              href="/"
              className="inline-flex min-h-[44px] items-center gap-2 rounded-lg border border-vault-border bg-vault-canvas px-4 py-2.5 text-sm font-semibold text-vault-ink hover:bg-vault-well"
            >
              <ArrowLeft className="h-4 w-4" />
              <span>กลับหน้าหลัก</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-vault-canvas text-vault-ink">
      {/* Sticky Institutional Top Bar */}
      <header className="sticky top-0 z-30 border-b border-vault-border bg-vault-surface/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <Link
              href="/"
              aria-label="กลับหน้าหลัก CloudVault Concierge"
              className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-vault-border bg-vault-canvas text-vault-ink hover:bg-vault-well"
            >
              <ShieldCheck className="h-5 w-5 text-vault-emerald" aria-hidden="true" />
            </Link>
            <div className="min-w-0">
              <p className="truncate text-sm font-bold text-vault-ink">
                {vault.owner_display_name}
              </p>
              <p className="flex items-center gap-1.5 text-[11px] text-vault-subtle">
                <span
                  className={`h-2 w-2 rounded-full ${
                    decryptedIndex ? 'bg-vault-emerald' : 'bg-amber-500'
                  }`}
                />
                <span className="truncate">
                  {decryptedIndex
                    ? `ปลดล็อกใน RAM แล้ว (${unlockDurationMs ?? 0} ms) · ค้นหาไม่ส่งออกเซิร์ฟเวอร์`
                    : 'Zero-Knowledge Encrypted AI Search Vault'}
                </span>
              </p>
            </div>
          </div>

          {decryptedIndex && (
            <button
              type="button"
              onClick={handleLockVault}
              className="inline-flex min-h-[44px] shrink-0 items-center gap-2 rounded-xl border border-vault-ink bg-vault-ink px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-slate-800 sm:text-sm"
            >
              <Lock className="h-4 w-4" aria-hidden="true" />
              <span>ล็อกตู้นิรภัย</span>
            </button>
          )}
        </div>
      </header>

      {!decryptedIndex ? (
        <VaultPassphraseGate
          vault={vault}
          isDemo={isDemo}
          unlockBusy={unlockBusy}
          unlockError={unlockError}
          onUnlock={handleUnlock}
          onRegisterKeys={handleRegisterKeys}
          onRefreshMetadata={fetchVaultMetadata}
        />
      ) : (
        <main className="mx-auto max-w-6xl space-y-6 px-4 py-6 sm:px-6">
          {/* Search Bar & Primary Controls */}
          <section className="rounded-2xl border border-vault-border bg-vault-surface p-4 shadow-vault sm:p-5">
            <div className="flex flex-col gap-3 md:flex-row">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-vault-subtle"
                  aria-hidden="true"
                />
                <input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder='ค้นหาข้อความในภาพ (เช่น "สวัสดีปีใหม่ 2562", "กสิกร") ชื่อคน หรือสถานที่…'
                  className="min-h-[50px] w-full rounded-xl border border-vault-border bg-vault-canvas pl-11 pr-10 text-base text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:bg-vault-surface focus:outline-none"
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => setQuery('')}
                    aria-label="ล้างคำค้นหา"
                    className="absolute right-2 top-1/2 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-lg text-vault-muted hover:bg-vault-well"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="relative flex items-center">
                  <Calendar
                    className="pointer-events-none absolute left-3 h-4 w-4 text-vault-subtle"
                    aria-hidden="true"
                  />
                  <select
                    aria-label="กรองตามปี ค.ศ."
                    value={selectedYear ?? ''}
                    onChange={(e) =>
                      setSelectedYear(e.target.value ? Number(e.target.value) : null)
                    }
                    className="min-h-[50px] rounded-xl border border-vault-border bg-vault-canvas pl-9 pr-8 text-sm font-medium text-vault-ink focus:border-vault-sky focus:outline-none"
                  >
                    <option value="">ทุกปี ({availableYears.length} ปี)</option>
                    {availableYears.map((yr) => (
                      <option key={yr} value={yr}>
                        ปี {yr} (พ.ศ. {yr + 543})
                      </option>
                    ))}
                  </select>
                </div>

                <button
                  type="button"
                  onClick={() => setOnlyWithOcr((v) => !v)}
                  className={`inline-flex min-h-[50px] items-center gap-1.5 rounded-xl border px-3.5 text-sm font-medium transition-colors ${
                    onlyWithOcr
                      ? 'border-vault-emerald bg-vault-emerald-soft text-vault-emerald'
                      : 'border-vault-border bg-vault-canvas text-vault-muted hover:bg-vault-well'
                  }`}
                >
                  <FileText className="h-4 w-4" aria-hidden="true" />
                  <span>เฉพาะภาพมีข้อความ OCR</span>
                </button>
              </div>
            </div>

            {/* Face Clusters Strip (InsightFace) + Inline Encrypted Rename */}
            {decryptedIndex.people.length > 0 && (
              <div className="mt-5 border-t border-vault-border pt-4">
                <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-vault-ink">
                    <Users className="h-4 w-4 text-vault-sky" aria-hidden="true" />
                    <span>ค้นหาตามใบหน้า (แตะได้หลายคนพร้อมกัน · ชื่อคนถูกเข้ารหัส E2EE)</span>
                  </div>
                  {selectedPersonIds.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setSelectedPersonIds([])}
                      className="text-xs font-semibold text-vault-sky hover:underline"
                    >
                      ล้างตัวกรองใบหน้า ({selectedPersonIds.length})
                    </button>
                  )}
                </div>

                <div className="flex gap-3 overflow-x-auto pb-1">
                  {decryptedIndex.people.map((person) => {
                    const displayName = resolvePersonDisplayName(
                      person.person_id,
                      person.default_label,
                      customLabels
                    );
                    const isSelected = selectedPersonIds.includes(person.person_id);
                    return (
                      <div
                        key={person.person_id}
                        className={`flex shrink-0 items-center gap-2.5 rounded-xl border p-2 pr-3 transition-colors ${
                          isSelected
                            ? 'border-vault-emerald bg-vault-emerald-soft shadow-vault'
                            : 'border-vault-border bg-vault-canvas hover:bg-vault-well/60'
                        }`}
                      >
                        <button
                          type="button"
                          onClick={() => togglePersonFilter(person.person_id)}
                          className="flex min-h-[44px] items-center gap-2.5 text-left"
                        >
                          <DecryptedThumbImage
                            thumbKey={person.avatar_thumb_key}
                            alt={displayName}
                            loadThumbUrl={loadThumbUrl}
                            className="h-11 w-11 shrink-0 rounded-full border border-vault-border"
                          />
                          <div>
                            <p className="text-sm font-semibold text-vault-ink">
                              {displayName}
                            </p>
                            <p className="text-[11px] text-vault-subtle">
                              {person.photo_count.toLocaleString()} ภาพ
                            </p>
                          </div>
                        </button>

                        <button
                          type="button"
                          onClick={() => {
                            setEditingPersonId(person.person_id);
                            setEditingPersonName(displayName);
                          }}
                          aria-label={`เปลี่ยนชื่อ ${displayName}`}
                          className="flex h-9 w-9 items-center justify-center rounded-lg text-vault-subtle hover:bg-white hover:text-vault-ink"
                        >
                          <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Semantic Tags Strip */}
            {availableTags.length > 0 && (
              <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-vault-border pt-3.5">
                <span className="text-xs font-medium text-vault-subtle">หมวด AI:</span>
                {availableTags.map(({ tag, count }) => {
                  const active = selectedTag === tag;
                  return (
                    <button
                      key={tag}
                      type="button"
                      onClick={() => setSelectedTag(active ? null : tag)}
                      className={`min-h-[36px] rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                        active
                          ? 'border-vault-sky bg-vault-sky text-white'
                          : 'border-vault-border bg-vault-canvas text-vault-ink hover:bg-vault-well'
                      }`}
                    >
                      {tag} <span className="opacity-75">({count})</span>
                    </button>
                  );
                })}
              </div>
            )}
          </section>

          {/* Pluggable Media Source Adapter Strip (Google Photos Today -> Home NAS Tomorrow) */}
          <section className="flex flex-col justify-between gap-3 rounded-xl border border-vault-border bg-vault-surface px-4 py-3 text-xs sm:flex-row sm:items-center">
            <div className="flex items-center gap-2.5">
              <HardDrive className="h-4 w-4 shrink-0 text-vault-emerald" aria-hidden="true" />
              <span className="font-semibold text-vault-ink">
                แหล่งเปิดภาพต้นฉบับ (Pluggable Media Source):
              </span>
              <span className="text-vault-muted">
                {mediaProviderOverride === 'default'
                  ? 'Google Photos Shared Album (Phase 1)'
                  : 'Home NAS / Immich (Zero-Reindex Phase 2)'}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setMediaProviderOverride('default')}
                className={`rounded-lg border px-2.5 py-1.5 font-semibold ${
                  mediaProviderOverride === 'default'
                    ? 'border-vault-emerald bg-vault-emerald-soft text-vault-emerald'
                    : 'border-vault-border bg-vault-canvas text-vault-muted'
                }`}
              >
                Google Photos
              </button>
              <button
                type="button"
                onClick={() => setMediaProviderOverride('nas_immich')}
                className={`rounded-lg border px-2.5 py-1.5 font-semibold ${
                  mediaProviderOverride === 'nas_immich'
                    ? 'border-vault-sky bg-vault-sky-soft text-vault-sky'
                    : 'border-vault-border bg-vault-canvas text-vault-muted'
                }`}
              >
                สลับไป Home NAS / Immich
              </button>
              {mediaProviderOverride === 'nas_immich' && (
                <input
                  type="url"
                  value={customNasBaseUrl}
                  onChange={(e) => setCustomNasBaseUrl(e.target.value)}
                  aria-label="URL ของ Home NAS / Immich"
                  className="rounded-lg border border-vault-border bg-vault-canvas px-2.5 py-1 font-mono text-[11px] text-vault-ink"
                />
              )}
            </div>
          </section>

          {/* Result Summary */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <p className="font-semibold text-vault-ink">
              พบ <span className="font-mono text-vault-emerald">{filteredAssets.length.toLocaleString()}</span>{' '}
              จาก {decryptedIndex.assets.length.toLocaleString()} ภาพ
            </p>
            {(query || selectedPersonIds.length > 0 || selectedTag || selectedYear || onlyWithOcr) && (
              <button
                type="button"
                onClick={() => {
                  setQuery('');
                  setSelectedPersonIds([]);
                  setSelectedTag(null);
                  setSelectedYear(null);
                  setOnlyWithOcr(false);
                }}
                className="text-xs font-semibold text-vault-sky hover:underline"
              >
                ล้างตัวกรองทั้งหมด
              </button>
            )}
          </div>

          {/* Decrypted Thumbnail Grid */}
          {filteredAssets.length === 0 ? (
            <div className="rounded-2xl border border-vault-border bg-vault-surface p-12 text-center">
              <Search className="mx-auto h-10 w-10 text-vault-subtle opacity-60" />
              <p className="mt-3 text-base font-semibold text-vault-ink">
                ไม่พบภาพที่ตรงกับเงื่อนไขการค้นหา
              </p>
              <p className="mt-1 text-sm text-vault-muted">
                ลองเปลี่ยนคำค้นหาภาษาไทย/อังกฤษ หรือล้างตัวกรองใบหน้าและปีด้านบน
              </p>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {filteredAssets.map((asset) => {
                const safeLink = resolveAssetLink(asset.media_ref);
                const ocrSegments = buildSafeHighlightSegments(asset.ocr_text, query);
                return (
                  <article
                    key={asset.sha256}
                    className="group flex flex-col overflow-hidden rounded-2xl border border-vault-border bg-vault-surface shadow-vault transition-shadow hover:shadow-vault-elevated"
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setActiveAsset(asset);
                        setCopiedOcr(false);
                      }}
                      className="relative block aspect-[4/3] w-full text-left"
                    >
                      <DecryptedThumbImage
                        thumbKey={asset.thumb_key}
                        alt={asset.filename}
                        loadThumbUrl={loadThumbUrl}
                        className="h-full w-full"
                      />
                      <span className="absolute left-3 top-3 rounded-md bg-vault-ink/80 px-2 py-0.5 font-mono text-[11px] font-semibold text-white">
                        {asset.year}
                      </span>
                      {asset.face_ids.length > 0 && (
                        <span className="absolute right-3 top-3 inline-flex items-center gap-1 rounded-md bg-vault-surface/90 px-2 py-0.5 text-[11px] font-semibold text-vault-ink shadow-sm">
                          <Users className="h-3 w-3 text-vault-emerald" />
                          {asset.face_ids.length}
                        </span>
                      )}
                    </button>

                    <div className="flex flex-1 flex-col justify-between p-4">
                      <div className="space-y-2">
                        <div className="flex items-start justify-between gap-2">
                          <p className="truncate font-mono text-xs font-semibold text-vault-ink">
                            {asset.filename}
                          </p>
                          <span className="shrink-0 text-[11px] text-vault-subtle">
                            {asset.media_ref.album_key ?? asset.year}
                          </span>
                        </div>

                        {asset.ocr_text && (
                          <p className="line-clamp-2 rounded-lg bg-vault-canvas px-2.5 py-2 text-xs leading-relaxed text-vault-muted">
                            {ocrSegments.map((seg, idx) =>
                              seg.match ? (
                                <mark
                                  key={idx}
                                  className="rounded bg-amber-200 px-0.5 font-semibold text-vault-ink"
                                >
                                  {seg.text}
                                </mark>
                              ) : (
                                <span key={idx}>{seg.text}</span>
                              )
                            )}
                          </p>
                        )}

                        <div className="flex flex-wrap gap-1.5">
                          {asset.face_ids.map((fid) => {
                            const person = decryptedIndex.people.find(
                              (p) => p.person_id === fid
                            );
                            const name = resolvePersonDisplayName(
                              fid,
                              person?.default_label ?? fid,
                              customLabels
                            );
                            return (
                              <span
                                key={fid}
                                className="rounded-md bg-vault-emerald-soft px-2 py-0.5 text-[11px] font-semibold text-vault-emerald"
                              >
                                {name}
                              </span>
                            );
                          })}
                          {asset.semantic_tags.slice(0, 2).map((tag) => (
                            <span
                              key={tag}
                              className="rounded-md bg-vault-well px-2 py-0.5 text-[11px] font-medium text-vault-muted"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="mt-4 flex items-center gap-2 border-t border-vault-border pt-3">
                        <button
                          type="button"
                          onClick={() => {
                            setActiveAsset(asset);
                            setCopiedOcr(false);
                          }}
                          className="min-h-[42px] flex-1 rounded-xl border border-vault-border bg-vault-canvas px-3 py-2 text-xs font-semibold text-vault-ink hover:bg-vault-well"
                        >
                          ดูรายละเอียด &amp; OCR
                        </button>
                        {safeLink && (
                          <a
                            href={safeLink}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex min-h-[42px] items-center gap-1.5 rounded-xl bg-vault-emerald px-3.5 py-2 text-xs font-semibold text-white hover:bg-teal-800"
                          >
                            <span>เปิดภาพต้นฉบับ</span>
                            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                          </a>
                        )}
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </main>
      )}

      {/* Encrypted Inline Person Rename Modal */}
      {editingPersonId && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="ตั้งชื่อใบหน้า (เข้ารหัส E2EE)"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4 backdrop-blur-sm"
        >
          <form
            onSubmit={handleSavePersonName}
            className="w-full max-w-md rounded-2xl border border-vault-border bg-vault-surface p-6 shadow-vault-elevated"
          >
            <h2 className="text-lg font-bold text-vault-ink">
              ตั้งชื่อใบหน้า (เข้ารหัสด้วย AES-256-GCM ก่อนบันทึก)
            </h2>
            <p className="mt-1 text-xs text-vault-muted">
              ชื่อที่คุณตั้ง (เช่น &ldquo;คุณแม่&rdquo;, &ldquo;คุณยาย&rdquo;) จะถูกเข้ารหัสในเบราว์เซอร์ก่อนบันทึก ฐานข้อมูลกลางจะไม่เห็นชื่อบุคคลในครอบครัวของคุณ
            </p>
            <input
              type="text"
              value={editingPersonName}
              onChange={(e) => setEditingPersonName(e.target.value)}
              placeholder="พิมพ์ชื่อที่ต้องการค้นหาได้ง่าย"
              autoFocus
              maxLength={60}
              className="mt-4 min-h-[48px] w-full rounded-xl border border-vault-border bg-vault-canvas px-4 text-base text-vault-ink focus:border-vault-sky focus:outline-none"
            />
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setEditingPersonId(null)}
                className="min-h-[44px] rounded-xl border border-vault-border px-4 py-2 text-sm font-semibold text-vault-muted hover:bg-vault-well"
              >
                ยกเลิก
              </button>
              <button
                type="submit"
                disabled={savingLabel}
                className="min-h-[44px] rounded-xl bg-vault-emerald px-5 py-2 text-sm font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
              >
                {savingLabel ? 'กำลังเข้ารหัสและบันทึก…' : 'บันทึกชื่อ (E2EE)'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Photo Inspection Lightbox Modal */}
      {activeAsset && decryptedIndex && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`รายละเอียดภาพ ${activeAsset.filename}`}
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/65 p-4 backdrop-blur-sm"
        >
          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-vault-border bg-vault-surface shadow-vault-elevated">
            <div className="flex items-center justify-between border-b border-vault-border px-5 py-3.5">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm font-bold text-vault-ink">
                  {activeAsset.filename}
                </p>
                <p className="text-xs text-vault-subtle">
                  อัลบั้ม: {activeAsset.media_ref.album_title ?? activeAsset.year} · SHA-256:{' '}
                  <span className="font-mono">{activeAsset.sha256.slice(0, 12)}…</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setActiveAsset(null)}
                aria-label="ปิดหน้าต่าง"
                className="flex h-10 w-10 items-center justify-center rounded-lg text-vault-muted hover:bg-vault-well"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-5">
              <DecryptedThumbImage
                thumbKey={activeAsset.thumb_key}
                alt={activeAsset.filename}
                loadThumbUrl={loadThumbUrl}
                className="aspect-[4/3] w-full rounded-xl border border-vault-border"
              />

              {activeAsset.ocr_text && (
                <div className="mt-4 rounded-xl border border-vault-border bg-vault-canvas p-4">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-semibold text-vault-ink">
                      ข้อความที่ AI อ่านได้จากภาพ (Thai / English OCR)
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        void navigator.clipboard?.writeText(activeAsset.ocr_text);
                        setCopiedOcr(true);
                      }}
                      className="inline-flex items-center gap-1 rounded-lg border border-vault-border bg-vault-surface px-2.5 py-1 text-xs font-semibold text-vault-ink hover:bg-vault-well"
                    >
                      {copiedOcr ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-vault-emerald" />
                          <span>คัดลอกแล้ว</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" />
                          <span>คัดลอกข้อความ</span>
                        </>
                      )}
                    </button>
                  </div>
                  <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-vault-muted">
                    {buildSafeHighlightSegments(activeAsset.ocr_text, query).map(
                      (seg, idx) =>
                        seg.match ? (
                          <mark
                            key={idx}
                            className="rounded bg-amber-200 px-0.5 font-semibold text-vault-ink"
                          >
                            {seg.text}
                          </mark>
                        ) : (
                          <span key={idx}>{seg.text}</span>
                        )
                    )}
                  </p>
                </div>
              )}

              <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
                <span className="text-xs text-vault-subtle">
                  ถ่ายเมื่อ: <span className="font-mono text-vault-ink">{activeAsset.captured_at}</span>
                </span>
                {resolveAssetLink(activeAsset.media_ref) && (
                  <a
                    href={resolveAssetLink(activeAsset.media_ref) ?? undefined}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex min-h-[48px] items-center gap-2 rounded-xl bg-vault-emerald px-5 py-2.5 text-sm font-semibold text-white shadow-vault hover:bg-teal-800"
                  >
                    <span>
                      {mediaProviderOverride === 'nas_immich'
                        ? 'เปิดภาพความละเอียดเต็มบน Home NAS / Immich'
                        : 'เปิดภาพความละเอียดเต็มในอัลบั้ม Google Photos'}
                    </span>
                    <ExternalLink className="h-4 w-4" aria-hidden="true" />
                  </a>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
