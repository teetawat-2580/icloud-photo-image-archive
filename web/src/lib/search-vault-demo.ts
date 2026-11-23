/**
 * CloudVault Concierge — Interactive Live Zero-Knowledge Demo Sandbox (`?demo=1`).
 *
 * Uses REAL Browser WebCrypto (`RSA-OAEP-2048` + `PBKDF2-SHA256` + `AES-256-GCM` + `gzip`)
 * to generate a live encrypted Search Index Bundle and encrypted SVG/image thumbnails in RAM.
 * Strictly ZERO real family emails or unlisted Google Photos share links.
 */

import {
  encryptPersonLabels,
  encryptSearchIndexBundleForTest,
  encryptVaultBlobAesGcm,
  generateCustomerVaultKeypairAndEncryptPrivateKey,
  wrapVaultDataKeyWithPublicPem,
  type DecryptedSearchIndex,
} from './search-vault-crypto';
import type { SearchVaultPublicMetadata } from './vault-auth';

export const DEMO_VAULT_PASSPHRASE = 'FamilyVault2569';

export interface LiveDemoVaultPayload {
  metadata: SearchVaultPublicMetadata;
  encryptedBlobs: Map<string, Uint8Array>;
  blobMimeTypes: Map<string, string>;
}

function makeIllustrativeThumbSvg(spec: {
  bg1: string;
  bg2: string;
  accent: string;
  badge: string;
  headline: string;
  subline: string;
  kind: 'cake' | 'slip' | 'beach' | 'temple' | 'dinner' | 'garden';
}): Uint8Array {
  const iconMarkup =
    spec.kind === 'cake'
      ? `<circle cx="160" cy="112" r="56" fill="#FFFBEB" stroke="${spec.accent}" stroke-width="5"/><circle cx="160" cy="112" r="44" fill="#FEF3C7"/><text x="160" y="106" text-anchor="middle" font-size="14" font-weight="700" fill="#B91C1C" font-family="sans-serif">สวัสดีปีใหม่</text><text x="160" y="128" text-anchor="middle" font-size="18" font-weight="800" fill="#B45309" font-family="sans-serif">2562</text>`
      : spec.kind === 'slip'
        ? `<rect x="92" y="44" width="136" height="142" rx="12" fill="#FFFFFF" stroke="#CBD5E1" stroke-width="2"/><rect x="108" y="60" width="104" height="14" rx="4" fill="#0F766E"/><text x="160" y="96" text-anchor="middle" font-size="12" font-weight="700" fill="#0F172A" font-family="sans-serif">โอนเงินสำเร็จ</text><text x="160" y="118" text-anchor="middle" font-size="15" font-weight="800" fill="#0F766E" font-family="monospace">15,000.00 THB</text><rect x="112" y="136" width="96" height="8" rx="4" fill="#E2E8F0"/><rect x="112" y="152" width="72" height="8" rx="4" fill="#E2E8F0"/>`
        : spec.kind === 'beach'
          ? `<circle cx="240" cy="64" r="24" fill="#FDE68A"/><path d="M0 156 Q80 132 160 152 T320 148 L320 240 L0 240 Z" fill="#0284C7" opacity="0.85"/><path d="M0 176 Q100 162 200 178 T320 172 L320 240 L0 240 Z" fill="#FDE68A" opacity="0.9"/>`
          : spec.kind === 'temple'
            ? `<polygon points="160,44 134,116 186,116" fill="#F59E0B"/><rect x="122" y="116" width="76" height="58" rx="4" fill="#FFFBEB" stroke="#D97706" stroke-width="3"/><rect x="150" y="136" width="20" height="38" rx="3" fill="#B45309"/>`
            : spec.kind === 'dinner'
              ? `<circle cx="112" cy="112" r="26" fill="#FDE68A" stroke="#FFFFFF" stroke-width="3"/><circle cx="164" cy="102" r="28" fill="#BAE6FD" stroke="#FFFFFF" stroke-width="3"/><circle cx="212" cy="116" r="25" fill="#BBF7D0" stroke="#FFFFFF" stroke-width="3"/><rect x="70" y="150" width="180" height="22" rx="11" fill="#FFFFFF" opacity="0.85"/>`
              : `<circle cx="128" cy="96" r="34" fill="#86EFAC" opacity="0.9"/><circle cx="192" cy="106" r="40" fill="#34D399" opacity="0.85"/><rect x="122" y="128" width="12" height="46" rx="4" fill="#78350F"/><rect x="186" y="136" width="14" height="40" rx="4" fill="#78350F"/>`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 240" width="320" height="240">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${spec.bg1}"/>
      <stop offset="100%" stop-color="${spec.bg2}"/>
    </linearGradient>
  </defs>
  <rect width="320" height="240" fill="url(#g)"/>
  ${iconMarkup}
  <rect x="14" y="14" width="108" height="24" rx="12" fill="rgba(15,23,42,0.72)"/>
  <text x="68" y="30" text-anchor="middle" font-size="11" font-weight="600" fill="#FFFFFF" font-family="sans-serif">${spec.badge}</text>
  <rect x="0" y="184" width="320" height="56" fill="rgba(15,23,42,0.76)"/>
  <text x="16" y="207" font-size="13" font-weight="700" fill="#FFFFFF" font-family="sans-serif">${spec.headline}</text>
  <text x="16" y="226" font-size="11" fill="#CBD5E1" font-family="sans-serif">${spec.subline}</text>
</svg>`;

  return new TextEncoder().encode(svg);
}

/**
 * Build a cryptographically authentic Zero-Knowledge Demo Vault inside Browser RAM.
 * Every blob (Index Bundle + 6 Thumbnails + Person Labels) is genuinely encrypted with AES-256-GCM
 * and wrapped ONE-WAY with RSA-OAEP-2048 so the demo proves the real cryptographic pipeline.
 */
export async function buildLiveZeroKnowledgeDemoVault(
  vaultId: string
): Promise<LiveDemoVaultPayload> {
  const cleanVaultId = vaultId || 'demo-family-archive';

  // Fast PBKDF2 iteration count strictly for instant in-browser sandbox boot;
  // production customer vaults enforce 600,000 iterations.
  const customerKeys = await generateCustomerVaultKeypairAndEncryptPrivateKey(
    DEMO_VAULT_PASSPHRASE,
    { iterations: 25_000, modulusLength: 2048 }
  );

  const rawVaultKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const wrappedVaultKeyB64 = await wrapVaultDataKeyWithPublicPem(
    rawVaultKey,
    customerKeys.publicKeyPem
  );

  const thumbSpecs: Array<{
    key: string;
    bg1: string;
    bg2: string;
    accent: string;
    badge: string;
    headline: string;
    subline: string;
    kind: 'cake' | 'slip' | 'beach' | 'temple' | 'dinner' | 'garden';
  }> = [
    {
      key: `vaults/${cleanVaultId}/thumbs/demo_cake_2562.enc`,
      bg1: '#FEF9C3',
      bg2: '#FDE68A',
      accent: '#15803D',
      badge: 'ปี 2018 · OCR ไทย',
      headline: 'เค้กสวัสดีปีใหม่ 2562',
      subline: 'ฉลองคืนข้ามปีพร้อมหน้าครอบครัว',
      kind: 'cake',
    },
    {
      key: `vaults/${cleanVaultId}/thumbs/demo_family_dinner.enc`,
      bg1: '#E0F2FE',
      bg2: '#BAE6FD',
      accent: '#0369A1',
      badge: 'ปี 2018 · 3 ใบหน้า',
      headline: 'รวมญาติมื้อค่ำส่งท้ายปี',
      subline: 'คุณแม่ · คุณยาย · พี่สาว',
      kind: 'dinner',
    },
    {
      key: `vaults/${cleanVaultId}/thumbs/demo_slip_kbank.enc`,
      bg1: '#F1F5F9',
      bg2: '#E2E8F0',
      accent: '#0F766E',
      badge: 'ปี 2019 · เอกสาร',
      headline: 'สลิปโอนเงิน ธนาคารกสิกรไทย',
      subline: 'ชำระค่าซ่อมบ้าน 15,000 บาท',
      kind: 'slip',
    },
    {
      key: `vaults/${cleanVaultId}/thumbs/demo_huahin_beach.enc`,
      bg1: '#E0F2FE',
      bg2: '#7DD3FC',
      accent: '#0284C7',
      badge: 'ปี 2019 · ทะเล',
      headline: 'ทริปหัวหิน ริมทะเลตอนเช้า',
      subline: 'คุณแม่ · น้องชาย',
      kind: 'beach',
    },
    {
      key: `vaults/${cleanVaultId}/thumbs/demo_temple_chiangmai.enc`,
      bg1: '#FEF3C7',
      bg2: '#FDBA74',
      accent: '#B45309',
      badge: 'ปี 2020 · ไหว้พระ',
      headline: 'วัดพระธาตุดอยสุเทพ เชียงใหม่',
      subline: 'ทริปทำบุญปีใหม่ 2563',
      kind: 'temple',
    },
    {
      key: `vaults/${cleanVaultId}/thumbs/demo_home_garden.enc`,
      bg1: '#DCFCE7',
      bg2: '#86EFAC',
      accent: '#0F766E',
      badge: 'ปี 2020 · สวนหน้าบ้าน',
      headline: 'ต้นไม้และดอกกล้วยไม้หน้าบ้าน',
      subline: 'ถ่ายคู่กับคุณยายช่วงวันหยุด',
      kind: 'garden',
    },
  ];

  const demoIndex: DecryptedSearchIndex = {
    schema_version: 2,
    vault_id: cleanVaultId,
    generated_at: '2026-11-23T08:00:00Z',
    media_source_type: 'google_photos_shared',
    media_source_config: {
      note: 'Interactive Zero-Knowledge Demo (Synthetic Placeholder URLs)',
    },
    people: [
      {
        person_id: 'person_001',
        default_label: 'คนที่ 1',
        photo_count: 4,
        avatar_thumb_key: thumbSpecs[1].key,
      },
      {
        person_id: 'person_002',
        default_label: 'คนที่ 2',
        photo_count: 3,
        avatar_thumb_key: thumbSpecs[5].key,
      },
      {
        person_id: 'person_003',
        default_label: 'คนที่ 3',
        photo_count: 2,
        avatar_thumb_key: thumbSpecs[3].key,
      },
    ],
    assets: [
      {
        sha256: '1001'.repeat(16),
        filename: 'IMG_20181231_211224_CAKE.JPG',
        captured_at: '2018-12-31T21:12:24+07:00',
        year: 2018,
        thumb_key: thumbSpecs[0].key,
        face_ids: ['person_001'],
        ocr_text: 'สวัสดีปีใหม่ 2562 เค้กปีใหม่ ครอบครัวอบอุ่น Happy New Year 2019',
        semantic_tags: ['เค้ก / วันเกิด', 'ครอบครัว', 'อาหาร'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2018',
          album_title: 'Family_Archive_Google (2018)',
          url: 'https://photos.app.goo.gl/ExampleDemoArchive2018',
          filename: 'IMG_20181231_211224_CAKE.JPG',
        },
      },
      {
        sha256: '1002'.repeat(16),
        filename: 'IMG_20181231_205510_DINNER.JPG',
        captured_at: '2018-12-31T20:55:10+07:00',
        year: 2018,
        thumb_key: thumbSpecs[1].key,
        face_ids: ['person_001', 'person_002', 'person_003'],
        ocr_text: 'มื้อค่ำส่งท้ายปีเก่า บ้านสวน Family Dinner',
        semantic_tags: ['ครอบครัว', 'อาหาร'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2018',
          album_title: 'Family_Archive_Google (2018)',
          url: 'https://photos.app.goo.gl/ExampleDemoArchive2018',
          filename: 'IMG_20181231_205510_DINNER.JPG',
        },
      },
      {
        sha256: '1003'.repeat(16),
        filename: 'IMG_20190615_101400_SLIP.JPG',
        captured_at: '2019-06-15T10:14:00+07:00',
        year: 2019,
        thumb_key: thumbSpecs[2].key,
        face_ids: [],
        ocr_text: 'โอนเงินสำเร็จ ธนาคารกสิกรไทย KBANK 15,000.00 บาท ใบเสร็จค่าซ่อมหลังคา',
        semantic_tags: ['เอกสาร / สลิป'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2019-2020',
          album_title: 'Family_Archive_Google (2019-2020)',
          url: 'https://photos.app.goo.gl/ExampleDemoArchive2019To2020',
          filename: 'IMG_20190615_101400_SLIP.JPG',
        },
      },
      {
        sha256: '1004'.repeat(16),
        filename: 'IMG_20191103_081500_HUAHIN.JPG',
        captured_at: '2019-11-03T08:15:00+07:00',
        year: 2019,
        thumb_key: thumbSpecs[3].key,
        face_ids: ['person_001', 'person_003'],
        ocr_text: 'Hua Hin Beach Resort หาดหัวหิน ทะเลสวย',
        semantic_tags: ['ทะเล / ท่องเที่ยว', 'ครอบครัว'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2019-2020',
          album_title: 'Family_Archive_Google (2019-2020)',
          url: 'https://photos.app.goo.gl/ExampleDemoArchive2019To2020',
          filename: 'IMG_20191103_081500_HUAHIN.JPG',
        },
      },
      {
        sha256: '1005'.repeat(16),
        filename: 'IMG_20200102_093000_TEMPLE.JPG',
        captured_at: '2020-01-02T09:30:00+07:00',
        year: 2020,
        thumb_key: thumbSpecs[4].key,
        face_ids: ['person_001', 'person_002'],
        ocr_text: 'วัดพระธาตุดอยสุเทพราชวรวิหาร เชียงใหม่ ทำบุญปีใหม่ 2563',
        semantic_tags: ['ท่องเที่ยว', 'ไหว้พระ / ทำบุญ', 'ครอบครัว'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2019-2020',
          album_title: 'Family_Archive_Google (2019-2020)',
          url: 'https://photos.app.goo.gl/ExampleDemoArchive2019To2020',
          filename: 'IMG_20200102_093000_TEMPLE.JPG',
        },
      },
      {
        sha256: '1006'.repeat(16),
        filename: 'IMG_20200518_164500_GARDEN.JPG',
        captured_at: '2020-05-18T16:45:00+07:00',
        year: 2020,
        thumb_key: thumbSpecs[5].key,
        face_ids: ['person_002'],
        ocr_text: 'กล้วยไม้ช้างกระ สวนหน้าบ้าน',
        semantic_tags: ['ธรรมชาติ / สวน', 'ครอบครัว'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2019-2020',
          album_title: 'Family_Archive_Google (2019-2020)',
          url: 'https://photos.app.goo.gl/ExampleDemoArchive2019To2020',
          filename: 'IMG_20200518_164500_GARDEN.JPG',
        },
      },
    ],
  };

  const encryptedBlobs = new Map<string, Uint8Array>();
  const blobMimeTypes = new Map<string, string>();

  const indexKey = `vaults/${cleanVaultId}/index_bundle.json.gz.enc`;
  const encryptedBundle = await encryptSearchIndexBundleForTest(
    demoIndex,
    rawVaultKey,
    cleanVaultId
  );
  encryptedBlobs.set(indexKey, encryptedBundle);

  let totalThumbBytes = 0;
  for (const spec of thumbSpecs) {
    const svgBytes = makeIllustrativeThumbSvg(spec);
    const encThumb = await encryptVaultBlobAesGcm(
      svgBytes,
      rawVaultKey,
      `${cleanVaultId}:${spec.key}`
    );
    encryptedBlobs.set(spec.key, encThumb);
    blobMimeTypes.set(spec.key, 'image/svg+xml');
    totalThumbBytes += encThumb.byteLength;
  }

  const encryptedPersonLabelsBlob = await encryptPersonLabels(
    {
      person_001: 'คุณแม่',
      person_002: 'คุณยาย',
      person_003: 'ลูกชาย',
    },
    rawVaultKey,
    cleanVaultId
  );

  // Zero ephemeral raw AES key in demo builder just like the Python AI worker does
  rawVaultKey.fill(0);

  const nowIso = new Date().toISOString();
  const metadata: SearchVaultPublicMetadata = {
    id: cleanVaultId,
    job_id: null,
    vault_code: 'DEMO-ZK-VAULT',
    owner_display_name: 'ตัวอย่างคลังภาพครอบครัว (Zero-Knowledge Sandbox)',
    status: 'READY',
    customer_public_key_pem: customerKeys.publicKeyPem,
    customer_key_fingerprint_sha256: customerKeys.keyFingerprintSha256,
    encrypted_private_key_blob: customerKeys.encryptedPrivateKeyBlob,
    wrapped_vault_key_b64: wrappedVaultKeyB64,
    storage_backend: 'cloudflare_r2',
    storage_bucket: 'cloudvault-encrypted-blobs',
    index_object_key: indexKey,
    index_sha256: 'demo-verified-in-ram',
    index_size_bytes: encryptedBundle.byteLength,
    thumb_prefix: `vaults/${cleanVaultId}/thumbs/`,
    media_source_type: 'google_photos_shared',
    media_source_config: {},
    encrypted_person_labels_blob: encryptedPersonLabelsBlob,
    total_assets: demoIndex.assets.length,
    total_faces: demoIndex.people.length,
    total_ocr_assets: demoIndex.assets.length,
    total_thumb_bytes: totalThumbBytes,
    plaintext_purged_at: nowIso,
    created_at: nowIso,
    updated_at: nowIso,
  };

  return { metadata, encryptedBlobs, blobMimeTypes };
}
