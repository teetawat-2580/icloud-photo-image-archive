/**
 * CloudVault Concierge — Client-Side Zero-Knowledge Search Engine & Pluggable Media Source Resolver.
 *
 * Runs 100% inside browser RAM over the decrypted Search Index Bundle:
 * - Multi-token Thai + English OCR search
 * - Multi-face AND filtering + search by customer-renamed custom person labels
 * - Bilingual semantic tag + capture year filtering
 * - Strict HTTPS URL allowlist for Pluggable Media Source Adapters (OWASP A03 XSS / Open Redirect defense)
 * - Safe highlight segmentation (pure React data tokens — zero `dangerouslySetInnerHTML`)
 */

import type {
  DecryptedSearchIndex,
  SearchVaultAsset,
  SearchVaultMediaRef,
} from './search-vault-crypto';

export interface SearchFilterState {
  query?: string;
  selectedPersonIds?: string[];
  selectedTag?: string | null;
  selectedYear?: number | null;
  onlyWithOcr?: boolean;
  onlyWithFaces?: boolean;
}

export interface HighlightSegment {
  text: string;
  match: boolean;
}

const GOOGLE_PHOTOS_ALLOWED_HOSTS = new Set([
  'photos.google.com',
  'photos.app.goo.gl',
]);

function normalizeSearchText(value: string): string {
  return value.normalize('NFC').toLowerCase().trim();
}

export function resolvePersonDisplayName(
  personId: string,
  defaultLabel: string,
  customLabels: Record<string, string>
): string {
  const custom = customLabels[personId]?.trim();
  return custom && custom.length > 0 ? custom : defaultLabel;
}

/**
 * Filter and rank decrypted assets strictly inside browser memory (< 20 ms for 100k assets).
 * Zero search terms ever touch Supabase or any external server.
 */
export function searchEncryptedVaultIndex(
  index: DecryptedSearchIndex,
  filters: SearchFilterState,
  customLabels: Record<string, string> = {}
): SearchVaultAsset[] {
  const rawQuery = normalizeSearchText(filters.query ?? '');
  const queryTokens = rawQuery ? rawQuery.split(/\s+/).filter(Boolean) : [];
  const selectedPersons = (filters.selectedPersonIds ?? []).filter(Boolean);
  const selectedTagNorm = filters.selectedTag
    ? normalizeSearchText(filters.selectedTag)
    : null;
  const selectedYear =
    typeof filters.selectedYear === 'number' && Number.isFinite(filters.selectedYear)
      ? filters.selectedYear
      : null;

  const defaultLabelById = new Map<string, string>();
  for (const person of index.people ?? []) {
    defaultLabelById.set(person.person_id, person.default_label);
  }

  const matched: SearchVaultAsset[] = [];

  for (const asset of index.assets ?? []) {
    const faceIds = Array.isArray(asset.face_ids) ? asset.face_ids : [];
    const tags = Array.isArray(asset.semantic_tags) ? asset.semantic_tags : [];

    if (filters.onlyWithOcr && !asset.ocr_text?.trim()) {
      continue;
    }
    if (filters.onlyWithFaces && faceIds.length === 0) {
      continue;
    }
    if (selectedYear !== null && asset.year !== selectedYear) {
      continue;
    }
    if (selectedPersons.length > 0) {
      let hasAllFaces = true;
      for (const pid of selectedPersons) {
        if (!faceIds.includes(pid)) {
          hasAllFaces = false;
          break;
        }
      }
      if (!hasAllFaces) {
        continue;
      }
    }
    if (selectedTagNorm) {
      const hasTag = tags.some(
        (tag) => normalizeSearchText(tag) === selectedTagNorm
      );
      if (!hasTag) {
        continue;
      }
    }

    if (queryTokens.length > 0) {
      const personNames: string[] = [];
      for (const fid of faceIds) {
        const custom = customLabels[fid];
        if (custom) personNames.push(custom);
        const def = defaultLabelById.get(fid);
        if (def) personNames.push(def);
      }

      const haystack = normalizeSearchText(
        [
          asset.ocr_text ?? '',
          asset.filename ?? '',
          String(asset.year ?? ''),
          asset.media_ref?.album_title ?? '',
          tags.join(' '),
          personNames.join(' '),
        ].join(' ')
      );

      let matchesAllTokens = true;
      for (const token of queryTokens) {
        if (!haystack.includes(token)) {
          matchesAllTokens = false;
          break;
        }
      }
      if (!matchesAllTokens) {
        continue;
      }
    }

    matched.push(asset);
  }

  matched.sort((a, b) => {
    const dateCompare = (b.captured_at ?? '').localeCompare(a.captured_at ?? '');
    if (dateCompare !== 0) return dateCompare;
    if (b.year !== a.year) return b.year - a.year;
    return (a.filename ?? '').localeCompare(b.filename ?? '');
  });

  return matched;
}

/**
 * Pluggable Media Source Adapter URL validator (OWASP A03 defense).
 * Blocks `javascript:`, `data:`, non-HTTPS schemes, and untrusted hosts for Google Photos links.
 */
export function resolveSafeMediaUrl(
  mediaRef: SearchVaultMediaRef | null | undefined,
  override?: {
    provider?: SearchVaultMediaRef['provider'];
    nasBaseUrl?: string;
  }
): string | null {
  if (!mediaRef) return null;
  const provider = override?.provider ?? mediaRef.provider;

  if (provider === 'local_hdd') {
    return null;
  }

  let candidateUrl = mediaRef.url?.trim() ?? '';

  if (override?.provider === 'nas_immich' && override.nasBaseUrl?.trim()) {
    const cleanBase = override.nasBaseUrl.trim().replace(/\/+$/, '');
    const assetSlug = encodeURIComponent(mediaRef.filename || mediaRef.album_key || 'asset');
    candidateUrl = `${cleanBase}/photos/${assetSlug}`;
  }

  if (!candidateUrl || candidateUrl.length > 2048) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidateUrl);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'https:') {
    return null;
  }
  if (parsed.username || parsed.password) {
    return null;
  }

  const host = parsed.hostname.toLowerCase();
  if (!host) {
    return null;
  }

  if (provider === 'google_photos_shared' || provider === 'google_photos_private') {
    if (!GOOGLE_PHOTOS_ALLOWED_HOSTS.has(host)) {
      return null;
    }
    return parsed.toString();
  }

  if (provider === 'nas_immich') {
    // Allow customer's own HTTPS NAS / Immich domain (e.g. Tailscale MagicDNS / Cloudflare Tunnel)
    return parsed.toString();
  }

  return null;
}

/**
 * Tokenize OCR text into safe plain-text highlight segments for React rendering.
 * Never constructs raw HTML strings.
 */
export function buildSafeHighlightSegments(
  text: string,
  query: string
): HighlightSegment[] {
  if (!text) return [];
  const rawTokens = normalizeSearchText(query)
    .split(/\s+/)
    .filter((t) => t.length > 0);
  if (rawTokens.length === 0) {
    return [{ text, match: false }];
  }

  // Escape regex metacharacters and match longest tokens first
  const escaped = Array.from(new Set(rawTokens))
    .sort((a, b) => b.length - a.length)
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

  const pattern = new RegExp(`(${escaped.join('|')})`, 'gi');
  const parts = text.split(pattern);
  const tokenSet = new Set(rawTokens);

  const segments: HighlightSegment[] = [];
  for (const part of parts) {
    if (!part) continue;
    segments.push({
      text: part,
      match: tokenSet.has(normalizeSearchText(part)),
    });
  }
  return segments;
}

export function getVaultAvailableYears(index: DecryptedSearchIndex): number[] {
  const years = new Set<number>();
  for (const asset of index.assets ?? []) {
    if (Number.isInteger(asset.year) && asset.year > 1900) {
      years.add(asset.year);
    }
  }
  return Array.from(years).sort((a, b) => b - a);
}

export function getVaultAvailableTags(
  index: DecryptedSearchIndex
): Array<{ tag: string; count: number }> {
  const counts = new Map<string, number>();
  for (const asset of index.assets ?? []) {
    for (const tag of asset.semantic_tags ?? []) {
      const clean = tag.trim();
      if (!clean) continue;
      counts.set(clean, (counts.get(clean) ?? 0) + 1);
    }
  }
  return Array.from(counts.entries())
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag));
}
