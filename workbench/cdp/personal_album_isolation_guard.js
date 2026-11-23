'use strict';

const fs = require('fs');

const DEFAULT_ARCHIVE_ALBUM_PREFIX = 'iCloud_Archive_Google';
const RECENTLY_ADDED_SEARCH_URL = 'https://photos.google.com/search/_tra_';
const ALBUMS_URL = 'https://photos.google.com/albums';
const DEFAULT_TIME_ZONES = ['Asia/Bangkok', 'UTC'];

const SYSTEM_NON_PERSONAL_ALBUM_TITLES = new Set([
  'no items',
  'albums',
  'untitled album',
  'add a title',
  'อัลบั้ม',
  'อัลบั้มไม่มีชื่อ',
  'เพิ่มชื่อ',
  'ไม่มีรายการ'
]);

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

function normalizeArchiveAlbumPrefix(archiveAlbumPrefix = DEFAULT_ARCHIVE_ALBUM_PREFIX) {
  if (archiveAlbumPrefix === undefined || archiveAlbumPrefix === null) {
    return DEFAULT_ARCHIVE_ALBUM_PREFIX;
  }
  if (typeof archiveAlbumPrefix !== 'string') {
    throw new Error('archiveAlbumPrefix must be a non-empty string');
  }
  const trimmed = archiveAlbumPrefix.trim();
  if (!trimmed) {
    throw new Error('archiveAlbumPrefix must not be empty (would disable Layer 1 personal album isolation)');
  }
  return trimmed;
}

function normalizeAriaSpaces(str = '') {
  return String(str || '').replace(/[\u202f\u00a0\s]+/g, ' ').trim();
}

function extractPhotoIdFromHref(href = '') {
  const m = String(href || '').match(/\/photo\/([A-Za-z0-9_-]+)/);
  return m ? m[1] : '';
}

/**
 * Layer 1 Classifier:
 * Returns true if an existing album title belongs to the customer's pre-existing personal
 * albums (anything that does NOT belong to the customer's archiveAlbumPrefix or system placeholders).
 */
function isPersonalNonArchiveAlbumTitle(title = '', archiveAlbumPrefix = DEFAULT_ARCHIVE_ALBUM_PREFIX) {
  const prefix = normalizeArchiveAlbumPrefix(archiveAlbumPrefix);
  const t = String(title || '').trim();
  if (!t) return false;

  const lower = t.toLowerCase();
  const prefixLower = prefix.toLowerCase();

  const hasTrailingBoundary = /[\s_\-(]$/.test(prefixLower);
  const matchesArchivePrefix = hasTrailingBoundary
    ? lower.startsWith(prefixLower)
    : (
        lower === prefixLower ||
        lower.startsWith(`${prefixLower} `) ||
        lower.startsWith(`${prefixLower}(`) ||
        lower.startsWith(`${prefixLower}_`) ||
        lower.startsWith(`${prefixLower}-`)
      );

  if (
    matchesArchivePrefix ||
    lower.startsWith('tmp_merge_') ||
    SYSTEM_NON_PERSONAL_ALBUM_TITLES.has(lower)
  ) {
    return false;
  }

  return true;
}

/**
 * Layer 2 Classifier:
 * Detects day-level "Select all photos from <Day>" / "เลือกรูปภาพทั้งหมด..." checkboxes
 * that must never be clicked when organizing archive items (prevents sweeping in personal photos
 * taken on the same calendar date).
 */
function isDayLevelSelectAllAria(ariaLabel = '') {
  const lower = normalizeAriaSpaces(ariaLabel).toLowerCase();
  if (!lower) return false;
  return (
    lower.startsWith('select all') ||
    lower.startsWith('เลือกรูปภาพทั้งหมด') ||
    lower.startsWith('เลือกรายการทั้งหมด') ||
    lower.startsWith('เลือกทั้งหมด')
  );
}

/**
 * Layer 2 Upload-Window Filter for https://photos.google.com/search/_tra_:
 * Confirms an item's upload timestamp sits inside the active CloudVault job upload window.
 */
function isWithinUploadWindow(itemTimestampMs, uploadWindow = null) {
  if (!uploadWindow || typeof uploadWindow !== 'object') return true;
  const ts = typeof itemTimestampMs === 'number'
    ? itemTimestampMs
    : (itemTimestampMs ? Date.parse(String(itemTimestampMs)) : NaN);
  if (!Number.isFinite(ts)) return false;

  const toleranceMs = Number.isFinite(uploadWindow.toleranceMs) ? uploadWindow.toleranceMs : 60000;
  const startMs = uploadWindow.windowStartMs !== undefined && uploadWindow.windowStartMs !== null
    ? Number(uploadWindow.windowStartMs)
    : null;
  const endMs = uploadWindow.windowEndMs !== undefined && uploadWindow.windowEndMs !== null
    ? Number(uploadWindow.windowEndMs)
    : null;

  if (startMs !== null && Number.isFinite(startMs) && ts < startMs - toleranceMs) {
    return false;
  }
  if (endMs !== null && Number.isFinite(endMs) && ts > endMs + toleranceMs) {
    return false;
  }
  return true;
}

function filterRecentlyAddedItemsByUploadWindow(items = [], uploadWindow = null) {
  if (!Array.isArray(items)) return [];
  if (!uploadWindow) return items.slice();
  return items.filter((item) => {
    if (!item || typeof item !== 'object') return false;
    const candidateTs = item.uploadedAtMs ?? item.uploaded_at ?? item.addedAtMs ?? item.added_at;
    return isWithinUploadWindow(candidateTs, uploadWindow);
  });
}

/**
 * Formats an ISO-8601 timestamp into Google Photos en-US aria-label strings for
 * Asia/Bangkok and UTC (plus any extra timeZones requested).
 */
function formatIsoToGooglePhotosAriaStrings(isoStr, timeZones = DEFAULT_TIME_ZONES) {
  if (!isoStr) return { timestamps: [], dates: [] };
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return { timestamps: [], dates: [] };

  const tzList = Array.isArray(timeZones) && timeZones.length > 0 ? timeZones : DEFAULT_TIME_ZONES;
  const timestamps = new Set();
  const dates = new Set();

  for (const timeZone of tzList) {
    try {
      const dateStr = normalizeAriaSpaces(
        new Intl.DateTimeFormat('en-US', {
          timeZone,
          month: 'short',
          day: 'numeric',
          year: 'numeric'
        }).format(d)
      );
      const dateTimeStr = normalizeAriaSpaces(
        new Intl.DateTimeFormat('en-US', {
          timeZone,
          month: 'short',
          day: 'numeric',
          year: 'numeric',
          hour: 'numeric',
          minute: '2-digit',
          second: '2-digit',
          hour12: true
        }).format(d)
      );
      dates.add(dateStr);
      timestamps.add(dateTimeStr);
    } catch {}
  }

  return {
    timestamps: Array.from(timestamps),
    dates: Array.from(dates)
  };
}

function extractYear4FromRecord(record, fallbackYearKey = '') {
  if (fallbackYearKey) {
    const m = String(fallbackYearKey).match(/\b(19\d{2}|20\d{2}|2100)\b/);
    if (m) return m[1];
  }
  if (record && typeof record === 'object') {
    const candidates = [record.year, record.yearFolder, record.created, record.created_at, record.date_taken];
    for (const c of candidates) {
      if (!c) continue;
      const m = String(c).match(/\b(19\d{2}|20\d{2}|2100)\b/);
      if (m) return m[1];
    }
  }
  return '';
}

/**
 * Layer 3 Whitelist Builder:
 * Builds exact-second timestamps (Asia/Bangkok + UTC), calendar dates, and filename sets
 * from either a nested `{ years: { ...: { months: { ...: { files: [...] } } } } }` manifest,
 * a flat `{ files: [...] }` / `[...]` manifest, or a manifest JSON file path.
 */
function buildManifestTimestampWhitelist(manifestInput = null, targetYears = null, options = {}) {
  let manifest = manifestInput;
  if (typeof manifestInput === 'string' && manifestInput.trim()) {
    if (fs.existsSync(manifestInput)) {
      const rawManifest = fs.readFileSync(manifestInput, 'utf8').replace(/^\uFEFF/, '');
      manifest = JSON.parse(rawManifest);
    } else {
      manifest = { years: {} };
    }
  }
  if (!manifest || typeof manifest !== 'object') {
    manifest = { years: {} };
  }

  const timeZones = Array.isArray(options.timeZones) && options.timeZones.length > 0
    ? options.timeZones
    : DEFAULT_TIME_ZONES;

  const yearFilterSet = Array.isArray(targetYears) && targetYears.length > 0
    ? new Set(targetYears.map((y) => String(y).trim().slice(0, 4)))
    : null;

  const whitelistTimestamps = new Set();
  const whitelistDates = new Set();
  const whitelistFilenames = new Set();
  let itemCount = 0;

  const ingestFile = (f, yearHint = '') => {
    if (!f || typeof f !== 'object') return;
    const y4 = extractYear4FromRecord(f, yearHint);
    if (yearFilterSet && y4 && !yearFilterSet.has(y4)) return;
    if (yearFilterSet && !y4) return;

    itemCount++;
    if (f.filename) whitelistFilenames.add(String(f.filename).trim());
    if (f.original_filename) whitelistFilenames.add(String(f.original_filename).trim());

    const createdIso = f.created || f.created_at || f.date_taken || '';
    if (createdIso) {
      const { timestamps, dates } = formatIsoToGooglePhotosAriaStrings(createdIso, timeZones);
      for (const ts of timestamps) whitelistTimestamps.add(ts);
      for (const dt of dates) whitelistDates.add(dt);
    }
  };

  if (Array.isArray(manifest)) {
    for (const f of manifest) ingestFile(f);
  } else {
    if (manifest.years && typeof manifest.years === 'object') {
      for (const [yearKey, yearVal] of Object.entries(manifest.years)) {
        const y4 = String(yearKey).trim().slice(0, 4);
        if (yearFilterSet && !yearFilterSet.has(y4)) continue;

        const monthsObj = (yearVal && yearVal.months) || {};
        for (const monthVal of Object.values(monthsObj)) {
          const files = (monthVal && monthVal.files) || [];
          for (const f of files) ingestFile(f, y4);
        }

        if (Array.isArray(yearVal && yearVal.files)) {
          for (const f of yearVal.files) ingestFile(f, y4);
        }
      }
    }

    if (Array.isArray(manifest.files)) {
      for (const f of manifest.files) ingestFile(f);
    }
  }

  return {
    whitelistTimestamps,
    whitelistDates,
    whitelistFilenames,
    itemCount
  };
}

/**
 * 3-Layer Personal Album Isolation Gate:
 * - Layer 1: Hard-blocks any photoId or exact aria-label collected from pre-existing personal albums.
 * - Layer 2: Hard-blocks day-level "Select all photos from <Day>" checkboxes & optional _tra_ upload window mismatches.
 * - Layer 3: Matches 1:1 manifest filenames and exact-second timestamps (Asia/Bangkok + UTC).
 *            strictTimestampMatch defaults to true so same-day wrong-second personal photos are always rejected.
 */
function isPhotoEligibleForArchiveAlbum({
  photoId = '',
  ariaLabel = '',
  filename = '',
  uploadedAtMs = undefined,
  uploadWindow = null,
  blacklistedPhotoIds = new Set(),
  blacklistedAriaLabels = new Set(),
  whitelistTimestamps = null,
  whitelistDates = null,
  whitelistFilenames = null,
  strictTimestampMatch = true
} = {}) {
  const normAria = normalizeAriaSpaces(ariaLabel);
  const pid = String(photoId || '').trim();
  const blIds = blacklistedPhotoIds instanceof Set
    ? blacklistedPhotoIds
    : new Set(blacklistedPhotoIds || []);
  const blArias = blacklistedAriaLabels instanceof Set
    ? new Set(Array.from(blacklistedAriaLabels, normalizeAriaSpaces))
    : new Set((blacklistedAriaLabels || []).map(normalizeAriaSpaces));

  // Layer 1: Hard block any photo ID or exact aria-label present in customer's pre-existing personal albums
  if (pid && blIds.has(pid)) {
    return { eligible: false, reason: 'blocked_by_personal_album_blacklist_id', layer: 1 };
  }
  if (normAria && blArias.has(normAria)) {
    return { eligible: false, reason: 'blocked_by_personal_album_blacklist_aria', layer: 1 };
  }

  // Layer 2: Hard block day-level "Select all photos from <Day>" checkboxes & enforce optional upload window
  if (isDayLevelSelectAllAria(normAria)) {
    return { eligible: false, reason: 'blocked_day_level_select_all', layer: 2 };
  }
  if (uploadWindow && uploadedAtMs !== undefined && uploadedAtMs !== null) {
    if (!isWithinUploadWindow(uploadedAtMs, uploadWindow)) {
      return { eligible: false, reason: 'outside_recently_added_upload_window', layer: 2 };
    }
  }

  // Layer 3: 1:1 Manifest Filename & Exact-Second Timestamp Whitelist Verification
  const fnList = whitelistFilenames ? Array.from(whitelistFilenames) : [];
  if (filename && fnList.length > 0) {
    const fnSet = new Set(fnList.map((f) => String(f).trim()));
    if (!fnSet.has(String(filename).trim())) {
      return { eligible: false, reason: 'filename_not_in_manifest_whitelist', layer: 3 };
    }
  }

  const tsList = whitelistTimestamps ? Array.from(whitelistTimestamps) : [];
  if (tsList.length > 0) {
    const matchedSecond = tsList.some((ts) => normAria.includes(normalizeAriaSpaces(ts)));
    if (matchedSecond) {
      return { eligible: true, reason: 'matched_manifest_timestamp_to_second', layer: 3 };
    }
    if (strictTimestampMatch) {
      return { eligible: false, reason: 'timestamp_not_in_manifest_whitelist', layer: 3 };
    }
  }

  const dtList = whitelistDates ? Array.from(whitelistDates) : [];
  if (dtList.length > 0) {
    const matchedDate = dtList.some((dt) => normAria.includes(normalizeAriaSpaces(dt)));
    if (!matchedDate) {
      return { eligible: false, reason: 'date_not_in_manifest_whitelist', layer: 3 };
    }
  }

  return { eligible: true, reason: 'passed_3_layer_archive_isolation_guard', layer: 3 };
}

/**
 * Layer 1 Live CDP Scanner (Strictly Read-Only):
 * Navigates to https://photos.google.com/albums, finds every customer album whose title does NOT
 * start with archiveAlbumPrefix, and scrolls each one read-only to collect blacklistedPhotoIds
 * and blacklistedAriaLabels. Never mutates or clicks destructive actions.
 */
async function collectPersonalAlbumBlacklistViaCDP(cdp, sessionId, options = {}) {
  const archiveAlbumPrefix = normalizeArchiveAlbumPrefix(options.archiveAlbumPrefix);
  const fastTest = Boolean(options.fastTest);
  const navWaitMs = Number.isFinite(options.navWaitMs) ? options.navWaitMs : (fastTest ? 10 : 3500);
  const waitForDomReady = options.waitForDomReady;
  const albumsUrl = options.albumsUrl || ALBUMS_URL;
  const maxScrollPasses = Number.isFinite(options.maxScrollPasses)
    ? options.maxScrollPasses
    : (fastTest ? 1 : 22);

  const blacklistedPhotoIds = new Set(options.seedPhotoIds || []);
  const blacklistedAriaLabels = new Set((options.seedAriaLabels || []).map(normalizeAriaSpaces));
  const personalAlbumUrls = new Set(options.personalAlbumUrls || []);
  const discoveredPersonalAlbums = [];
  const skippedArchiveAlbums = [];

  // 1. Discover all non-archive personal albums on https://photos.google.com/albums
  if (options.scanAlbumsPage !== false) {
    await cdp.send('Page.navigate', { url: albumsUrl }, sessionId);
    await sleep(navWaitMs);
    if (typeof waitForDomReady === 'function') {
      await waitForDomReady(cdp, sessionId);
    }

    const discovered = await cdp.evalJS(sessionId, `
      (() => {
        // Marker: discoverPersonalAlbumsOnAlbumsPage
        const out = [];
        const links = [...document.querySelectorAll('a[href*="/album/"], a[href*="/share/"]')];
        for (const a of links) {
          if (a.closest('nav, [role="navigation"]')) continue;
          const href = a.href;
          if (!href) continue;
          let card = a;
          while (card && card.parentElement) {
            const r = card.parentElement.getBoundingClientRect();
            if (r.width > 520 || r.height > 520) break;
            card = card.parentElement;
          }
          const lines = ((a.innerText || '') + '\\n' + (card ? (card.innerText || '') : ''))
            .split('\\n')
            .map(s => s.trim())
            .filter(Boolean);
          const title = lines[0] || '';
          out.push({ title, href });
        }
        return out;
      })()
    `);

    for (const item of (discovered || [])) {
      if (!item || !item.href) continue;
      const cleanHref = String(item.href).split('?')[0];
      if (isPersonalNonArchiveAlbumTitle(item.title, archiveAlbumPrefix)) {
        personalAlbumUrls.add(cleanHref);
        discoveredPersonalAlbums.push({ title: item.title, href: cleanHref });
      } else {
        skippedArchiveAlbums.push({ title: item.title, href: cleanHref });
      }
    }
  }

  // 2. Visit each personal album in strictly Read-Only mode to record all photoIds & aria-labels
  const scannedAlbums = [];
  for (const albumUrl of personalAlbumUrls) {
    try {
      await cdp.send('Page.navigate', { url: albumUrl }, sessionId);
      await sleep(navWaitMs);
      if (typeof waitForDomReady === 'function') {
        await waitForDomReady(cdp, sessionId);
      }

      const idsBefore = blacklistedPhotoIds.size;
      const ariasBefore = blacklistedAriaLabels.size;

      for (let pass = 0; pass < maxScrollPasses; pass++) {
        const snap = await cdp.evalJS(sessionId, `
          (() => {
            // Marker: collectPersonalAlbumPhotoIdsInDom
            const photoIds = [];
            const ariaLabels = [];
            const links = [...document.querySelectorAll('a[href*="/photo/"]')];
            for (const a of links) {
              const href = a.getAttribute('href') || '';
              const m = href.match(/\\/photo\\/([A-Za-z0-9_-]+)/);
              if (m) photoIds.push(m[1]);
              const aria = (a.getAttribute('aria-label') || '').trim();
              if (aria) ariaLabels.push(aria);
            }
            const cbs = [...document.querySelectorAll('[role="checkbox"]')];
            for (const cb of cbs) {
              const aria = (cb.getAttribute('aria-label') || '').trim();
              const lower = aria.toLowerCase();
              if (
                aria &&
                !lower.startsWith('select all') &&
                !lower.startsWith('เลือกรูปภาพทั้งหมด') &&
                !lower.startsWith('เลือกรายการทั้งหมด')
              ) {
                ariaLabels.push(aria);
              }
            }
            let moved = false;
            const beforeY = window.scrollY;
            window.scrollBy(0, 800);
            if (window.scrollY > beforeY) moved = true;
            const scrollers = [...document.querySelectorAll('c-wiz, [role="main"], div')].filter(
              el => el.scrollHeight > el.clientHeight + 100 && el.clientHeight > 300
            );
            for (const sc of scrollers) {
              const prev = sc.scrollTop;
              sc.scrollTop += 800;
              if (sc.scrollTop > prev) moved = true;
            }
            return { photoIds, ariaLabels, moved };
          })()
        `);

        for (const id of ((snap && snap.photoIds) || [])) {
          blacklistedPhotoIds.add(String(id).trim());
        }
        for (const aria of ((snap && snap.ariaLabels) || [])) {
          const norm = normalizeAriaSpaces(aria);
          if (norm) blacklistedAriaLabels.add(norm);
        }

        if (fastTest || !snap || !snap.moved) break;
        await sleep(260);
      }

      scannedAlbums.push({
        albumUrl,
        collectedIds: blacklistedPhotoIds.size - idsBefore,
        collectedAriaLabels: blacklistedAriaLabels.size - ariasBefore
      });
    } catch {}
  }

  return {
    archiveAlbumPrefix,
    blacklistedPhotoIds: Array.from(blacklistedPhotoIds),
    blacklistedAriaLabels: Array.from(blacklistedAriaLabels),
    discoveredPersonalAlbums,
    skippedArchiveAlbums,
    scannedAlbums
  };
}

module.exports = {
  DEFAULT_ARCHIVE_ALBUM_PREFIX,
  RECENTLY_ADDED_SEARCH_URL,
  ALBUMS_URL,
  DEFAULT_TIME_ZONES,
  SYSTEM_NON_PERSONAL_ALBUM_TITLES,
  normalizeArchiveAlbumPrefix,
  normalizeAriaSpaces,
  extractPhotoIdFromHref,
  isPersonalNonArchiveAlbumTitle,
  isDayLevelSelectAllAria,
  isWithinUploadWindow,
  filterRecentlyAddedItemsByUploadWindow,
  formatIsoToGooglePhotosAriaStrings,
  buildManifestTimestampWhitelist,
  isPhotoEligibleForArchiveAlbum,
  collectPersonalAlbumBlacklistViaCDP
};
