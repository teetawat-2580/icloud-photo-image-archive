'use strict';

const fs = require('fs');
const path = require('path');

const {
  DEFAULT_START_URL,
  validateCdpPort,
  validateIsolatedProfileDir,
  launchDedicatedChrome,
  SingleTargetCDP
} = require('./dedicated_chrome_manager');

const {
  DEFAULT_ARCHIVE_ALBUM_PREFIX,
  ALBUMS_URL,
  RECENTLY_ADDED_SEARCH_URL,
  normalizeArchiveAlbumPrefix,
  buildManifestTimestampWhitelist,
  collectPersonalAlbumBlacklistViaCDP
} = require('./personal_album_isolation_guard');

const DEFAULT_ALBUM_PREFIX = DEFAULT_ARCHIVE_ALBUM_PREFIX;
const GPHOTOS_ALBUM_HARD_LIMIT = 20000;
const DEFAULT_ALBUM_SOFT_SPLIT_LIMIT = 19500;
const DEFAULT_BATCH_SIZE = 100;
const MAX_MENU_ITEM_HEIGHT_PX = 68;

const BLOCKED_ADD_TO_MENU_KEYWORDS = [
  'animation', 'animated', 'collage', 'highlight', 'movie', 'cinematic', 'shared',
  'ภาพเคลื่อนไหว', 'ภาพปะติด', 'วิดีโอไฮไลต์', 'อัลบั้มที่แชร์'
];

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

function compressYearRanges(yearsInput) {
  const raw = Array.isArray(yearsInput) ? yearsInput : [yearsInput];
  const nums = Array.from(
    new Set(
      raw
        .map((y) => parseInt(String(y || '').trim().slice(0, 4), 10))
        .filter((n) => Number.isFinite(n) && n >= 1990 && n <= 2100)
    )
  ).sort((a, b) => a - b);

  if (nums.length === 0) return '';
  const ranges = [];
  let start = nums[0];
  let prev = nums[0];

  for (let i = 1; i < nums.length; i++) {
    const cur = nums[i];
    if (cur === prev + 1) {
      prev = cur;
    } else {
      ranges.push(start === prev ? `${start}` : `${start}-${prev}`);
      start = cur;
      prev = cur;
    }
  }
  ranges.push(start === prev ? `${start}` : `${start}-${prev}`);
  return ranges.join(', ');
}

function extractYearsFromBatch(batch, fallbackYears = []) {
  const found = [];
  if (Array.isArray(batch)) {
    for (const item of batch) {
      if (!item) continue;
      const src = String(item.yearFolder || item.year || item.created || item.created_at || item.path || '');
      const m = src.match(/\b(19\d{2}|20\d{2}|2100)\b/);
      if (m) found.push(parseInt(m[1], 10));
    }
  }
  if (found.length > 0) return Array.from(new Set(found)).sort((a, b) => a - b);
  return Array.isArray(fallbackYears) ? fallbackYears : [fallbackYears];
}

/**
 * Guard 1a: Multi-customer parameterized album title formatter.
 */
function formatArchiveAlbumTitle(albumPrefix, yearsInput, { partIndex = null, partLabel = 'Part' } = {}) {
  const prefix = normalizeArchiveAlbumPrefix(albumPrefix);
  const parsedPart = partIndex !== null && partIndex !== undefined ? parseInt(String(partIndex), 10) : null;
  const validPart = Number.isFinite(parsedPart) && parsedPart >= 1 ? parsedPart : null;
  const label = String(partLabel || 'Part').trim() || 'Part';
  const yearLabel = compressYearRanges(yearsInput);

  if (!yearLabel) return validPart ? `${prefix} (${label} ${validPart})` : prefix;
  if (validPart) return `${prefix} (${yearLabel} - ${label} ${validPart})`;
  return `${prefix} (${yearLabel})`;
}

/**
 * Guard 1b: Detects approaching Google Photos' 20,000 items/album hard limit (default soft split at 19,500).
 */
function shouldAutoSplitAlbum(
  currentAlbumItemCount = 0,
  incomingBatchCount = 0,
  { softSplitLimit = DEFAULT_ALBUM_SOFT_SPLIT_LIMIT, hardLimit = GPHOTOS_ALBUM_HARD_LIMIT, roomLeft = null } = {}
) {
  const cur = Math.max(0, Number(currentAlbumItemCount) || 0);
  const inc = Math.max(0, Number(incomingBatchCount) || 0);
  const effectiveSoft = Math.min(
    Math.max(1, Number(softSplitLimit) || DEFAULT_ALBUM_SOFT_SPLIT_LIMIT),
    Math.max(1, Number(hardLimit) || GPHOTOS_ALBUM_HARD_LIMIT)
  );

  if (roomLeft !== null && roomLeft !== undefined && Number.isFinite(Number(roomLeft))) {
    if (Number(roomLeft) <= 0 || Number(roomLeft) < inc) return true;
  }
  return cur >= effectiveSoft || (cur + inc) > effectiveSoft;
}

/**
 * Guard 1c: Stateful album naming & automatic 20k-ceiling splitter parameterized by customer albumPrefix.
 */
function nextAlbumTitleForState(state, batch = [], fallbackYears = [], reason = 'init', options = {}) {
  if (!state || typeof state !== 'object') {
    throw new Error('state object is required for nextAlbumTitleForState');
  }
  if (!state.partByYearKey) state.partByYearKey = {};
  if (!state.itemCountByYearKey) state.itemCountByYearKey = {};

  const albumPrefix = normalizeArchiveAlbumPrefix(
    options.albumPrefix || options.prefix || state.albumPrefix || DEFAULT_ALBUM_PREFIX
  );
  const softSplitLimit = Number.isFinite(options.softSplitLimit)
    ? options.softSplitLimit
    : DEFAULT_ALBUM_SOFT_SPLIT_LIMIT;
  const hardLimit = Number.isFinite(options.hardLimit) ? options.hardLimit : GPHOTOS_ALBUM_HARD_LIMIT;
  const partLabel = options.partLabel || 'Part';

  const years = extractYearsFromBatch(batch, fallbackYears);
  const yearKey = compressYearRanges(years) || 'archive';
  const hasExistingPart = Object.prototype.hasOwnProperty.call(state.partByYearKey, yearKey);
  const prevPart = state.partByYearKey[yearKey] || 1;
  const incomingCount = Number.isFinite(options.incomingBatchCount)
    ? options.incomingBatchCount
    : (Array.isArray(batch) ? batch.length : 0);

  const trackedCount = Number.isFinite(state.itemCountByYearKey[yearKey])
    ? state.itemCountByYearKey[yearKey]
    : (state.currentAlbumYearKey === yearKey ? (Number(state.currentAlbumItemCount) || 0) : 0);

  const ceilingTriggered =
    hasExistingPart &&
    shouldAutoSplitAlbum(trackedCount, incomingCount, {
      softSplitLimit,
      hardLimit,
      roomLeft: options.roomLeft
    });

  const shouldIncrementPart = hasExistingPart && (reason === 'overflow' || ceilingTriggered);
  const nextPart = shouldIncrementPart ? prevPart + 1 : prevPart;

  state.albumPrefix = albumPrefix;
  state.partByYearKey[yearKey] = nextPart;
  state.currentAlbumYearKey = yearKey;
  state.itemCountByYearKey[yearKey] = (shouldIncrementPart || !hasExistingPart) ? 0 : trackedCount;
  state.currentAlbumItemCount = state.itemCountByYearKey[yearKey];

  const usePart = Boolean(options.alwaysNumberParts) || nextPart > 1;
  const title = formatArchiveAlbumTitle(albumPrefix, years, {
    partIndex: usePart ? nextPart : null,
    partLabel
  });
  state.currentAlbumTitle = title;
  return title;
}

/**
 * Guard 2: Strict Single-Line Album Menu Item Isolation.
 * Hard-blocks Animation, Collage, Highlight video, Movie, Cinematic, Shared album,
 * multi-line container divs, and tall rows (height > 68px).
 */
function pickSafeAlbumMenuItemFromDomRecords(records = []) {
  if (!Array.isArray(records) || records.length === 0) return { found: false };

  const matches = [];
  for (const rec of records) {
    if (!rec || typeof rec !== 'object') continue;

    const rawText = String(rec.text ?? rec.innerText ?? '');
    const rawAria = String(rec.ariaLabel ?? rec.aria ?? '');
    const rawAncestorText = String(rec.ancestorText ?? rawText);
    const rawAncestorAria = String(rec.ancestorAriaLabel ?? '');
    const fullLower = `${rawText} ${rawAria} ${rawAncestorText} ${rawAncestorAria}`.toLowerCase();

    if (BLOCKED_ADD_TO_MENU_KEYWORDS.some((kw) => fullLower.includes(kw))) continue;

    const lines = rawText.split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean);
    const ancestorLines = rawAncestorText.split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean);
    const ariaLower = rawAria.trim().toLowerCase();

    if (ancestorLines.length > 1 || lines.length > 1) continue;

    const isExactSingleLineAlbum =
      (lines.length === 1 && (lines[0] === 'album' || lines[0] === 'อัลบั้ม')) ||
      (lines.length === 0 && (ariaLower === 'album' || ariaLower === 'อัลบั้ม'));
    if (!isExactSingleLineAlbum) continue;

    const rect = rec.rect && typeof rec.rect === 'object' ? rec.rect : rec;
    const left = Number(rect.left);
    const top = Number(rect.top);
    const width = Number(rect.width);
    const height = Number(rect.height);

    if (!Number.isFinite(left) || !Number.isFinite(top) || !Number.isFinite(width) || !Number.isFinite(height)) {
      continue;
    }
    if (width <= 15 || height <= 10 || height > MAX_MENU_ITEM_HEIGHT_PX || top <= 20 || top >= 550) {
      continue;
    }

    matches.push({
      x: left + width / 2,
      y: top + height / 2,
      top,
      area: width * height,
      label: lines[0] || ariaLower,
      record: rec
    });
  }

  if (matches.length === 0) return { found: false };
  matches.sort((a, b) => (a.top - b.top) || (a.area - b.area));
  return { found: true, ...matches[0] };
}

/**
 * Guard 3: Strict 100% Selection Completeness Gate.
 * Blocks any sub-album container deletion if selectedCount < requiredCount.
 */
function enforceSelectionCompletenessGate(selectedCount, requiredCount, context = {}) {
  const sel = Number(selectedCount);
  const req = Number(requiredCount);

  if (!Number.isFinite(req) || req <= 0) {
    return {
      allowed: false,
      selectedCount: Number.isFinite(sel) ? sel : 0,
      requiredCount: Number.isFinite(req) ? req : 0,
      missingCount: 0,
      reason: 'invalid_required_count_blocked_before_delete',
      ...context
    };
  }
  if (!Number.isFinite(sel) || sel <= 0) {
    return {
      allowed: false,
      selectedCount: 0,
      requiredCount: req,
      missingCount: req,
      reason: 'zero_items_selected_blocked_before_delete',
      ...context
    };
  }
  if (sel < req) {
    return {
      allowed: false,
      selectedCount: sel,
      requiredCount: req,
      missingCount: req - sel,
      reason: 'incomplete_selection_blocked_before_delete',
      ...context
    };
  }
  return {
    allowed: true,
    selectedCount: sel,
    requiredCount: req,
    missingCount: 0,
    reason: 'selection_complete_100_percent',
    ...context
  };
}

/**
 * Guard 4: Atomic Checkpointing inside customer's job sandbox.
 */
function sanitizeJobId(jobId) {
  const cleaned = String(jobId || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(cleaned)) {
    throw new Error(`Invalid jobId "${jobId}": only alphanumeric, hyphen, and underscore characters allowed`);
  }
  return cleaned;
}

function getJobCheckpointPath(sandboxDir, jobId) {
  if (typeof sandboxDir !== 'string' || !sandboxDir.trim()) {
    throw new Error('sandboxDir is required to locate job checkpoint');
  }
  const safeId = sanitizeJobId(jobId);
  const resolvedSandbox = path.resolve(sandboxDir.trim());
  const candidate = path.resolve(resolvedSandbox, `${safeId}.checkpoint.json`);
  const rel = path.relative(resolvedSandbox, candidate);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('Checkpoint path escaped job sandbox directory');
  }
  return candidate;
}

function saveJobCheckpoint(checkpointPath, state) {
  if (typeof checkpointPath !== 'string' || !checkpointPath.trim()) {
    throw new Error('checkpointPath is required');
  }
  const resolvedPath = path.resolve(checkpointPath.trim());
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

  const payload = {
    ...(state && typeof state === 'object' ? state : {}),
    updated_at: new Date().toISOString()
  };
  const tmpPath = `${resolvedPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), 'utf8');

  let lastErr = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      fs.renameSync(tmpPath, resolvedPath);
      return { ok: true, path: resolvedPath, updated_at: payload.updated_at };
    } catch (err) {
      lastErr = err;
    }
  }
  try { fs.unlinkSync(tmpPath); } catch {}
  throw new Error(`Failed atomic checkpoint rename to "${resolvedPath}": ${lastErr && lastErr.message}`);
}

function loadJobCheckpoint(checkpointPath, fallback = null) {
  if (typeof checkpointPath !== 'string' || !checkpointPath.trim()) return fallback;
  const resolvedPath = path.resolve(checkpointPath.trim());
  if (!fs.existsSync(resolvedPath)) return fallback;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const raw = fs.readFileSync(resolvedPath, 'utf8').replace(/^\uFEFF/, '');
      return JSON.parse(raw);
    } catch {}
  }
  return fallback;
}

function collectPendingItemsFromManifest(manifest, checkpoint = null, { verifyExists = true } = {}) {
  const uploadedIds = new Set((checkpoint && checkpoint.uploaded_ids) || []);
  const uploadedPaths = new Set((checkpoint && checkpoint.uploaded_paths) || []);
  const pending = [];
  let totalCount = 0;

  const pushItem = (f, yearHint = '', monthHint = '') => {
    if (!f || typeof f !== 'object') return;
    totalCount++;
    const fileId = f.id ? String(f.id) : '';
    const filePath = f.path ? String(f.path) : '';
    const done =
      Boolean(f.gphotos_uploaded) ||
      (fileId && uploadedIds.has(fileId)) ||
      (filePath && uploadedPaths.has(filePath));
    if (done) return;
    if (verifyExists && (!filePath || !fs.existsSync(filePath))) return;

    pending.push({
      id: fileId,
      path: filePath,
      filename: String(f.filename || path.basename(filePath || '')),
      created: f.created || f.created_at || f.date_taken || '',
      yearFolder: String(f.yearFolder || yearHint || ''),
      month: String(f.month || monthHint || ''),
      size: Number(f.size) || 0
    });
  };

  if (Array.isArray(manifest)) {
    for (const f of manifest) pushItem(f);
  } else if (manifest && typeof manifest === 'object') {
    if (manifest.years && typeof manifest.years === 'object') {
      for (const yearKey of Object.keys(manifest.years).sort()) {
        const yObj = manifest.years[yearKey];
        if (!yObj || typeof yObj !== 'object') continue;
        if (yObj.months && typeof yObj.months === 'object') {
          for (const monthKey of Object.keys(yObj.months).sort()) {
            const mObj = yObj.months[monthKey];
            for (const f of ((mObj && mObj.files) || [])) pushItem(f, yearKey, monthKey);
          }
        }
        if (Array.isArray(yObj.files)) {
          for (const f of yObj.files) pushItem(f, yearKey);
        }
      }
    }
    if (Array.isArray(manifest.files)) {
      for (const f of manifest.files) pushItem(f);
    }
  }

  return { totalCount, pending };
}

async function waitForPhotosDomReady(cdp, sessionId, { maxAttempts = 30, intervalMs = 1000 } = {}) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const info = await cdp.evalJS(sessionId, `
        (() => ({
          host: location.hostname,
          href: location.href,
          readyState: document.readyState,
          cwizCount: document.querySelectorAll('c-wiz').length
        }))()
      `);
      if (info && info.host === 'photos.google.com' && info.readyState === 'complete' && info.cwizCount > 0) {
        return info;
      }
    } catch {}
    await sleep(intervalMs);
  }
  throw new Error('Timed out waiting for Google Photos DOM to become ready');
}

async function installUploadNetworkTracker(cdp, sessionId, { jobId = 'default' } = {}) {
  await cdp.evalJS(sessionId, `
    (() => {
      window.__cvJobId = ${JSON.stringify(String(jobId))};
      if (window.__cvTrackerInstalled) return true;
      window.__cvTrackerInstalled = true;
      window.__cvActiveUploads = 0;
      window.__cvCompletedUploads = 0;
      window.__cvLastActivityTs = Date.now();
      const origFetch = window.fetch;
      if (origFetch) {
        window.fetch = async function(...args) {
          const url = String((args[0] && args[0].url) || args[0] || '');
          const isUp = url.includes('upload') || url.includes('PhotosUi') || url.includes('batchexecute') || url.includes('googleusercontent');
          if (isUp) { window.__cvActiveUploads++; window.__cvLastActivityTs = Date.now(); }
          try { return await origFetch.apply(this, args); }
          finally {
            if (isUp) {
              window.__cvActiveUploads = Math.max(0, window.__cvActiveUploads - 1);
              window.__cvCompletedUploads++;
              window.__cvLastActivityTs = Date.now();
            }
          }
        };
      }
      const origOpen = XMLHttpRequest.prototype.open;
      const origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this.__cvMethod = String(method || '').toUpperCase();
        return origOpen.call(this, method, url, ...rest);
      };
      XMLHttpRequest.prototype.send = function(body) {
        if (this.__cvMethod === 'POST' || this.__cvMethod === 'PUT') {
          window.__cvActiveUploads++;
          window.__cvLastActivityTs = Date.now();
          this.addEventListener('loadend', () => {
            window.__cvActiveUploads = Math.max(0, window.__cvActiveUploads - 1);
            window.__cvCompletedUploads++;
            window.__cvLastActivityTs = Date.now();
          });
        }
        return origSend.call(this, body);
      };
      return true;
    })()
  `);
}

async function clearPreviousToastViaCDP(cdp, sessionId) {
  await cdp.evalJS(sessionId, `
    (() => {
      for (const b of document.querySelectorAll('button, [role="button"]')) {
        const t = (b.innerText || '').trim();
        const aria = (b.getAttribute('aria-label') || '').trim();
        if (['Done', 'เสร็จสิ้น', 'ปิด', 'OK', 'ตกลง'].includes(t) || ['Close', 'ปิด'].includes(aria)) {
          try { b.click(); } catch {}
        }
      }
      window.__cvCompletedUploads = 0;
      window.__cvActiveUploads = 0;
      return true;
    })()
  `);
}

async function dropBatchNativeViaCDP(cdp, sessionId, batchItems, { jobId = 'job' } = {}) {
  const inputId = `__cv_native_file_input_${sanitizeJobId(jobId)}`;
  const filePaths = batchItems.map((x) => x.path);

  const evalRes = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const id = ${JSON.stringify(inputId)};
      let inp = document.getElementById(id);
      if (inp) inp.remove();
      inp = document.createElement('input');
      inp.id = id; inp.type = 'file'; inp.multiple = true; inp.style.display = 'none';
      document.body.appendChild(inp);
      return inp;
    })()`,
    returnByValue: false
  }, sessionId);

  const objectId = evalRes && evalRes.result && evalRes.result.objectId;
  if (!objectId) throw new Error(`Could not create synthetic file input #${inputId}`);

  await cdp.send('DOM.setFileInputFiles', { objectId, files: filePaths }, sessionId);

  return await cdp.evalJS(sessionId, `
    (() => {
      const inp = document.getElementById(${JSON.stringify(inputId)});
      if (!inp || !inp.files || inp.files.length === 0) return { ok: false, count: 0 };
      const dt = new DataTransfer();
      for (const f of inp.files) dt.items.add(f);
      const cwizList = [...document.querySelectorAll('c-wiz')].filter(el => el.offsetWidth > 300 && el.offsetHeight > 200);
      cwizList.sort((a, b) => (b.offsetWidth * b.offsetHeight) - (a.offsetWidth * a.offsetHeight));
      const target = cwizList[0] || document.querySelector('[role="main"]') || document.body;
      for (const evType of ['dragenter', 'dragover', 'drop']) {
        target.dispatchEvent(new DragEvent(evType, { bubbles: true, cancelable: true, composed: true, dataTransfer: dt }));
      }
      inp.value = '';
      return { ok: true, count: dt.files.length };
    })()
  `);
}

async function readUploadStatusViaCDP(cdp, sessionId) {
  return await cdp.evalJS(sessionId, `
    (() => {
      const txt = document.body ? document.body.innerText : '';
      const keys = ['Preparing', 'Backing up', 'backed up', 'Uploading', 'Uploaded', 'Adding', 'Added',
        'You have room for', 'พื้นที่เหลือสำหรับ', 'กำลังเตรียม', 'กำลังสำรองข้อมูล', 'สำรองข้อมูลแล้ว',
        'กำลังอัปโหลด', 'อัปโหลดแล้ว', 'กำลังเพิ่ม'];
      const snippet = txt.split('\\n').filter(l => keys.some(k => l.includes(k))).slice(0, 8).join(' | ');
      const isPreparing = snippet.includes('Preparing') || snippet.includes('กำลังเตรียม');
      const isUploading = isPreparing || ['Backing up', 'Uploading', 'Adding', 'กำลังสำรองข้อมูล', 'กำลังอัปโหลด', 'กำลังเพิ่ม'].some(k => snippet.includes(k));
      const hasFinished = ['backed up', 'Uploaded', 'Added', 'สำรองข้อมูลแล้ว', 'อัปโหลดแล้ว'].some(k => snippet.includes(k));
      const roomMatch = snippet.match(/You have room for (\\d+) more item/i) || snippet.match(/พื้นที่เหลือสำหรับอีก\\s*(\\d+)\\s*รายการ/);
      return {
        isPreparing,
        isUploading,
        hasFinished,
        roomLeft: roomMatch ? parseInt(roomMatch[1], 10) : null,
        activeXhr: window.__cvActiveUploads || 0,
        completedXhr: window.__cvCompletedUploads || 0,
        idleMs: Date.now() - (window.__cvLastActivityTs || Date.now()),
        snippet
      };
    })()
  `);
}

async function findAlbumMenuItemViaCDP(cdp, sessionId) {
  const domRecords = await cdp.evalJS(sessionId, `
    (() => [...document.querySelectorAll('[role="menuitem"], [role="option"], li, button, [role="button"], div, span')].map((el) => {
      const menuAncestor = el.closest('[role="menuitem"], [role="option"], li') || el;
      const r = el.getBoundingClientRect();
      return {
        text: el.innerText || '',
        ariaLabel: el.getAttribute('aria-label') || '',
        ancestorText: menuAncestor.innerText || '',
        ancestorAriaLabel: (menuAncestor.getAttribute && menuAncestor.getAttribute('aria-label')) || '',
        rect: { left: r.left, top: r.top, width: r.width, height: r.height }
      };
    }))()
  `);
  return pickSafeAlbumMenuItemFromDomRecords(domRecords || []);
}

async function setAlbumTitleViaCDP(cdp, sessionId, albumTitle, options = {}) {
  if (!albumTitle) return false;
  const archivePrefixLower = String(options.albumPrefix || DEFAULT_ALBUM_PREFIX).trim().toLowerCase();

  const box = await cdp.evalJS(sessionId, `
    (() => {
      const prefixLower = ${JSON.stringify(archivePrefixLower)};
      const isSearch = (el) => {
        const a = ((el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('name') || '')).toLowerCase();
        return a.includes('search') || a.includes('ค้นหา') || Boolean(el.closest('[role="search"], form[role="search"]'));
      };
      const selectors = [
        'textarea[aria-label*="title" i]', 'input[aria-label*="title" i]',
        'textarea[placeholder*="title" i]', 'input[placeholder*="title" i]',
        'textarea[aria-label*="ชื่อ" i]', 'input[aria-label*="ชื่อ" i]',
        '[aria-label="Edit album title" i]', '[aria-label="Add a title" i]',
        '[aria-label="แก้ไขชื่ออัลบั้ม" i]', '[aria-label="เพิ่มชื่อ" i]'
      ];
      for (const sel of selectors) {
        for (const el of document.querySelectorAll(sel)) {
          if (isSearch(el)) continue;
          const r = el.getBoundingClientRect();
          if (r.width > 10 && r.height > 10 && r.top > 70 && r.top < 550) {
            el.focus();
            return { found: true, x: r.left + Math.min(40, r.width / 2), y: r.top + r.height / 2 };
          }
        }
      }
      const fallbacks = new Set(['add a title', 'เพิ่มชื่อ', 'untitled album', 'อัลบั้มไม่มีชื่อ']);
      for (const el of document.querySelectorAll('h1, h2, [role="heading"], div, span, [role="button"]')) {
        if (el.children && el.children.length > 2) continue;
        const t = (el.innerText || el.textContent || '').trim().toLowerCase();
        if (fallbacks.has(t) || (prefixLower && t.startsWith(prefixLower)) || t.startsWith('tmp_merge_')) {
          const r = el.getBoundingClientRect();
          if (r.width > 15 && r.height > 10 && r.top >= 50 && r.top < 580) {
            return { found: true, x: r.left + Math.min(60, r.width / 2), y: r.top + r.height / 2 };
          }
        }
      }
      return { found: false };
    })()
  `);

  if (!box || !box.found) return false;
  if (typeof cdp.trustedClick === 'function') await cdp.trustedClick(sessionId, box.x, box.y);
  await sleep(160);

  await cdp.evalJS(sessionId, `(() => {
    const el = document.activeElement;
    if (el && ('value' in el)) { el.value = ''; el.dispatchEvent(new Event('input', { bubbles: true })); }
    else if (el && el.isContentEditable) { el.textContent = ''; el.dispatchEvent(new Event('input', { bubbles: true })); }
    return true;
  })()`);

  await cdp.send('Input.insertText', { text: albumTitle }, sessionId);
  await sleep(160);
  await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 }, sessionId);
  await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 }, sessionId);
  await sleep(250);
  return true;
}

/**
 * Generalized sub-album merger combining Guard 2 (Single-Line Album Menu Isolation)
 * and Guard 3 (100% Selection Completeness Gate before deleting the redundant source container).
 */
async function mergeSubAlbumIntoTargetViaCDP(cdp, sessionId, planItem, options = {}) {
  const fastTest = Boolean(options.fastTest);
  await cdp.send('Page.navigate', { url: planItem.sourceUrl }, sessionId);
  await sleep(fastTest ? 10 : 3500);

  const sourceInfo = await cdp.evalJS(sessionId, `(() => {
    const txt = document.body ? (document.body.innerText || '') : '';
    const m = txt.match(/(\\d[\\d,]*)\\s*(items|item|รายการ)/i);
    const parsed = m ? parseInt(m[1].replace(/,/g, ''), 10) : 0;
    return { itemCount: parsed > 0 ? parsed : document.querySelectorAll('[role="checkbox"]').length };
  })()`);

  const selInfo = await cdp.evalJS(sessionId, `(() => {
    const txt = document.body ? (document.body.innerText || '') : '';
    const m = txt.match(/(\\d[\\d,]*)\\s*selected/i) || txt.match(/เลือกไว้\\s*(\\d[\\d,]*)/i);
    return { selectedCount: m ? parseInt(m[1].replace(/,/g, ''), 10) : document.querySelectorAll('[role="checkbox"][aria-checked="true"]').length };
  })()`);

  const requiredCount = Math.max(Number(planItem.expectedItems) || 0, Number(sourceInfo && sourceInfo.itemCount) || 0);
  const selectedCount = Number(selInfo && selInfo.selectedCount) || 0;
  const gate = enforceSelectionCompletenessGate(selectedCount, requiredCount, {
    sourceUrl: planItem.sourceUrl,
    targetUrl: planItem.targetUrl,
    targetTitle: planItem.targetTitle
  });

  if (!gate.allowed) return { merged: false, deletedSource: false, ...gate };

  const albumMenuItem = await findAlbumMenuItemViaCDP(cdp, sessionId);
  if (!albumMenuItem.found) {
    return {
      merged: false,
      deletedSource: false,
      selectedCount,
      requiredCount,
      reason: 'safe_single_line_album_menu_item_not_found'
    };
  }

  if (typeof cdp.trustedClick === 'function') {
    await cdp.trustedClick(sessionId, albumMenuItem.x, albumMenuItem.y);
  }
  await sleep(fastTest ? 10 : 750);

  return {
    merged: true,
    deletedSource: false,
    selectedCount,
    requiredCount,
    menuItemClicked: albumMenuItem.label,
    sourceUrl: planItem.sourceUrl,
    targetTitle: planItem.targetTitle
  };
}

/**
 * End-to-end dedicated Chrome profile CDP uploader for a CloudVault Concierge customer job.
 */
async function uploadJobViaCDP({
  jobId,
  profileDir,
  cdpPort,
  manifestPath,
  albumPrefix = DEFAULT_ALBUM_PREFIX,
  chromePath = '',
  sandboxDir = '',
  batchSize = DEFAULT_BATCH_SIZE,
  softSplitLimit = DEFAULT_ALBUM_SOFT_SPLIT_LIMIT,
  startUrl = DEFAULT_START_URL,
  dryRun = false
} = {}) {
  const safeJobId = sanitizeJobId(jobId);
  const resolvedProfileDir = validateIsolatedProfileDir(profileDir);
  const port = validateCdpPort(cdpPort);
  const prefix = normalizeArchiveAlbumPrefix(albumPrefix);
  const resolvedSandbox = sandboxDir ? path.resolve(sandboxDir) : path.dirname(resolvedProfileDir);
  const checkpointPath = getJobCheckpointPath(resolvedSandbox, safeJobId);

  if (!manifestPath || !fs.existsSync(manifestPath)) {
    throw new Error(`Manifest file not found: "${manifestPath}"`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8').replace(/^\uFEFF/, ''));
  const existingCheckpoint = loadJobCheckpoint(checkpointPath, {
    job_id: safeJobId,
    album_prefix: prefix,
    uploaded_ids: [],
    uploaded_paths: [],
    partByYearKey: {},
    itemCountByYearKey: {},
    currentAlbumYearKey: '',
    currentAlbumItemCount: 0,
    currentAlbumTitle: ''
  });

  const { totalCount, pending } = collectPendingItemsFromManifest(manifest, existingCheckpoint, {
    verifyExists: !dryRun
  });
  const whitelist = buildManifestTimestampWhitelist(manifest);

  if (dryRun) {
    return {
      dryRun: true,
      jobId: safeJobId,
      profileDir: resolvedProfileDir,
      cdpPort: port,
      albumPrefix: prefix,
      checkpointPath,
      totalCount,
      pendingCount: pending.length,
      whitelistedTimestampCount: whitelist.whitelistTimestamps.size
    };
  }

  const chrome = await launchDedicatedChrome({ chromePath, profileDir: resolvedProfileDir, cdpPort: port, startUrl });
  const cdp = new SingleTargetCDP(chrome.wsUrl);

  try {
    await cdp.connect();
    const targetsRes = await cdp.send('Target.getTargets', {});
    const targets = (targetsRes && targetsRes.targetInfos) || [];
    const pageTarget =
      targets.find((t) => t.type === 'page' && typeof t.url === 'string' && t.url.startsWith('https://photos.google.com')) ||
      targets.find((t) => t.type === 'page');
    if (!pageTarget) throw new Error('No page target found in dedicated Chrome instance');

    const sessionId = await cdp.attachToTarget(pageTarget.targetId);
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('DOM.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);

    // Layer 1 strictly read-only scan of pre-existing personal albums before any uploads
    const blacklistSnapshot = await collectPersonalAlbumBlacklistViaCDP(cdp, sessionId, {
      archiveAlbumPrefix: prefix,
      albumsUrl: ALBUMS_URL,
      waitForDomReady: waitForPhotosDomReady
    });

    await cdp.send('Page.navigate', { url: DEFAULT_START_URL }, sessionId);
    await waitForPhotosDomReady(cdp, sessionId);
    await installUploadNetworkTracker(cdp, sessionId, { jobId: safeJobId });

    const state = {
      ...existingCheckpoint,
      job_id: safeJobId,
      album_prefix: prefix,
      personal_blacklist_count: blacklistSnapshot.blacklistedPhotoIds.length,
      recently_added_url: RECENTLY_ADDED_SEARCH_URL
    };
    const uploadedIdSet = new Set(state.uploaded_ids || []);
    const uploadedPathSet = new Set(state.uploaded_paths || []);
    const effectiveBatchSize = Math.max(1, Number(batchSize) || DEFAULT_BATCH_SIZE);

    for (let offset = 0; offset < pending.length; offset += effectiveBatchSize) {
      const batch = pending.slice(offset, offset + effectiveBatchSize);
      const targetTitle = nextAlbumTitleForState(state, batch, [], offset === 0 ? 'init' : 'batch', {
        albumPrefix: prefix,
        softSplitLimit
      });

      await clearPreviousToastViaCDP(cdp, sessionId);
      const dropInfo = await dropBatchNativeViaCDP(cdp, sessionId, batch, { jobId: safeJobId });
      if (!dropInfo || !dropInfo.ok) {
        throw new Error(`Batch drop failed at offset ${offset} for album "${targetTitle}"`);
      }

      const deadline = Date.now() + 600000;
      let sawActivity = false;
      while (Date.now() < deadline) {
        await sleep(2000);
        const status = await readUploadStatusViaCDP(cdp, sessionId);
        if (status.isUploading || status.activeXhr > 0 || status.completedXhr > 0) sawActivity = true;
        if (status.roomLeft !== null && status.roomLeft < batch.length && !status.isUploading) {
          nextAlbumTitleForState(state, batch, [], 'overflow', {
            albumPrefix: prefix,
            softSplitLimit,
            roomLeft: status.roomLeft
          });
          break;
        }
        if (sawActivity && !status.isUploading && status.activeXhr === 0 && (status.hasFinished || status.idleMs >= 4500)) {
          break;
        }
      }

      for (const item of batch) {
        if (item.id) uploadedIdSet.add(item.id);
        if (item.path) uploadedPathSet.add(item.path);
      }
      const yKey = state.currentAlbumYearKey || 'archive';
      state.itemCountByYearKey[yKey] = (state.itemCountByYearKey[yKey] || 0) + batch.length;
      state.currentAlbumItemCount = state.itemCountByYearKey[yKey];
      state.uploaded_ids = Array.from(uploadedIdSet);
      state.uploaded_paths = Array.from(uploadedPathSet);
      saveJobCheckpoint(checkpointPath, state);
    }

    return {
      ok: true,
      jobId: safeJobId,
      albumPrefix: prefix,
      uploadedCount: uploadedIdSet.size || uploadedPathSet.size,
      totalCount,
      checkpointPath,
      personalBlacklistCount: blacklistSnapshot.blacklistedPhotoIds.length
    };
  } finally {
    await cdp.detach().catch(() => {});
    await chrome.shutdown().catch(() => {});
  }
}

function parseCliArgs(argv = process.argv.slice(2)) {
  const out = {
    jobId: '',
    profileDir: '',
    cdpPort: null,
    manifestPath: '',
    albumPrefix: DEFAULT_ALBUM_PREFIX,
    chromePath: '',
    sandboxDir: '',
    batchSize: DEFAULT_BATCH_SIZE,
    softSplitLimit: DEFAULT_ALBUM_SOFT_SPLIT_LIMIT,
    dryRun: false,
    help: false
  };

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--help' || token === '-h') { out.help = true; continue; }
    if (token === '--dry-run') { out.dryRun = true; continue; }
    const next = argv[i + 1];
    if (token === '--job-id' && next !== undefined) { out.jobId = next; i++; }
    else if (token === '--profile-dir' && next !== undefined) { out.profileDir = next; i++; }
    else if (token === '--cdp-port' && next !== undefined) { out.cdpPort = Number(next); i++; }
    else if (token === '--manifest' && next !== undefined) { out.manifestPath = next; i++; }
    else if (token === '--album-prefix' && next !== undefined) { out.albumPrefix = next; i++; }
    else if (token === '--chrome-path' && next !== undefined) { out.chromePath = next; i++; }
    else if (token === '--sandbox-dir' && next !== undefined) { out.sandboxDir = next; i++; }
    else if (token === '--batch-size' && next !== undefined) { out.batchSize = Number(next); i++; }
    else if (token === '--soft-split-limit' && next !== undefined) { out.softSplitLimit = Number(next); i++; }
  }
  return out;
}

if (require.main === module) {
  const parsed = parseCliArgs(process.argv.slice(2));
  if (parsed.help || !parsed.jobId || !parsed.profileDir || !parsed.cdpPort || !parsed.manifestPath) {
    console.log(
      'Usage: node gphotos_uploader.js --job-id <id> --profile-dir <isolated_dir> ' +
      '--cdp-port <9301-9399> --manifest <manifest.json> [--album-prefix <prefix>] ' +
      '[--sandbox-dir <dir>] [--chrome-path <exe>] [--batch-size 100] [--soft-split-limit 19500] [--dry-run]'
    );
    process.exit(parsed.help ? 0 : 1);
  }
  uploadJobViaCDP(parsed)
    .then((summary) => { console.log(JSON.stringify(summary, null, 2)); process.exit(0); })
    .catch((err) => { console.error(`[CloudVault CDP Uploader Error] ${err.message}`); process.exit(1); });
}

module.exports = {
  DEFAULT_ALBUM_PREFIX,
  GPHOTOS_ALBUM_HARD_LIMIT,
  DEFAULT_ALBUM_SOFT_SPLIT_LIMIT,
  DEFAULT_BATCH_SIZE,
  MAX_MENU_ITEM_HEIGHT_PX,
  BLOCKED_ADD_TO_MENU_KEYWORDS,
  compressYearRanges,
  extractYearsFromBatch,
  formatArchiveAlbumTitle,
  shouldAutoSplitAlbum,
  nextAlbumTitleForState,
  pickSafeAlbumMenuItemFromDomRecords,
  enforceSelectionCompletenessGate,
  sanitizeJobId,
  getJobCheckpointPath,
  saveJobCheckpoint,
  loadJobCheckpoint,
  collectPendingItemsFromManifest,
  waitForPhotosDomReady,
  installUploadNetworkTracker,
  clearPreviousToastViaCDP,
  dropBatchNativeViaCDP,
  readUploadStatusViaCDP,
  findAlbumMenuItemViaCDP,
  setAlbumTitleViaCDP,
  mergeSubAlbumIntoTargetViaCDP,
  uploadJobViaCDP,
  parseCliArgs
};
