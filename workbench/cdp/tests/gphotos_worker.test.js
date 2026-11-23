'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const { webcrypto } = require('crypto');

const chromeManager = require('../dedicated_chrome_manager');
const isolationGuard = require('../personal_album_isolation_guard');
const uploader = require('../gphotos_uploader');

// ============================================================================
// 1. Dedicated Chrome Manager: Isolated Profile, Port Guard & SingleTargetCDP
// ============================================================================

test('buildDedicatedChromeLaunchArgs rejects default Chrome/Edge User Data paths and out-of-range ports', () => {
  const forbiddenPaths = [
    'C:\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data',
    'C:\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default',
    'C:\\Users\\Bob\\AppData\\Local\\Microsoft\\Edge\\User Data',
    '/Users/alice/Library/Application Support/Google/Chrome',
    '/home/alice/.config/google-chrome',
    ''
  ];

  for (const badPath of forbiddenPaths) {
    assert.throws(
      () => chromeManager.buildDedicatedChromeLaunchArgs({
        profileDir: badPath,
        cdpPort: 9301
      }),
      /default\/system browser profile|non-empty string/i,
      `Expected default browser profile path "${badPath}" to be rejected`
    );
  }

  const invalidPorts = [9222, 9300, 9400, 0, -1, 9305.5, '9301abc', '', null, undefined];
  const safeProfile = path.join(os.tmpdir(), 'cloudvault-test-profile-job-01');

  for (const badPort of invalidPorts) {
    assert.throws(
      () => chromeManager.buildDedicatedChromeLaunchArgs({
        profileDir: safeProfile,
        cdpPort: badPort
      }),
      RangeError,
      `Expected out-of-range or malformed port "${badPort}" to be rejected`
    );
  }
});

test('buildDedicatedChromeLaunchArgs builds clean isolated --user-data-dir and --remote-debugging-port args', () => {
  const safeProfile = path.join(os.tmpdir(), 'cloudvault-sandboxes', 'job-9001', 'chrome_profile');
  const args = chromeManager.buildDedicatedChromeLaunchArgs({
    profileDir: safeProfile,
    cdpPort: 9315,
    startUrl: 'https://photos.google.com/'
  });

  assert.equal(args[0], `--user-data-dir=${path.resolve(safeProfile)}`);
  assert.equal(args[1], '--remote-debugging-port=9315');
  assert.ok(args.includes('--no-first-run'));
  assert.ok(args.includes('--no-default-browser-check'));
  assert.ok(args.includes('--disable-default-apps'));
  assert.equal(args[args.length - 1], 'https://photos.google.com/');

  assert.throws(
    () => chromeManager.buildDedicatedChromeLaunchArgs({
      profileDir: safeProfile,
      cdpPort: 9315,
      extraArgs: ['--user-data-dir=C:\\hijack']
    }),
    /must not override isolated flag/i
  );
});

test('launchDedicatedChrome spawns without shell, polls /json/version, and tears down cleanly', async () => {
  const tmpProfile = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-launch-test-'));
  let capturedSpawn = null;
  let killSignals = [];
  let pollAttempts = 0;

  class FakeChild extends EventEmitter {
    constructor() {
      super();
      this.exitCode = null;
      this.killed = false;
    }
    kill(signal) {
      killSignals.push(signal);
      this.killed = true;
      this.exitCode = 0;
      setImmediate(() => this.emit('exit', 0, signal));
      return true;
    }
  }

  try {
    const handle = await chromeManager.launchDedicatedChrome({
      chromePath: 'C:\\Fake\\chrome.exe',
      profileDir: tmpProfile,
      cdpPort: 9321,
      startUrl: 'https://photos.google.com/',
      pollIntervalMs: 10,
      readyTimeoutMs: 2000,
      spawnImpl: (exe, args, opts) => {
        capturedSpawn = { exe, args, opts };
        return new FakeChild();
      },
      fetchImpl: async (url) => {
        pollAttempts++;
        assert.equal(url, 'http://127.0.0.1:9321/json/version');
        if (pollAttempts < 2) {
          throw new Error('ECONNREFUSED');
        }
        return {
          ok: true,
          async json() {
            return {
              Browser: 'Chrome/145.0.0.0',
              webSocketDebuggerUrl: 'ws://127.0.0.1:9321/devtools/browser/test-id'
            };
          }
        };
      }
    });

    assert.equal(capturedSpawn.exe, 'C:\\Fake\\chrome.exe');
    assert.equal(capturedSpawn.opts.shell, false, 'Chrome must NEVER spawn with shell: true');
    assert.equal(capturedSpawn.opts.detached, false, 'Chrome must spawn with detached: false');
    assert.equal(handle.wsUrl, 'ws://127.0.0.1:9321/devtools/browser/test-id');
    assert.equal(handle.cdpPort, 9321);
    assert.ok(pollAttempts >= 2);

    await handle.shutdown();
    assert.deepEqual(killSignals, ['SIGTERM']);
  } finally {
    fs.rmSync(tmpProfile, { recursive: true, force: true });
  }
});

test('SingleTargetCDP handles evalJS, trustedClick, shiftClick, command timeout, and safe detach without Browser.close', async () => {
  const sentPayloads = [];
  let wsClosed = false;

  class MockWebSocket extends EventTarget {
    constructor(url) {
      super();
      this.url = url;
      setImmediate(() => this.dispatchEvent(new Event('open')));
    }
    send(raw) {
      const msg = JSON.parse(raw);
      sentPayloads.push(msg);

      if (msg.method === 'Slow.HangCommand') {
        return; // deliberately never reply to trigger timeout guard
      }
      if (msg.method === 'Runtime.evaluate') {
        this._reply(msg.id, { result: { value: { ok: true, sum: 42 } } });
        return;
      }
      if (msg.method === 'Target.attachToTarget') {
        this._reply(msg.id, { sessionId: 'sess-isolated-1' });
        return;
      }
      this._reply(msg.id, {});
    }
    _reply(id, result) {
      setImmediate(() => {
        this.dispatchEvent(new MessageEvent('message', {
          data: JSON.stringify({ id, result })
        }));
      });
    }
    close() {
      wsClosed = true;
      this.dispatchEvent(new Event('close'));
    }
  }

  const cdp = new chromeManager.SingleTargetCDP('ws://127.0.0.1:9321/devtools/browser/mock', {
    commandTimeoutMs: 120,
    WebSocketImpl: MockWebSocket
  });

  await cdp.connect();
  const sessionId = await cdp.attachToTarget('target-1');
  assert.equal(sessionId, 'sess-isolated-1');

  const evalVal = await cdp.evalJS(sessionId, '({ ok: true, sum: 40 + 2 })');
  assert.deepEqual(evalVal, { ok: true, sum: 42 });

  await cdp.trustedClick(sessionId, 120.4, 240.6, { delayMs: 0 });
  await cdp.shiftClick(sessionId, 300.2, 410.8, { delayMs: 0 });

  await assert.rejects(
    () => cdp.send('Slow.HangCommand', {}, sessionId, 60),
    /timed out after 60ms/i
  );

  await cdp.detach();
  assert.equal(wsClosed, true);

  const methodsSent = sentPayloads.map((p) => p.method);
  assert.ok(methodsSent.includes('Target.detachFromTarget'), 'detach() must detach active target session');
  assert.ok(!methodsSent.includes('Browser.close'), 'detach() must NEVER call Browser.close');
  assert.ok(!methodsSent.includes('Target.closeTarget'), 'detach() must NEVER call Target.closeTarget');

  const shiftDown = sentPayloads.find(
    (p) => p.method === 'Input.dispatchKeyEvent' && p.params.type === 'keyDown' && p.params.key === 'Shift'
  );
  const shiftUp = sentPayloads.find(
    (p) => p.method === 'Input.dispatchKeyEvent' && p.params.type === 'keyUp' && p.params.key === 'Shift'
  );
  assert.ok(shiftDown && shiftUp, 'shiftClick must dispatch both Shift keyDown and Shift keyUp');
});

// ============================================================================
// 2. 3-Layer Personal Album Isolation Guard
// ============================================================================

test('Layer 1: isPersonalNonArchiveAlbumTitle blocks pre-existing personal albums while allowing archiveAlbumPrefix', () => {
  const customPrefix = 'ClientAlpha_iCloud_Archive';

  // Customer personal albums must be classified as personal (true -> blacklisted)
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('Me_1', customPrefix), true);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('Family Trip', customPrefix), true);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('Kyoto Autumn 2023', customPrefix), true);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('ClientAlpha_iCloud_ArchiveExtraPersonal', customPrefix), true);

  // Archive albums matching customer prefix must be allowed (false -> not personal)
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('ClientAlpha_iCloud_Archive', customPrefix), false);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('ClientAlpha_iCloud_Archive (2019)', customPrefix), false);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('ClientAlpha_iCloud_Archive (2019 - Part 2)', customPrefix), false);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('TMP_MERGE_2019_1', customPrefix), false);
  assert.equal(isolationGuard.isPersonalNonArchiveAlbumTitle('Untitled album', customPrefix), false);

  // Empty prefix must throw to prevent accidentally disabling Layer 1 protection
  assert.throws(
    () => isolationGuard.isPersonalNonArchiveAlbumTitle('Me_1', '   '),
    /must not be empty/i
  );
});

test('Layer 1 CDP read-only scan collects blacklisted photo IDs & aria-labels ONLY from non-archive personal albums', async () => {
  const visitedUrls = [];
  const fakeCdp = {
    async send(method, params) {
      if (method === 'Page.navigate') visitedUrls.push(params.url);
      return {};
    },
    async evalJS(_sessionId, expr) {
      if (expr.includes('discoverPersonalAlbumsOnAlbumsPage')) {
        return [
          { title: 'Me_1', href: 'https://photos.google.com/album/PERSONAL_ALBUM_01' },
          { title: 'Family Trip', href: 'https://photos.google.com/album/PERSONAL_ALBUM_02?hl=en' },
          { title: 'Jane_Archive (2020)', href: 'https://photos.google.com/album/ARCHIVE_ALBUM_2020' }
        ];
      }
      if (expr.includes('collectPersonalAlbumPhotoIdsInDom')) {
        const lastUrl = visitedUrls[visitedUrls.length - 1];
        if (lastUrl.includes('PERSONAL_ALBUM_01')) {
          return {
            photoIds: ['PID_ME_101'],
            ariaLabels: ['Photo - Portrait - May 12, 2019, 10:15:30\u202fAM'],
            moved: false
          };
        }
        return {
          photoIds: ['PID_FAM_202'],
          ariaLabels: ['Photo - Landscape - Dec 25, 2020, 6:00:00 PM'],
          moved: false
        };
      }
      return null;
    }
  };

  const result = await isolationGuard.collectPersonalAlbumBlacklistViaCDP(fakeCdp, 'sess-1', {
    archiveAlbumPrefix: 'Jane_Archive',
    fastTest: true
  });

  assert.deepEqual(visitedUrls, [
    'https://photos.google.com/albums',
    'https://photos.google.com/album/PERSONAL_ALBUM_01',
    'https://photos.google.com/album/PERSONAL_ALBUM_02'
  ]);
  assert.ok(!visitedUrls.some((u) => u.includes('ARCHIVE_ALBUM_2020')), 'Archive album must NOT be blacklisted');
  assert.ok(result.blacklistedPhotoIds.includes('PID_ME_101'));
  assert.ok(result.blacklistedPhotoIds.includes('PID_FAM_202'));
  assert.ok(result.blacklistedAriaLabels.includes('Photo - Portrait - May 12, 2019, 10:15:30 AM'));
});

test('Layer 2 & Layer 3: blocks day-level Select-All, filters upload window, rejects same-day wrong-second, accepts exact-second manifest matches', () => {
  const manifest = {
    years: {
      '2019': {
        months: {
          '05': {
            files: [
              {
                id: 'f-001',
                filename: 'IMG_2019_001.JPG',
                created: '2019-05-12T03:15:30.000Z' // 10:15:30 AM Asia/Bangkok & 3:15:30 AM UTC
              }
            ]
          }
        }
      },
      '2021': {
        months: {
          '01': {
            files: [
              {
                id: 'f-002',
                filename: 'IMG_2021_999.JPG',
                created: '2021-01-01T12:00:00.000Z'
              }
            ]
          }
        }
      }
    }
  };

  const wl2019 = isolationGuard.buildManifestTimestampWhitelist(manifest, [2019]);
  assert.equal(wl2019.itemCount, 1);
  assert.ok(wl2019.whitelistFilenames.has('IMG_2019_001.JPG'));
  assert.ok(!wl2019.whitelistFilenames.has('IMG_2021_999.JPG'));

  const blacklistedPhotoIds = new Set(['PID_PERSONAL_99']);
  const blacklistedAriaLabels = new Set(['Photo - Landscape - May 12, 2019, 10:15:30 AM']);

  // Layer 1: blacklisted photoId blocked even if timestamp matches manifest
  const rLayer1Id = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_PERSONAL_99',
    ariaLabel: 'Photo - Portrait - May 12, 2019, 10:15:30 AM',
    blacklistedPhotoIds,
    whitelistTimestamps: wl2019.whitelistTimestamps
  });
  assert.equal(rLayer1Id.eligible, false);
  assert.equal(rLayer1Id.reason, 'blocked_by_personal_album_blacklist_id');

  // Layer 1: blacklisted exact aria-label blocked
  const rLayer1Aria = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_OTHER',
    ariaLabel: 'Photo - Landscape - May 12, 2019, 10:15:30\u202fAM',
    blacklistedAriaLabels,
    whitelistTimestamps: wl2019.whitelistTimestamps
  });
  assert.equal(rLayer1Aria.eligible, false);
  assert.equal(rLayer1Aria.reason, 'blocked_by_personal_album_blacklist_aria');

  // Layer 2: English and Thai day-level "Select all" checkboxes hard-blocked
  const rDayEn = isolationGuard.isPhotoEligibleForArchiveAlbum({
    ariaLabel: 'Select all photos from May 12, 2019',
    whitelistTimestamps: wl2019.whitelistTimestamps
  });
  assert.equal(rDayEn.eligible, false);
  assert.equal(rDayEn.reason, 'blocked_day_level_select_all');

  const rDayTh = isolationGuard.isPhotoEligibleForArchiveAlbum({
    ariaLabel: 'เลือกรูปภาพทั้งหมดจาก 12 พ.ค. 2019',
    whitelistTimestamps: wl2019.whitelistTimestamps
  });
  assert.equal(rDayTh.eligible, false);
  assert.equal(rDayTh.reason, 'blocked_day_level_select_all');

  // Layer 2: _tra_ upload window filter rejects photos uploaded outside job window
  const uploadWindow = { windowStartMs: 1700000000000, windowEndMs: 1700003600000, toleranceMs: 1000 };
  const rOutOfWindow = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_OLD_UPLOAD',
    ariaLabel: 'Photo - Portrait - May 12, 2019, 10:15:30 AM',
    uploadedAtMs: 1690000000000,
    uploadWindow,
    whitelistTimestamps: wl2019.whitelistTimestamps
  });
  assert.equal(rOutOfWindow.eligible, false);
  assert.equal(rOutOfWindow.reason, 'outside_recently_added_upload_window');

  // Layer 3: Same-day WRONG-second photo (10:15:31 AM instead of 10:15:30 AM) MUST be REJECTED
  const rWrongSecond = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_SAME_DAY_PERSONAL',
    ariaLabel: 'Photo - Portrait - May 12, 2019, 10:15:31 AM',
    whitelistTimestamps: wl2019.whitelistTimestamps,
    whitelistDates: wl2019.whitelistDates
  });
  assert.equal(rWrongSecond.eligible, false);
  assert.equal(rWrongSecond.reason, 'timestamp_not_in_manifest_whitelist');

  // Layer 3: Exact-second Bangkok timestamp match + valid filename ACCEPTED
  const rExactBkk = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_ARCHIVE_OK_1',
    ariaLabel: 'Photo - Portrait - May 12, 2019, 10:15:30\u202fAM',
    filename: 'IMG_2019_001.JPG',
    uploadedAtMs: 1700001000000,
    uploadWindow,
    whitelistTimestamps: wl2019.whitelistTimestamps,
    whitelistFilenames: wl2019.whitelistFilenames
  });
  assert.equal(rExactBkk.eligible, true);
  assert.equal(rExactBkk.reason, 'matched_manifest_timestamp_to_second');

  // Layer 3: Exact-second UTC timestamp match ACCEPTED
  const rExactUtc = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_ARCHIVE_OK_2',
    ariaLabel: 'Photo - Portrait - May 12, 2019, 3:15:30 AM',
    whitelistTimestamps: wl2019.whitelistTimestamps
  });
  assert.equal(rExactUtc.eligible, true);
  assert.equal(rExactUtc.reason, 'matched_manifest_timestamp_to_second');

  // Layer 3: Wrong filename rejected even if timestamp matches
  const rWrongFile = isolationGuard.isPhotoEligibleForArchiveAlbum({
    photoId: 'PID_ARCHIVE_BAD_FN',
    ariaLabel: 'Photo - Portrait - May 12, 2019, 10:15:30 AM',
    filename: 'PERSONAL_SELFIE.JPG',
    whitelistTimestamps: wl2019.whitelistTimestamps,
    whitelistFilenames: wl2019.whitelistFilenames
  });
  assert.equal(rWrongFile.eligible, false);
  assert.equal(rWrongFile.reason, 'filename_not_in_manifest_whitelist');
});

// ============================================================================
// 3. Strict Single-Line Album Menu Item Isolation
// ============================================================================

test('pickSafeAlbumMenuItemFromDomRecords rejects containers, tall rows, Animation/Collage/Highlight/Shared, and picks exact single-line Album', () => {
  const domRecords = [
    // Multi-line wrapper container containing "Album" among other menu entries -> REJECT
    {
      text: 'Album\nShared album\nAnimation\nCollage',
      ancestorText: 'Album\nShared album\nAnimation\nCollage',
      rect: { left: 900, top: 60, width: 220, height: 240 }
    },
    // Tall single-line element (height > 68) -> REJECT
    {
      text: 'Album',
      ancestorText: 'Album',
      rect: { left: 900, top: 65, width: 220, height: 92 }
    },
    // Dangerous "+" creation menu items -> HARD-BLOCK
    {
      text: 'Shared album',
      ancestorText: 'Shared album',
      rect: { left: 900, top: 110, width: 200, height: 40 }
    },
    {
      text: 'Animation',
      ancestorText: 'Animation',
      rect: { left: 900, top: 150, width: 200, height: 40 }
    },
    {
      text: 'Collage',
      ancestorText: 'Collage',
      rect: { left: 900, top: 190, width: 200, height: 40 }
    },
    {
      text: 'Highlight video',
      ancestorText: 'Highlight video',
      rect: { left: 900, top: 230, width: 200, height: 40 }
    },
    {
      text: 'Cinematic photo',
      ancestorText: 'Cinematic photo',
      rect: { left: 900, top: 270, width: 200, height: 40 }
    },
    // Safe exact single-line "Album" row -> MUST PICK THIS ONE
    {
      text: 'Album',
      ancestorText: 'Album',
      rect: { left: 900, top: 72, width: 200, height: 44 }
    }
  ];

  const picked = uploader.pickSafeAlbumMenuItemFromDomRecords(domRecords);
  assert.equal(picked.found, true);
  assert.equal(picked.label, 'album');
  assert.equal(picked.x, 1000);
  assert.equal(picked.y, 94);

  // Also test Thai Google Photos UI: blocks ภาพเคลื่อนไหว / ภาพปะติด / วิดีโอไฮไลต์ / อัลบั้มที่แชร์, picks exact อัลบั้ม
  const thaiRecords = [
    { text: 'อัลบั้มที่แชร์', ancestorText: 'อัลบั้มที่แชร์', rect: { left: 880, top: 120, width: 180, height: 42 } },
    { text: 'ภาพเคลื่อนไหว', ancestorText: 'ภาพเคลื่อนไหว', rect: { left: 880, top: 162, width: 180, height: 42 } },
    { text: 'ภาพปะติด', ancestorText: 'ภาพปะติด', rect: { left: 880, top: 204, width: 180, height: 42 } },
    { text: 'วิดีโอไฮไลต์', ancestorText: 'วิดีโอไฮไลต์', rect: { left: 880, top: 246, width: 180, height: 42 } },
    { text: 'อัลบั้ม', ancestorText: 'อัลบั้ม', rect: { left: 880, top: 78, width: 180, height: 42 } }
  ];
  const pickedThai = uploader.pickSafeAlbumMenuItemFromDomRecords(thaiRecords);
  assert.equal(pickedThai.found, true);
  assert.equal(pickedThai.label, 'อัลบั้ม');
  assert.equal(pickedThai.y, 99);

  // If ONLY blocked items exist, must return { found: false }
  const onlyDangerous = domRecords.filter((r) => r.text !== 'Album');
  assert.equal(uploader.pickSafeAlbumMenuItemFromDomRecords(onlyDangerous).found, false);
});

// ============================================================================
// 4. Strict 100% Selection Completeness Gate
// ============================================================================

test('enforceSelectionCompletenessGate blocks sub-album deletion when selectedCount < requiredCount and allows at 100%', () => {
  const partial = uploader.enforceSelectionCompletenessGate(184, 600);
  assert.equal(partial.allowed, false);
  assert.equal(partial.missingCount, 416);
  assert.equal(partial.reason, 'incomplete_selection_blocked_before_delete');

  const zeroSel = uploader.enforceSelectionCompletenessGate(0, 600);
  assert.equal(zeroSel.allowed, false);
  assert.equal(zeroSel.reason, 'zero_items_selected_blocked_before_delete');

  const invalidReq = uploader.enforceSelectionCompletenessGate(100, 0);
  assert.equal(invalidReq.allowed, false);
  assert.equal(invalidReq.reason, 'invalid_required_count_blocked_before_delete');

  const exact = uploader.enforceSelectionCompletenessGate(600, 600);
  assert.equal(exact.allowed, true);
  assert.equal(exact.missingCount, 0);
  assert.equal(exact.reason, 'selection_complete_100_percent');

  const surplus = uploader.enforceSelectionCompletenessGate(605, 600);
  assert.equal(surplus.allowed, true);
});

test('mergeSubAlbumIntoTargetViaCDP refuses to proceed or delete when selectedCount < requiredCount (184 < 600)', async () => {
  const clicks = [];
  const fakeCdp = {
    async send() { return {}; },
    async trustedClick(sid, x, y) { clicks.push({ sid, x, y }); },
    async evalJS(_sid, expr) {
      if (expr.includes('items|item')) return { itemCount: 600 };
      if (expr.includes('selected')) return { selectedCount: 184 };
      return [];
    }
  };

  const res = await uploader.mergeSubAlbumIntoTargetViaCDP(
    fakeCdp,
    'sess-merge',
    {
      sourceUrl: 'https://photos.google.com/album/SUB_ALBUM_TEST',
      targetUrl: 'https://photos.google.com/album/PRIMARY_ALBUM_TEST',
      targetTitle: 'ClientBeta_Archive (2019)',
      expectedItems: 600
    },
    { fastTest: true }
  );

  assert.equal(res.merged, false);
  assert.equal(res.deletedSource, false);
  assert.equal(res.allowed, false);
  assert.equal(res.reason, 'incomplete_selection_blocked_before_delete');
  assert.equal(clicks.length, 0, 'Must NOT click any menu or delete actions when completeness gate blocks');
});

// ============================================================================
// 5. Parameterized Album Naming, 20k Ceiling Auto-Split & Atomic Checkpoints
// ============================================================================

test('formatArchiveAlbumTitle and nextAlbumTitleForState auto-split at 20,000 ceiling (19,500 soft limit) with custom albumPrefix', () => {
  const prefix = 'CustomerNova_iCloud';

  assert.equal(uploader.formatArchiveAlbumTitle(prefix, [2019]), 'CustomerNova_iCloud (2019)');
  assert.equal(
    uploader.formatArchiveAlbumTitle(prefix, [2014, 2015, 2016]),
    'CustomerNova_iCloud (2014-2016)'
  );
  assert.equal(
    uploader.formatArchiveAlbumTitle(prefix, [2019], { partIndex: 2 }),
    'CustomerNova_iCloud (2019 - Part 2)'
  );
  assert.equal(
    uploader.formatArchiveAlbumTitle(prefix, [2019], { partIndex: 2, partLabel: 'ชุดที่' }),
    'CustomerNova_iCloud (2019 - ชุดที่ 2)'
  );

  const state = {};
  const batch2019 = Array.from({ length: 100 }, (_, i) => ({
    yearFolder: '2019',
    filename: `IMG_${i}.JPG`
  }));

  // First batch starts unnumbered (Part 1)
  const title1 = uploader.nextAlbumTitleForState(state, batch2019, [2019], 'init', {
    albumPrefix: prefix
  });
  assert.equal(title1, 'CustomerNova_iCloud (2019)');

  // Simulate 19,400 items uploaded -> adding 100 hits 19,500 (still fits within softSplitLimit=19500)
  state.itemCountByYearKey['2019'] = 19400;
  state.currentAlbumItemCount = 19400;
  const titleStill1 = uploader.nextAlbumTitleForState(state, batch2019, [2019], 'batch', {
    albumPrefix: prefix
  });
  assert.equal(titleStill1, 'CustomerNova_iCloud (2019)');

  // Simulate 19,450 items uploaded -> adding 100 would exceed 19,500 soft ceiling -> auto-splits to Part 2!
  state.itemCountByYearKey['2019'] = 19450;
  state.currentAlbumItemCount = 19450;
  const title2 = uploader.nextAlbumTitleForState(state, batch2019, [2019], 'batch', {
    albumPrefix: prefix
  });
  assert.equal(title2, 'CustomerNova_iCloud (2019 - Part 2)');
  assert.equal(state.currentAlbumItemCount, 0, 'Item count resets to 0 on newly split part album');

  // Explicit overflow signal from Google Photos ("You have room for 0 more items") -> auto-splits to Part 3!
  const title3 = uploader.nextAlbumTitleForState(state, batch2019, [2019], 'overflow', {
    albumPrefix: prefix,
    roomLeft: 0
  });
  assert.equal(title3, 'CustomerNova_iCloud (2019 - Part 3)');
});

test('saveJobCheckpoint and loadJobCheckpoint perform atomic persistence inside customer sandbox and block path traversal', () => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-sandbox-'));
  try {
    assert.throws(
      () => uploader.getJobCheckpointPath(sandbox, '../escape'),
      /Invalid jobId/i
    );

    const cpPath = uploader.getJobCheckpointPath(sandbox, 'job_customer_42');
    assert.equal(path.dirname(cpPath), path.resolve(sandbox));

    const saveRes = uploader.saveJobCheckpoint(cpPath, {
      job_id: 'job_customer_42',
      album_prefix: 'Customer42_Archive',
      uploaded_ids: ['a1', 'a2'],
      currentAlbumItemCount: 2
    });
    assert.equal(saveRes.ok, true);

    const loaded = uploader.loadJobCheckpoint(cpPath);
    assert.equal(loaded.job_id, 'job_customer_42');
    assert.deepEqual(loaded.uploaded_ids, ['a1', 'a2']);
    assert.ok(loaded.updated_at);

    // Confirm no leftover .tmp files exist in sandbox
    const leftovers = fs.readdirSync(sandbox).filter((f) => f.endsWith('.tmp'));
    assert.equal(leftovers.length, 0);
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('parseCliArgs extracts job parameters cleanly', () => {
  const parsed = uploader.parseCliArgs([
    '--job-id', 'job-77',
    '--profile-dir', 'D:\\Sandboxes\\job-77\\chrome',
    '--cdp-port', '9344',
    '--manifest', 'D:\\Sandboxes\\job-77\\manifest.json',
    '--album-prefix', 'Customer77_Archive',
    '--dry-run'
  ]);

  assert.equal(parsed.jobId, 'job-77');
  assert.equal(parsed.profileDir, 'D:\\Sandboxes\\job-77\\chrome');
  assert.equal(parsed.cdpPort, 9344);
  assert.equal(parsed.manifestPath, 'D:\\Sandboxes\\job-77\\manifest.json');
  assert.equal(parsed.albumPrefix, 'Customer77_Archive');
  assert.equal(parsed.dryRun, true);
});

// ============================================================================
// 6. WebCrypto Hybrid Envelope Interop Self-Test (RSA-OAEP-256 + AES-256-GCM)
// ============================================================================

test('WebCrypto Hybrid Envelope Interop Self-Test: RSA-OAEP-256 + A256GCM exact envelope round-trips and detects tampering', async () => {
  const subtle = webcrypto.subtle;

  // 1. Operator workbench generates RSA-OAEP (SHA-256) keypair
  const keyPair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  // 2. Compute SPKI SHA-256 hex fingerprint (matches browser & Python cryptography workbench)
  const spkiDer = await subtle.exportKey('spki', keyPair.publicKey);
  const fpDigest = await subtle.digest('SHA-256', spkiDer);
  const keyFingerprintSha256 = Buffer.from(fpDigest).toString('hex');
  assert.equal(keyFingerprintSha256.length, 64);

  // 3. Browser encrypts customer credential payload with ephemeral AES-256-GCM + wraps key with RSA-OAEP-256
  const credentialPayload = {
    job_id: 'job-crypto-interop-01',
    apple_id_handle: 'demo_customer_handle_01',
    app_specific_token: 'ephemeral-test-token-1234',
    target_album_prefix: 'DemoCustomer_Archive',
    issued_at: '2026-11-23T06:48:11Z'
  };

  const aesKey = await subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const rawAesKey = await subtle.exportKey('raw', aesKey);
  assert.equal(rawAesKey.byteLength, 32);

  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(credentialPayload));
  const ciphertextBuf = await subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    plaintextBytes
  );
  const wrappedKeyBuf = await subtle.encrypt(
    { name: 'RSA-OAEP' },
    keyPair.publicKey,
    rawAesKey
  );

  // Exact interop envelope contract
  const envelope = {
    version: 1,
    alg: 'RSA-OAEP-256+A256GCM',
    key_fingerprint_sha256: keyFingerprintSha256,
    wrapped_key_b64: Buffer.from(wrappedKeyBuf).toString('base64'),
    iv_b64: Buffer.from(iv).toString('base64'),
    ciphertext_b64: Buffer.from(ciphertextBuf).toString('base64')
  };

  assert.deepEqual(Object.keys(envelope).sort(), [
    'alg',
    'ciphertext_b64',
    'iv_b64',
    'key_fingerprint_sha256',
    'version',
    'wrapped_key_b64'
  ]);
  assert.equal(envelope.version, 1);
  assert.equal(envelope.alg, 'RSA-OAEP-256+A256GCM');

  // 4. Workbench decrypts envelope using private key & verifies fingerprint
  assert.equal(envelope.key_fingerprint_sha256, keyFingerprintSha256);

  const unwrappedRawKey = await subtle.decrypt(
    { name: 'RSA-OAEP' },
    keyPair.privateKey,
    Buffer.from(envelope.wrapped_key_b64, 'base64')
  );
  const importedAesKey = await subtle.importKey(
    'raw',
    unwrappedRawKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  const decryptedBuf = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: Buffer.from(envelope.iv_b64, 'base64'),
      tagLength: 128
    },
    importedAesKey,
    Buffer.from(envelope.ciphertext_b64, 'base64')
  );

  const recovered = JSON.parse(new TextDecoder().decode(decryptedBuf));
  assert.deepEqual(recovered, credentialPayload);

  // 5. Tamper test: flipping 1 bit in ciphertext must fail AES-GCM authentication tag check
  const tamperedBytes = Buffer.from(envelope.ciphertext_b64, 'base64');
  tamperedBytes[0] ^= 0x01;
  await assert.rejects(
    () => subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: Buffer.from(envelope.iv_b64, 'base64'),
        tagLength: 128
      },
      importedAesKey,
      tamperedBytes
    ),
    /OperationError|unable to authenticate/i
  );
});
