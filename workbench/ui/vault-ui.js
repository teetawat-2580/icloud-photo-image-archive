/* CloudVault Concierge — Zero-Knowledge AI Search Vault Workbench Module
 * Modular companion to `/ui/app.js` (Golden Rule #10).
 * Security: Strictly uses createElement + textContent (ZERO innerHTML — OWASP A03 defense).
 */
(() => {
  'use strict';

  const vState = {
    activeTab: 'jobs',
    vaults: [],
    selectedVaultId: null,
    ephemeralVaultLinks: new Map(), // vaultId -> one-time customer_vault_url (RAM only)
    searchQuery: '',
    r2Status: null,
  };

  const vEls = {
    tabJobs: document.getElementById('tab-migration-jobs'),
    tabVaults: document.getElementById('tab-search-vaults'),
    viewJobs: document.getElementById('view-migration-jobs'),
    viewVaults: document.getElementById('view-search-vaults'),
    toastBar: document.getElementById('toast-bar'),
    r2StatusPill: document.getElementById('r2-status-pill'),
    r2StatusDesc: document.getElementById('r2-status-desc'),
    r2Form: document.getElementById('r2-config-form'),
    r2Endpoint: document.getElementById('r2-endpoint-input'),
    r2Bucket: document.getElementById('r2-bucket-input'),
    r2AccessKey: document.getElementById('r2-access-key-input'),
    r2SecretKey: document.getElementById('r2-secret-key-input'),
    r2Log: document.getElementById('r2-result-log'),
    vaultsList: document.getElementById('vaults-list'),
    vaultSearch: document.getElementById('vault-search-input'),
    deskEmpty: document.getElementById('vault-desk-empty'),
    deskContent: document.getElementById('vault-desk-content'),
    ownerName: document.getElementById('vdetail-owner-name'),
    statusBadge: document.getElementById('vdetail-status-badge'),
    code: document.getElementById('vdetail-code'),
    storage: document.getElementById('vdetail-storage'),
    sourceType: document.getElementById('vdetail-source-type'),
    pubkeyFp: document.getElementById('vdetail-pubkey-fp'),
    assetsCount: document.getElementById('vdetail-assets-count'),
    linkPanel: document.getElementById('vault-link-panel'),
    linkCode: document.getElementById('vdetail-vault-link'),
    openPortalBtn: document.getElementById('btn-open-vault-portal'),
    statAssets: document.getElementById('vstat-assets'),
    statFaces: document.getElementById('vstat-faces'),
    statOcr: document.getElementById('vstat-ocr'),
    statBytes: document.getElementById('vstat-bytes'),
    keyStatusMsg: document.getElementById('vdetail-key-status-msg'),
    buildForm: document.getElementById('build-index-form'),
    sourceDirInput: document.getElementById('input-vault-source-dir'),
    maxFilesInput: document.getElementById('input-vault-max-files'),
    indexerBtn: document.getElementById('btn-run-vault-indexer'),
    indexerLog: document.getElementById('vault-indexer-log'),
    mediaForm: document.getElementById('media-source-form'),
    mediaTypeSelect: document.getElementById('input-media-source-type'),
    nasBaseUrlInput: document.getElementById('input-nas-base-url'),
    albumMappingsInput: document.getElementById('input-album-mappings'),
    mediaLog: document.getElementById('media-source-log'),
    createModal: document.getElementById('create-vault-modal'),
    createForm: document.getElementById('create-vault-form'),
    createOwnerInput: document.getElementById('input-vault-owner'),
    createStorageSelect: document.getElementById('input-vault-storage'),
    createSourceSelect: document.getElementById('input-vault-source-mode'),
    createError: document.getElementById('create-vault-error'),
  };

  if (!vEls.tabVaults || !vEls.viewVaults) return;

  let vToastTimer = null;
  function showVToast(message, variant = 'default') {
    if (!vEls.toastBar) return;
    if (vToastTimer) clearTimeout(vToastTimer);
    vEls.toastBar.textContent = message;
    vEls.toastBar.className = 'toast-bar';
    if (variant === 'error') vEls.toastBar.classList.add('toast-error');
    if (variant === 'success') vEls.toastBar.classList.add('toast-success');
    vToastTimer = setTimeout(() => vEls.toastBar.classList.add('hidden'), 4400);
  }

  function clearNode(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  async function apiJson(path, options = {}) {
    const resp = await fetch(path, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const text = await resp.text();
    let data = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_err) {
        data = { detail: text };
      }
    }
    if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
    return data;
  }

  async function copyText(text, msg) {
    try {
      await navigator.clipboard.writeText(text);
      showVToast(msg, 'success');
    } catch (_err) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showVToast(msg, 'success');
    }
  }

  function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (!n || n <= 0) return '0 B';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function shortFp(hex) {
    if (!hex || hex.length < 16) return hex || 'รอเจ้าของตั้งรหัสผ่าน';
    return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
  }

  function vaultPillClass(status) {
    const s = String(status || '').toUpperCase();
    if (s === 'READY') return 'pill-teal';
    if (s === 'REVOKED') return 'pill-danger';
    if (s === 'AWAITING_CUSTOMER_KEY') return 'pill-amber';
    return 'pill-cobalt';
  }

  function switchTab(tabName) {
    vState.activeTab = tabName;
    const isVaults = tabName === 'vaults';
    vEls.tabJobs.classList.toggle('active', !isVaults);
    vEls.tabJobs.setAttribute('aria-pressed', String(!isVaults));
    vEls.tabVaults.classList.toggle('active', isVaults);
    vEls.tabVaults.setAttribute('aria-pressed', String(isVaults));
    vEls.viewJobs.classList.toggle('hidden', isVaults);
    vEls.viewVaults.classList.toggle('hidden', !isVaults);

    if (isVaults) {
      void loadR2Status();
      void loadVaults();
    }
  }

  async function loadR2Status() {
    try {
      const data = await apiJson('/api/operator/vaults/r2-status');
      vState.r2Status = data;
      if (data.configured) {
        vEls.r2StatusPill.className = 'status-pill pill-teal';
        vEls.r2StatusPill.textContent = `R2 เชื่อมต่อพร้อมใช้ (${data.bucket_name})`;
        vEls.r2StatusDesc.textContent =
          `Endpoint: ${data.endpoint_url} · Access Key: ${data.access_key_masked} · ไฟล์ .enc ถูกเก็บแบบ Zero-Knowledge`;
        if (!vEls.r2Endpoint.value) vEls.r2Endpoint.value = data.endpoint_url || '';
        if (!vEls.r2Bucket.value) vEls.r2Bucket.value = data.bucket_name || '';
      } else {
        vEls.r2StatusPill.className = 'status-pill pill-amber';
        vEls.r2StatusPill.textContent = 'ยังไม่ได้ใส่คีย์ Cloudflare R2';
        vEls.r2StatusDesc.textContent =
          `สามารถกด "ตั้งค่า / แก้ไขคีย์ R2" เพื่อเชื่อมต่อ Cloudflare R2 ฟรี 10 GB หรือใช้โหมด PC NAS (${data.local_blobs_root}) ชั่วคราวได้`;
      }
    } catch (err) {
      vEls.r2StatusPill.className = 'status-pill pill-danger';
      vEls.r2StatusPill.textContent = 'ตรวจสอบ R2 ไม่สำเร็จ';
      vEls.r2Log.textContent = err.message;
    }
  }

  function getSelectedVault() {
    return vState.vaults.find((v) => v.id === vState.selectedVaultId) || null;
  }

  async function loadVaults() {
    try {
      const data = await apiJson('/api/operator/vaults');
      vState.vaults = Array.isArray(data.vaults) ? data.vaults : [];
      if (vState.selectedVaultId && !vState.vaults.some((v) => v.id === vState.selectedVaultId)) {
        vState.selectedVaultId = null;
      }
      if (!vState.selectedVaultId && vState.vaults.length > 0) {
        vState.selectedVaultId = vState.vaults[0].id;
      }
      renderVaultsList();
      renderSelectedVault();
    } catch (err) {
      showVToast(`โหลดรายการ Search Vaults ไม่สำเร็จ: ${err.message}`, 'error');
    }
  }

  function renderVaultsList() {
    clearNode(vEls.vaultsList);
    const q = vState.searchQuery.trim().toLowerCase();
    const filtered = vState.vaults.filter((v) => {
      if (!q) return true;
      return (
        String(v.owner_display_name || '').toLowerCase().includes(q) ||
        String(v.vault_code || '').toLowerCase().includes(q)
      );
    });

    if (filtered.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'muted-caption';
      empty.textContent =
        vState.vaults.length === 0
          ? 'ยังไม่มี AI Search Vault กด "+ สร้าง AI Search Vault" ด้านบน'
          : 'ไม่พบตู้นิรภัยที่ตรงกับคำค้นหา';
      vEls.vaultsList.appendChild(empty);
      return;
    }

    for (const v of filtered) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `job-row${v.id === vState.selectedVaultId ? ' active' : ''}`;
      btn.setAttribute('role', 'option');
      btn.setAttribute('aria-selected', String(v.id === vState.selectedVaultId));
      btn.addEventListener('click', () => {
        vState.selectedVaultId = v.id;
        renderVaultsList();
        renderSelectedVault();
      });

      const top = document.createElement('div');
      top.className = 'job-row-top';
      const nameEl = document.createElement('span');
      nameEl.className = 'job-row-name';
      nameEl.textContent = v.owner_display_name || 'ไม่ระบุชื่อ';
      const pill = document.createElement('span');
      pill.className = `status-pill ${vaultPillClass(v.status)}`;
      pill.textContent = v.status || 'AWAITING_CUSTOMER_KEY';
      top.appendChild(nameEl);
      top.appendChild(pill);

      const meta = document.createElement('div');
      meta.className = 'job-row-meta';
      const c1 = document.createElement('span');
      c1.textContent = v.vault_code || v.id.slice(0, 8);
      const c2 = document.createElement('span');
      c2.textContent = v.storage_backend === 'cloudflare_r2' ? 'R2' : 'PC-NAS';
      const c3 = document.createElement('span');
      c3.textContent = `${Number(v.total_assets || 0).toLocaleString()} ภาพ`;
      meta.appendChild(c1);
      meta.appendChild(c2);
      meta.appendChild(c3);

      btn.appendChild(top);
      btn.appendChild(meta);
      vEls.vaultsList.appendChild(btn);
    }
  }

  function serializeAlbumsToLines(albumsObj) {
    if (!albumsObj || typeof albumsObj !== 'object') return '';
    const lines = [];
    for (const [key, val] of Object.entries(albumsObj)) {
      if (typeof val === 'string') {
        lines.push(`${key} = ${val}`);
      } else if (val && typeof val === 'object') {
        const url = val.short_url || val.url || '';
        if (url) lines.push(`${key} = ${url}`);
      }
    }
    return lines.join('\n');
  }

  function parseLinesToAlbums(rawText) {
    const albums = {};
    const lines = String(rawText || '').split(/\r?\n/);
    for (const line of lines) {
      const clean = line.trim();
      if (!clean || clean.startsWith('#')) continue;
      const eqIdx = clean.indexOf('=');
      if (eqIdx <= 0) continue;
      const key = clean.slice(0, eqIdx).trim();
      const url = clean.slice(eqIdx + 1).trim();
      if (key && url) {
        albums[key] = { short_url: url, title: `Archive (${key})` };
      }
    }
    return albums;
  }

  function renderSelectedVault() {
    const v = getSelectedVault();
    if (!v) {
      vEls.deskEmpty.classList.remove('hidden');
      vEls.deskContent.classList.add('hidden');
      return;
    }

    vEls.deskEmpty.classList.add('hidden');
    vEls.deskContent.classList.remove('hidden');

    vEls.ownerName.textContent = v.owner_display_name || 'ไม่ระบุชื่อ';
    vEls.statusBadge.textContent = v.status || 'AWAITING_CUSTOMER_KEY';
    vEls.statusBadge.className = `status-pill ${vaultPillClass(v.status)}`;
    vEls.code.textContent = v.vault_code || v.id;
    vEls.storage.textContent = v.storage_backend || 'cloudflare_r2';
    vEls.sourceType.textContent = v.media_source_type || 'google_photos_shared';
    vEls.pubkeyFp.textContent = shortFp(v.customer_key_fingerprint_sha256);

    const totalAssets = Number(v.total_assets || 0);
    vEls.assetsCount.textContent = `${totalAssets.toLocaleString()} ภาพ`;
    vEls.statAssets.textContent = totalAssets.toLocaleString();
    vEls.statFaces.textContent = Number(v.total_faces || 0).toLocaleString();
    vEls.statOcr.textContent = Number(v.total_ocr_assets || 0).toLocaleString();
    vEls.statBytes.textContent = formatBytes(
      Number(v.index_size_bytes || 0) + Number(v.total_thumb_bytes || 0)
    );

    const link = vState.ephemeralVaultLinks.get(v.id);
    if (link) {
      vEls.linkPanel.classList.remove('hidden');
      vEls.linkCode.textContent = link;
      vEls.openPortalBtn.href = link;
    } else {
      vEls.linkPanel.classList.add('hidden');
    }

    const hasKey = Boolean(v.customer_public_key_pem);
    vEls.keyStatusMsg.textContent = hasKey
      ? `เจ้าของคลังลงทะเบียนกุญแจสาธารณะแล้ว (${shortFp(v.customer_key_fingerprint_sha256)}) — พร้อมรัน AI สแกนและเข้ารหัสทางเดียวได้ทันที`
      : 'ยังรอกุญแจสาธารณะจากเจ้าของคลัง: ส่งลิงก์ตู้นิรภัยให้คุณแม่/ลูกค้าเปิดครั้งแรกเพื่อตั้งรหัสผ่าน แล้วกดปุ่ม "รีเฟรชตรวจกุญแจสาธารณะ"';

    vEls.mediaTypeSelect.value = v.media_source_type || 'google_photos_shared';
    const cfg = v.media_source_config && typeof v.media_source_config === 'object' ? v.media_source_config : {};
    vEls.nasBaseUrlInput.value = cfg.nas_base_url || '';
    vEls.albumMappingsInput.value = serializeAlbumsToLines(cfg.albums || {});
    vEls.indexerLog.textContent = v.plaintext_purged_at
      ? `ล่าสุด: เข้ารหัสเสร็จและล้างไฟล์พักต้นฉบับแล้วเมื่อ ${v.plaintext_purged_at}`
      : '';
    vEls.mediaLog.textContent = '';
  }

  // Event Bindings
  vEls.tabJobs.addEventListener('click', () => switchTab('jobs'));
  vEls.tabVaults.addEventListener('click', () => switchTab('vaults'));

  function openCreateVaultModal() {
    switchTab('vaults');
    vEls.createError.classList.add('hidden');
    vEls.createError.textContent = '';
    vEls.createOwnerInput.value = '';
    vEls.createModal.showModal();
    vEls.createOwnerInput.focus();
  }

  document.getElementById('btn-open-create-vault').addEventListener('click', openCreateVaultModal);
  document.getElementById('btn-empty-create-vault').addEventListener('click', openCreateVaultModal);
  document.getElementById('btn-close-vault-modal').addEventListener('click', () => vEls.createModal.close());
  document.getElementById('btn-cancel-create-vault').addEventListener('click', () => vEls.createModal.close());
  document.getElementById('btn-refresh-vaults').addEventListener('click', () => {
    void loadR2Status();
    void loadVaults();
  });
  document.getElementById('btn-recheck-vault-key').addEventListener('click', () => {
    void loadVaults().then(() => showVToast('อัปเดตสถานะกุญแจสาธารณะล่าสุดจาก Supabase แล้ว', 'success'));
  });

  vEls.vaultSearch.addEventListener('input', (ev) => {
    vState.searchQuery = ev.target.value;
    renderVaultsList();
  });

  document.getElementById('btn-toggle-r2-form').addEventListener('click', () => {
    vEls.r2Form.classList.toggle('hidden');
  });

  document.getElementById('btn-test-r2').addEventListener('click', async () => {
    vEls.r2Log.textContent = 'กำลังทดสอบเชื่อมต่อ Cloudflare R2 (SigV4 HEAD)...';
    vEls.r2Form.classList.remove('hidden');
    try {
      const res = await apiJson('/api/operator/vaults/r2-test', { method: 'POST' });
      if (res.ok) {
        vEls.r2Log.textContent = `เชื่อมต่อสำเร็จ! Bucket ${res.bucket_name} ตอบกลับ HTTP ${res.http_status}`;
        showVToast('เชื่อมต่อ Cloudflare R2 สำเร็จ 100%', 'success');
      } else {
        vEls.r2Log.textContent = `Cloudflare R2 ตอบกลับ HTTP ${res.http_status} — ตรวจชื่อ Bucket หรือสิทธิ์ R2 API Token`;
        showVToast(`R2 ตอบกลับ HTTP ${res.http_status}`, 'error');
      }
    } catch (err) {
      vEls.r2Log.textContent = err.message;
      showVToast(err.message, 'error');
    }
  });

  vEls.r2Form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    vEls.r2Log.textContent = 'กำลังบันทึกคีย์ R2 ลง .env และทดสอบการเชื่อมต่อ...';
    try {
      const res = await apiJson('/api/operator/vaults/r2-config', {
        method: 'POST',
        body: JSON.stringify({
          endpoint_url: vEls.r2Endpoint.value.trim(),
          bucket_name: vEls.r2Bucket.value.trim(),
          access_key_id: vEls.r2AccessKey.value.trim(),
          secret_access_key: vEls.r2SecretKey.value.trim(),
          test_connection: true,
        }),
      });
      vEls.r2SecretKey.value = '';
      await loadR2Status();
      const ct = res.connection_test;
      if (ct && ct.ok) {
        vEls.r2Log.textContent = `บันทึกสำเร็จและทดสอบผ่าน! Bucket ${res.bucket_name} พร้อมใช้งาน (HTTP ${ct.http_status})`;
        showVToast('บันทึกและเชื่อมต่อ Cloudflare R2 สำเร็จ!', 'success');
      } else if (ct) {
        vEls.r2Log.textContent = `บันทึกคีย์ลงเครื่องแล้ว แต่ผลทดสอบ R2: ${ct.error || `HTTP ${ct.http_status}`}`;
        showVToast('บันทึกคีย์แล้ว กรุณาตรวจสอบผลทดสอบ R2', 'default');
      }
    } catch (err) {
      vEls.r2Log.textContent = err.message;
      showVToast(err.message, 'error');
    }
  });

  document.getElementById('btn-copy-vercel-r2').addEventListener('click', () => {
    const endpoint = vEls.r2Endpoint.value.trim() || (vState.r2Status && vState.r2Status.endpoint_url) || 'https://<account_id>.r2.cloudflarestorage.com';
    const bucket = vEls.r2Bucket.value.trim() || (vState.r2Status && vState.r2Status.bucket_name) || 'cloudvault-encrypted-blobs';
    const template = [
      '# วาง 4 ตัวแปรนี้ใน Vercel -> Project Settings -> Environment Variables (Production & Preview)',
      `R2_ENDPOINT_URL=${endpoint}`,
      `R2_BUCKET_NAME=${bucket}`,
      'R2_ACCESS_KEY_ID=<วาง Access Key ID จาก Cloudflare R2>',
      'R2_SECRET_ACCESS_KEY=<วาง Secret Access Key จาก Cloudflare R2>',
    ].join('\n');
    void copyText(template, 'คัดลอกรายการตัวแปร Environment สำหรับวางบน Vercel แล้ว');
  });

  vEls.createForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    vEls.createError.classList.add('hidden');
    try {
      const created = await apiJson('/api/operator/vaults', {
        method: 'POST',
        body: JSON.stringify({
          owner_display_name: vEls.createOwnerInput.value.trim(),
          storage_backend: vEls.createStorageSelect.value,
          media_source_type: vEls.createSourceSelect.value,
          media_source_config: {},
        }),
      });
      vState.ephemeralVaultLinks.set(created.vault.id, created.customer_vault_url);
      vState.selectedVaultId = created.vault.id;
      vEls.createModal.close();
      await loadVaults();
      showVToast(`สร้างตู้นิรภัย ${created.vault.vault_code} สำเร็จ พร้อมลิงก์ส่งเจ้าของคลัง`, 'success');
    } catch (err) {
      vEls.createError.textContent = err.message;
      vEls.createError.classList.remove('hidden');
    }
  });

  document.getElementById('btn-copy-vault-link').addEventListener('click', () => {
    const v = getSelectedVault();
    const link = v && vState.ephemeralVaultLinks.get(v.id);
    if (link) void copyText(link, 'คัดลอกลิงก์ตู้นิรภัยแล้ว');
  });

  document.getElementById('btn-copy-vault-line').addEventListener('click', () => {
    const v = getSelectedVault();
    const link = v && vState.ephemeralVaultLinks.get(v.id);
    if (!v || !link) return;
    const msg = [
      `ตู้นิรภัยค้นหาภาพ AI ส่วนตัว (${v.owner_display_name}) พร้อมเปิดใช้งานแล้วครับ`,
      'กดลิงก์ด้านล่างเพื่อตั้งรหัสผ่านส่วนตัวครั้งแรก (ระบบเข้ารหัสในเบราว์เซอร์ของคุณ 100% คนอื่นรวมถึงคลาวด์เปิดดูไม่ได้):',
      link,
    ].join('\n');
    void copyText(msg, 'คัดลอกข้อความสำหรับส่ง LINE เรียบร้อยแล้ว');
  });

  vEls.buildForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const v = getSelectedVault();
    if (!v) return;
    vEls.indexerBtn.disabled = true;
    vEls.indexerLog.textContent = 'กำลังสแกน AI (InsightFace + Thai OCR + CLIP) และเข้ารหัสทางเดียว .enc กรุณารอสักครู่...';
    try {
      const res = await apiJson(`/api/operator/vaults/${encodeURIComponent(v.id)}/build-index`, {
        method: 'POST',
        body: JSON.stringify({
          source_dir: vEls.sourceDirInput.value.trim(),
          max_files: parseInt(vEls.maxFilesInput.value, 10) || 200000,
        }),
      });
      const pub = res.published || {};
      vEls.indexerLog.textContent =
        `สำเร็จ! จัดดัชนี ${pub.total_assets ?? 0} ภาพ · ใบหน้า ${pub.total_faces ?? 0} กลุ่ม · OCR ${pub.total_ocr_assets ?? 0} ภาพ · ปลายทาง ${pub.storage_backend} · ล้างไฟล์ชั่วคราวแล้ว`;
      await loadVaults();
      showVToast('เข้ารหัสดัชนีและภาพย่อสำเร็จพร้อมล้างไฟล์พักแล้ว!', 'success');
    } catch (err) {
      vEls.indexerLog.textContent = err.message;
      showVToast(err.message, 'error');
    } finally {
      vEls.indexerBtn.disabled = false;
    }
  });

  vEls.mediaForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const v = getSelectedVault();
    if (!v) return;
    const cfg = {
      albums: parseLinesToAlbums(vEls.albumMappingsInput.value),
      nas_base_url: vEls.nasBaseUrlInput.value.trim(),
    };
    try {
      await apiJson(`/api/operator/vaults/${encodeURIComponent(v.id)}/media-source`, {
        method: 'PATCH',
        body: JSON.stringify({
          media_source_type: vEls.mediaTypeSelect.value,
          media_source_config: cfg,
        }),
      });
      vEls.mediaLog.textContent = `บันทึกแหล่งภาพต้นฉบับ (${vEls.mediaTypeSelect.value}) เรียบร้อยแล้ว`;
      await loadVaults();
      showVToast('บันทึกการตั้งค่า Pluggable Media Source เรียบร้อยแล้ว', 'success');
    } catch (err) {
      vEls.mediaLog.textContent = err.message;
      showVToast(err.message, 'error');
    }
  });

  // Allow direct deep-link to AI Search Vault tab via http://127.0.0.1:8790/#vaults
  if (window.location.hash === '#vaults') {
    switchTab('vaults');
  }
})();
