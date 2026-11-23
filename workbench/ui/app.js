/* CloudVault Concierge — Local Operator Control Panel Client
 * Security: Uses strictly safe DOM APIs (createElement + textContent).
 * ZERO innerHTML with untrusted data (OWASP A03 DOM XSS defense).
 */
(() => {
  'use strict';

  const state = {
    health: null,
    jobs: [],
    selectedJobId: null,
    ephemeralLinks: new Map(), // jobId -> one-time customer_tracking_link kept in browser RAM only
    searchQuery: '',
  };

  const els = {
    healthBind: document.getElementById('health-bind'),
    healthMode: document.getElementById('health-mode'),
    healthModeDot: document.getElementById('health-mode-dot'),
    healthFingerprint: document.getElementById('health-fingerprint'),
    healthStagingRoot: document.getElementById('health-staging-root'),
    onedriveAlert: document.getElementById('onedrive-alert'),
    toastBar: document.getElementById('toast-bar'),
    jobsList: document.getElementById('jobs-list'),
    jobSearch: document.getElementById('job-search-input'),
    deskEmpty: document.getElementById('desk-empty'),
    deskContent: document.getElementById('desk-content'),
    detailName: document.getElementById('detail-customer-name'),
    detailStatus: document.getElementById('detail-status-badge'),
    detailCode: document.getElementById('detail-job-code'),
    detailMode: document.getElementById('detail-service-mode'),
    detailAlbum: document.getElementById('detail-album-prefix'),
    detailPort: document.getElementById('detail-cdp-port'),
    detailSandboxFiles: document.getElementById('detail-sandbox-files'),
    lineLinkPanel: document.getElementById('line-link-panel'),
    detailTrackingLink: document.getElementById('detail-tracking-link'),
    envelopeResult: document.getElementById('envelope-result'),
    otpProvider: document.getElementById('otp-provider-select'),
    otpResult: document.getElementById('otp-result'),
    cdpDryRun: document.getElementById('cdp-dry-run'),
    cdpResult: document.getElementById('cdp-result'),
    fiveLockYear: document.getElementById('fivelock-year-input'),
    fiveLockSummary: document.getElementById('fivelock-summary'),
    fiveLockChecklist: document.getElementById('fivelock-checklist'),
    pdpaCertBox: document.getElementById('pdpa-cert-box'),
    pdpaCertFields: document.getElementById('pdpa-cert-fields'),
    modal: document.getElementById('create-job-modal'),
    createForm: document.getElementById('create-job-form'),
    createError: document.getElementById('create-form-error'),
    inputCustomerName: document.getElementById('input-customer-name'),
    inputServiceMode: document.getElementById('input-service-mode'),
    inputAlbumPrefix: document.getElementById('input-album-prefix'),
    inputTargetYears: document.getElementById('input-target-years'),
    inputStagingDrive: document.getElementById('input-staging-drive'),
  };

  let toastTimer = null;

  function showToast(message, variant = 'default') {
    if (toastTimer) clearTimeout(toastTimer);
    els.toastBar.textContent = message;
    els.toastBar.className = 'toast-bar';
    if (variant === 'error') els.toastBar.classList.add('toast-error');
    if (variant === 'success') els.toastBar.classList.add('toast-success');
    toastTimer = setTimeout(() => {
      els.toastBar.classList.add('hidden');
    }, 4200);
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function statusPillClass(status) {
    const s = String(status || '').toUpperCase();
    if (s === 'COMPLETED' || s === 'AUDIT_READY') return 'pill-teal';
    if (s === 'FAILED' || s === 'CANCELLED') return 'pill-danger';
    if (s.includes('AWAITING') || s.includes('5LOCK')) return 'pill-amber';
    return 'pill-cobalt';
  }

  function shortFingerprint(hex) {
    if (!hex || hex.length < 16) return hex || '—';
    return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
  }

  async function apiRequest(path, options = {}) {
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
    if (!resp.ok) {
      throw new Error(data.detail || `HTTP ${resp.status}`);
    }
    return data;
  }

  async function copyToClipboard(text, successMsg) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(successMsg, 'success');
    } catch (_err) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(successMsg, 'success');
    }
  }

  function getSelectedJob() {
    return state.jobs.find((j) => j.id === state.selectedJobId) || null;
  }

  async function loadHealth() {
    const data = await apiRequest('/api/operator/health');
    state.health = data;
    els.healthBind.textContent = `${data.bind_host}:${data.port}`;
    els.healthFingerprint.textContent = shortFingerprint(data.key_fingerprint_sha256);
    els.healthStagingRoot.textContent = data.staging_root || 'D:\\MigrationJobs';
    if (!els.inputStagingDrive.value) {
      els.inputStagingDrive.value = data.staging_root || 'D:\\MigrationJobs';
    }
    const online = data.supabase_mode === 'online';
    els.healthMode.textContent = online ? 'Supabase Online' : 'Offline Local Mode';
    els.healthModeDot.className = `dot ${online ? 'dot-teal' : 'dot-amber'}`;
    els.onedriveAlert.classList.toggle('hidden', !data.staging_in_onedrive);
  }

  async function loadJobs() {
    const data = await apiRequest('/api/operator/jobs');
    state.jobs = Array.isArray(data.jobs) ? data.jobs : [];
    if (state.selectedJobId && !state.jobs.some((j) => j.id === state.selectedJobId)) {
      state.selectedJobId = null;
    }
    if (!state.selectedJobId && state.jobs.length > 0) {
      state.selectedJobId = state.jobs[0].id;
    }
    renderJobsList();
    renderSelectedJob();
  }

  function renderJobsList() {
    clearNode(els.jobsList);
    const q = state.searchQuery.trim().toLowerCase();
    const filtered = state.jobs.filter((job) => {
      if (!q) return true;
      const name = String(job.customer_display_name || '').toLowerCase();
      const code = String(job.job_code || '').toLowerCase();
      return name.includes(q) || code.includes(q);
    });

    if (filtered.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'muted-caption';
      empty.textContent = state.jobs.length === 0 ? 'ยังไม่มีงานลูกค้า กดปุ่มสร้างงานใหม่ด้านบน' : 'ไม่พบงานที่ตรงกับคำค้นหา';
      els.jobsList.appendChild(empty);
      return;
    }

    for (const job of filtered) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `job-row${job.id === state.selectedJobId ? ' active' : ''}`;
      btn.setAttribute('role', 'option');
      btn.setAttribute('aria-selected', String(job.id === state.selectedJobId));
      btn.addEventListener('click', () => {
        state.selectedJobId = job.id;
        renderJobsList();
        renderSelectedJob();
      });

      const top = document.createElement('div');
      top.className = 'job-row-top';

      const nameEl = document.createElement('span');
      nameEl.className = 'job-row-name';
      nameEl.textContent = job.customer_display_name || 'ไม่ระบุชื่อ';

      const pill = document.createElement('span');
      pill.className = `status-pill ${statusPillClass(job.status)}`;
      pill.textContent = job.status || 'CREATED';

      top.appendChild(nameEl);
      top.appendChild(pill);

      const meta = document.createElement('div');
      meta.className = 'job-row-meta';
      const codeSpan = document.createElement('span');
      codeSpan.textContent = job.job_code || job.id.slice(0, 8);
      const modeSpan = document.createElement('span');
      modeSpan.textContent = job.service_mode || 'copy_only';
      const portSpan = document.createElement('span');
      const portVal = job.sandbox && job.sandbox.cdp_port ? `CDP:${job.sandbox.cdp_port}` : 'CDP:—';
      portSpan.textContent = portVal;

      meta.appendChild(codeSpan);
      meta.appendChild(modeSpan);
      meta.appendChild(portSpan);

      btn.appendChild(top);
      btn.appendChild(meta);
      els.jobsList.appendChild(btn);
    }
  }

  function renderFiveLocks(checkResult) {
    clearNode(els.fiveLockChecklist);
    if (!checkResult || !checkResult.locks) {
      els.fiveLockSummary.className = 'fivelock-banner';
      els.fiveLockSummary.textContent = 'ยังไม่ได้รันการตรวจสอบ 5-Lock สำหรับงานนี้';
      return;
    }

    els.fiveLockSummary.className = `fivelock-banner ${checkResult.passed ? 'passed' : 'blocked'}`;
    els.fiveLockSummary.textContent = checkResult.passed
      ? `ผ่านครบทั้ง 5 ล็อก สำหรับปี ${checkResult.target_year} — อนุญาตให้ทำ Soft-Delete ได้`
      : `ปิดกั้นแบบ Fail-Closed สำหรับปี ${checkResult.target_year} — ห้ามลบไฟล์จนกว่าล็อกทั้ง 5 ชั้นจะผ่านครบ`;

    const lockLabels = [
      ['lock_1_gphotos_uploaded', 'Lock 1 · Google Photos Uploaded 100%'],
      ['lock_2_local_sha256', 'Lock 2 · Local SHA-256 Verified 100%'],
      ['lock_3_identity_1to1', 'Lock 3 · 1:1 CloudKit ID & Original Filename'],
      ['lock_4_catalog_completeness', 'Lock 4 · Whole-Year Catalog Completeness'],
      ['lock_5_customer_approval', 'Lock 5 · Customer Explicit Approval'],
    ];

    for (const [key, label] of lockLabels) {
      const info = checkResult.locks[key] || { passed: false, reason: 'ไม่พบข้อมูล' };
      const li = document.createElement('li');
      li.className = 'lock-item';

      const left = document.createElement('div');
      const title = document.createElement('div');
      title.className = 'lock-item-name';
      title.textContent = label;
      const reason = document.createElement('div');
      reason.className = 'lock-item-reason';
      reason.textContent = info.reason || '';
      left.appendChild(title);
      left.appendChild(reason);

      const badge = document.createElement('span');
      badge.className = `status-pill ${info.passed ? 'pill-teal' : 'pill-amber'}`;
      badge.textContent = info.passed ? 'PASS' : 'BLOCKED';

      li.appendChild(left);
      li.appendChild(badge);
      els.fiveLockChecklist.appendChild(li);
    }
  }

  function renderPdpaCertificate(cert) {
    clearNode(els.pdpaCertFields);
    if (!cert) {
      els.pdpaCertBox.classList.add('hidden');
      return;
    }
    els.pdpaCertBox.classList.remove('hidden');

    const rows = [
      ['Job ID', cert.job_id],
      ['Purged At (UTC)', cert.purged_at],
      ['Deleted Files', `${cert.deleted_file_count ?? 0} ไฟล์`],
      ['Remaining Files', `${cert.remaining_files ?? 0} ไฟล์ (ยืนยัน 0 ไฟล์)`],
      ['Payload SHA-256', cert.payload_sha256],
      ['Key Fingerprint', cert.key_fingerprint_sha256],
      ['RSA-PSS Signature', cert.signature_b64],
    ];
    for (const [label, value] of rows) {
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = value == null ? '—' : String(value);
      els.pdpaCertFields.appendChild(dt);
      els.pdpaCertFields.appendChild(dd);
    }
  }

  function renderSelectedJob() {
    const job = getSelectedJob();
    if (!job) {
      els.deskEmpty.classList.remove('hidden');
      els.deskContent.classList.add('hidden');
      return;
    }

    els.deskEmpty.classList.add('hidden');
    els.deskContent.classList.remove('hidden');

    els.detailName.textContent = job.customer_display_name || 'ไม่ระบุชื่อ';
    els.detailStatus.textContent = job.status || 'CREATED';
    els.detailStatus.className = `status-pill ${statusPillClass(job.status)}`;
    els.detailCode.textContent = job.job_code || job.id;
    els.detailMode.textContent = job.service_mode || 'copy_only';
    els.detailAlbum.textContent = job.album_prefix || 'iCloud_Archive_Google';

    const sb = job.sandbox || {};
    els.detailPort.textContent = sb.cdp_port ? String(sb.cdp_port) : '—';
    els.detailSandboxFiles.textContent = `${sb.sensitive_total_files ?? 0} ไฟล์`;

    const ephemeralLink = state.ephemeralLinks.get(job.id);
    if (ephemeralLink) {
      els.lineLinkPanel.classList.remove('hidden');
      els.detailTrackingLink.textContent = ephemeralLink;
    } else {
      els.lineLinkPanel.classList.add('hidden');
    }

    const snap = job.telemetry_snapshot || {};
    els.envelopeResult.textContent = snap.account_masked
      ? `บัญชีใน RAM: ${snap.account_masked} (ซองถูกทำลายแล้ว)`
      : '';
    els.otpResult.textContent = '';
    els.cdpResult.textContent = sb.has_active_process ? 'CDP Uploader กำลังทำงานอยู่' : '';

    if (Array.isArray(job.target_years) && job.target_years.length > 0) {
      els.fiveLockYear.value = String(job.target_years[0]);
    }
    renderFiveLocks(snap.last_five_lock_check || null);
    renderPdpaCertificate(job.pdpa_purge_certificate || null);
  }

  // Event Bindings
  function openCreateModal() {
    els.createError.classList.add('hidden');
    els.createError.textContent = '';
    els.inputCustomerName.value = '';
    els.inputTargetYears.value = '';
    if (state.health && state.health.staging_root) {
      els.inputStagingDrive.value = state.health.staging_root;
    }
    els.modal.showModal();
    els.inputCustomerName.focus();
  }

  document.getElementById('btn-open-create').addEventListener('click', openCreateModal);
  document.getElementById('btn-empty-create').addEventListener('click', openCreateModal);
  document.getElementById('btn-close-modal').addEventListener('click', () => els.modal.close());
  document.getElementById('btn-cancel-create').addEventListener('click', () => els.modal.close());
  document.getElementById('btn-refresh-jobs').addEventListener('click', () => {
    loadHealth().then(loadJobs).catch((err) => showToast(err.message, 'error'));
  });

  els.jobSearch.addEventListener('input', (ev) => {
    state.searchQuery = ev.target.value;
    renderJobsList();
  });

  els.createForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    els.createError.classList.add('hidden');

    const yearsRaw = els.inputTargetYears.value
      .split(/[,\s]+/)
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n) && n >= 1990 && n <= 2100);

    try {
      const created = await apiRequest('/api/operator/jobs', {
        method: 'POST',
        body: JSON.stringify({
          customer_name: els.inputCustomerName.value.trim(),
          service_mode: els.inputServiceMode.value,
          album_prefix: els.inputAlbumPrefix.value.trim() || 'iCloud_Archive_Google',
          staging_drive: els.inputStagingDrive.value.trim() || null,
          target_years: yearsRaw,
        }),
      });
      state.ephemeralLinks.set(created.job.id, created.customer_tracking_link);
      state.selectedJobId = created.job.id;
      els.modal.close();
      await loadJobs();
      showToast(`สร้างงาน ${created.job.job_code} สำเร็จ พร้อมลิงก์ส่ง LINE`, 'success');
    } catch (err) {
      els.createError.textContent = err.message;
      els.createError.classList.remove('hidden');
    }
  });

  document.getElementById('btn-copy-link').addEventListener('click', () => {
    const job = getSelectedJob();
    const link = job && state.ephemeralLinks.get(job.id);
    if (link) copyToClipboard(link, 'คัดลอกลิงก์ติดตามงานลูกค้าแล้ว');
  });

  document.getElementById('btn-copy-line-msg').addEventListener('click', () => {
    const job = getSelectedJob();
    const link = job && state.ephemeralLinks.get(job.id);
    if (!job || !link) return;
    const msg = [
      `สวัสดีครับคุณ ${job.customer_display_name}`,
      `CloudVault Concierge เปิดห้องย้ายภาพส่วนตัว (รหัส ${job.job_code}) เรียบร้อยแล้วครับ`,
      'คุณสามารถกรอกข้อมูลแบบเข้ารหัส End-to-End (RSA-4096) และติดตามสถานะแบบเรียลไทม์ได้ที่ลิงก์นี้ครับ:',
      link,
    ].join('\n');
    copyToClipboard(msg, 'คัดลอกข้อความสำหรับส่ง LINE เรียบร้อยแล้ว');
  });

  document.getElementById('btn-consume-envelope').addEventListener('click', async () => {
    const job = getSelectedJob();
    if (!job) return;
    try {
      const res = await apiRequest(`/api/operator/jobs/${encodeURIComponent(job.id)}/consume-envelope`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      els.envelopeResult.textContent = `ถอดรหัสใน RAM สำเร็จ (${res.account_masked}) · ทำลายซองแล้ว`;
      await loadJobs();
      showToast('ถอดรหัส Envelope ใน RAM และทำลายซองต้นฉบับแล้ว', 'success');
    } catch (err) {
      els.envelopeResult.textContent = err.message;
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-request-otp').addEventListener('click', async () => {
    const job = getSelectedJob();
    if (!job) return;
    const provider = els.otpProvider.value;
    const promptMsg =
      provider === 'icloud'
        ? 'กรุณากรอกรหัสยืนยัน Apple 2FA 6 หลักที่แสดงบน iPhone ของคุณ'
        : 'กรุณากรอกรหัสยืนยัน Google 2FA 6 หลักสำหรับบัญชี Google Photos';
    try {
      const res = await apiRequest(`/api/operator/jobs/${encodeURIComponent(job.id)}/request-otp`, {
        method: 'POST',
        body: JSON.stringify({ provider, prompt_message: promptMsg, ttl_seconds: 300 }),
      });
      els.otpResult.textContent = `ส่งคำขอ OTP แล้ว (Challenge: ${String(res.challenge.id || '').slice(0, 8)})`;
      await loadJobs();
      showToast('ส่งคำขอรหัส 2FA ไปที่หน้าเว็บลูกค้าแล้ว', 'success');
    } catch (err) {
      els.otpResult.textContent = err.message;
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-consume-otp').addEventListener('click', async () => {
    const job = getSelectedJob();
    if (!job) return;
    try {
      await apiRequest(`/api/operator/jobs/${encodeURIComponent(job.id)}/consume-otp`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      els.otpResult.textContent = 'รับรหัส OTP ใน RAM และทำลายรายการบนรีเลย์แล้ว';
      await loadJobs();
      showToast('รับรหัส 2FA OTP และลบออกจากระบบรีเลย์แล้ว', 'success');
    } catch (err) {
      els.otpResult.textContent = err.message;
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-launch-cdp').addEventListener('click', async () => {
    const job = getSelectedJob();
    if (!job) return;
    try {
      const res = await apiRequest(`/api/operator/jobs/${encodeURIComponent(job.id)}/launch-cdp-upload`, {
        method: 'POST',
        body: JSON.stringify({ dry_run: els.cdpDryRun.checked }),
      });
      els.cdpResult.textContent = `เริ่มทำงาน PID ${res.pid} บน CDP Port ${res.cdp_port}`;
      await loadJobs();
      showToast(`เปิด Chrome CDP Uploader (Port ${res.cdp_port}) แล้ว`, 'success');
    } catch (err) {
      els.cdpResult.textContent = err.message;
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-verify-fivelock').addEventListener('click', async () => {
    const job = getSelectedJob();
    if (!job) return;
    const yr = parseInt(els.fiveLockYear.value, 10);
    if (!Number.isFinite(yr)) {
      showToast('กรุณาระบุปี ค.ศ. ให้ถูกต้อง', 'error');
      return;
    }
    try {
      const res = await apiRequest(`/api/operator/jobs/${encodeURIComponent(job.id)}/verify-five-locks`, {
        method: 'POST',
        body: JSON.stringify({ target_year: yr }),
      });
      renderFiveLocks(res);
      await loadJobs();
      showToast(
        res.passed ? `5-Lock Gate ปี ${yr} ผ่านครบทุกชั้น` : `5-Lock Gate ปี ${yr} ถูกปิดกั้น (ยังไม่ครบเงื่อนไข)`,
        res.passed ? 'success' : 'default'
      );
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-pdpa-purge').addEventListener('click', async () => {
    const job = getSelectedJob();
    if (!job) return;
    const ok = window.confirm(
      `ยืนยันการทำ 1-Click PDPA Purge สำหรับงาน ${job.job_code} (${job.customer_display_name})?\n` +
        'ระบบจะลบไฟล์ภาพ โปรไฟล์ Chrome และคุกกี้ iCloud ของลูกค้าออกจากเครื่องนี้ถาวรและออกใบรับรองลงนามดิจิทัล'
    );
    if (!ok) return;
    try {
      const res = await apiRequest(`/api/operator/jobs/${encodeURIComponent(job.id)}/pdpa-purge`, {
        method: 'POST',
      });
      state.ephemeralLinks.delete(job.id);
      renderPdpaCertificate(res.pdpa_certificate);
      await loadJobs();
      showToast(`ล้างข้อมูล PDPA ครบ 0 ไฟล์ และออกใบรับรองแล้ว`, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-copy-cert').addEventListener('click', () => {
    const job = getSelectedJob();
    if (job && job.pdpa_purge_certificate) {
      copyToClipboard(
        JSON.stringify(job.pdpa_purge_certificate, null, 2),
        'คัดลอกใบรับรอง PDPA (JSON) แล้ว'
      );
    }
  });

  // Initial Boot
  loadHealth()
    .then(loadJobs)
    .catch((err) => showToast(`เชื่อมต่อ Workbench ไม่สำเร็จ: ${err.message}`, 'error'));
})();
