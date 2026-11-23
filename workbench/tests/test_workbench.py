"""
CloudVault Concierge — Comprehensive Python Unit & Integration Tests.

Covers:
1. workbench/crypto_vault.py (RSA-4096, AES-256-GCM + RSA-OAEP, tampering, fingerprint mismatch,
   PDPA RSA-PSS-SHA256 signing/verification, CLI interop)
2. workbench/job_sandbox.py (path traversal defense, dynamic CDP ports 9301..9399,
   active subprocess guard, 1-Click PDPA Purge verifying 0 remaining files)
3. workbench/icloud_engine.py (filename sanitization, O(log N) binary search,
   Fail-Closed 5-Lock Safety Gate across all 5 locks, XSS-safe audit HTML)
4. workbench/server.py (FastAPI TestClient: strict token hashing, envelope & OTP shred,
   5-Lock endpoint, PDPA purge endpoint, 127.0.0.1 binding enforcement)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from workbench.crypto_vault import (  # noqa: E402
    OperatorCryptoVault,
    compute_public_key_fingerprint,
    encrypt_envelope_with_public_pem,
)
from workbench.icloud_engine import (  # noqa: E402
    ICloudJobEngine,
    binary_search_year_bounds,
    compute_sha256,
    generate_standalone_audit_html,
    get_month_folder_name,
    get_year_folder_name,
    normalize_year,
    sanitize_windows_filename,
    verify_five_locks,
)
from workbench.job_sandbox import JobSandboxManager, is_onedrive_path  # noqa: E402
from workbench.server import create_app, run_server  # noqa: E402


# ----------------------------------------------------------------------
# Shared Fixtures
# ----------------------------------------------------------------------
@pytest.fixture(scope="module")
def shared_rsa4096_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate one real RSA-4096 keypair for the test module to keep test execution fast."""
    kdir = tmp_path_factory.mktemp("operator_keys_4096")
    OperatorCryptoVault(keys_dir=kdir, key_size=4096)
    return kdir


@pytest.fixture()
def vault(shared_rsa4096_dir: Path) -> OperatorCryptoVault:
    return OperatorCryptoVault(keys_dir=shared_rsa4096_dir)


def _make_valid_manifest(year: int = 2019, count: int = 3) -> dict[str, Any]:
    yr_folder = get_year_folder_name(year)
    mn_folder = get_month_folder_name(3)
    files = []
    for idx in range(count):
        sha = hashlib.sha256(f"photo-{year}-{idx}".encode("utf-8")).hexdigest()
        files.append(
            {
                "id": f"CK-REC-{year}-{idx:04d}",
                "filename": f"IMG_{1000 + idx}.JPG",
                "original_filename": f"IMG_{1000 + idx}.JPG",
                "size": 1024 * (idx + 1),
                "sha256": sha,
                "is_video": False,
                "created": f"{year}-03-15T10:20:{idx:02d}Z",
                "local_verified": True,
                "gphotos_uploaded": True,
            }
        )
    return {
        "year_catalog_counts": {str(year): count},
        "years": {yr_folder: {"months": {mn_folder: {"files": files}}}},
    }


# ======================================================================
# 1. Crypto Vault Tests
# ======================================================================
class TestCryptoVault:
    def test_rsa4096_keygen_reload_and_fingerprint(self, shared_rsa4096_dir: Path) -> None:
        v1 = OperatorCryptoVault(keys_dir=shared_rsa4096_dir)
        assert (shared_rsa4096_dir / "operator_private.pem").exists()
        assert (shared_rsa4096_dir / "operator_public.pem").exists()
        assert v1._private_key.key_size == 4096

        expected_fp = hashlib.sha256(v1.public_key_pem.encode("utf-8")).hexdigest()
        assert v1.key_fingerprint_sha256 == expected_fp
        assert compute_public_key_fingerprint(v1.public_key_pem) == expected_fp

        # Reloading from existing PEM files preserves identical fingerprint & public key
        v2 = OperatorCryptoVault(keys_dir=shared_rsa4096_dir)
        assert v2.key_fingerprint_sha256 == v1.key_fingerprint_sha256
        assert v2.public_key_pem == v1.public_key_pem

    def test_encrypt_decrypt_roundtrip_and_spki_fingerprint_compat(self, vault: OperatorCryptoVault) -> None:
        secret_payload = {
            "provider": "icloud",
            "apple_id": "customer.thai@example.com",
            "password": "Sup3r-S3cr3t-รหัสผ่าน!",
        }
        envelope = encrypt_envelope_with_public_pem(secret_payload, vault.public_key_pem)
        assert envelope["key_fingerprint_sha256"] == vault.key_fingerprint_sha256

        decrypted = vault.decrypt_envelope(envelope)
        assert decrypted == secret_payload

        # Also accept WebCrypto SPKI DER SHA-256 fingerprint for browser interop
        spki_envelope = dict(envelope)
        spki_envelope["key_fingerprint_sha256"] = vault.spki_fingerprint_sha256
        assert vault.decrypt_envelope(spki_envelope) == secret_payload

    def test_tampered_ciphertext_raises_invalid_tag(self, vault: OperatorCryptoVault) -> None:
        envelope = vault.encrypt_envelope({"apple_id": "a@b.com", "password": "pw"})
        ct_bytes = bytearray(base64.b64decode(envelope["ciphertext_b64"]))
        ct_bytes[0] ^= 0xFF  # flip first byte to corrupt ciphertext/GCM tag
        envelope["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")

        with pytest.raises(InvalidTag):
            vault.decrypt_envelope(envelope)

    def test_fingerprint_mismatch_rejected(self, vault: OperatorCryptoVault) -> None:
        envelope = vault.encrypt_envelope({"apple_id": "a@b.com", "password": "pw"})
        envelope["key_fingerprint_sha256"] = "0" * 64

        with pytest.raises(ValueError, match="Key fingerprint mismatch"):
            vault.decrypt_envelope(envelope)

    def test_pdpa_certificate_sign_and_verify(self, vault: OperatorCryptoVault) -> None:
        payload = {
            "job_id": "job-test-1001",
            "purged_at": "2026-11-23T07:00:00+00:00",
            "deleted_file_count": 42,
            "remaining_files": 0,
        }
        cert = vault.sign_pdpa_certificate(payload)
        assert cert["signature_algorithm"] == "RSA-PSS-SHA256"
        assert cert["key_fingerprint_sha256"] == vault.key_fingerprint_sha256
        assert len(cert["payload_sha256"]) == 64
        assert vault.verify_pdpa_certificate(cert) is True

        # Tampering with any field must invalidate signature verification
        tampered = dict(cert)
        tampered["deleted_file_count"] = 999
        assert vault.verify_pdpa_certificate(tampered) is False

    def test_cli_export_and_decrypt_stdin(self, shared_rsa4096_dir: Path, vault: OperatorCryptoVault) -> None:
        env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
        export_proc = subprocess.run(
            [sys.executable, "-m", "workbench.crypto_vault", "--keys-dir", str(shared_rsa4096_dir), "--export-public-key"],
            capture_output=True,
            text=True,
            check=True,
            env=env,
            timeout=15,
        )
        exported = json.loads(export_proc.stdout)
        assert exported["key_fingerprint_sha256"] == vault.key_fingerprint_sha256

        payload = {"provider": "icloud", "apple_id": "cli@example.com", "password": "cli-secret-password"}
        envelope = encrypt_envelope_with_public_pem(payload, exported["public_key_pem"])
        decrypt_proc = subprocess.run(
            [sys.executable, "-m", "workbench.crypto_vault", "--keys-dir", str(shared_rsa4096_dir), "--decrypt-stdin"],
            input=json.dumps(envelope),
            capture_output=True,
            text=True,
            check=True,
            env=env,
            timeout=15,
        )
        assert json.loads(decrypt_proc.stdout) == payload

    @pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
    def test_nodejs_webcrypto_to_python_decrypt_interop(self, shared_rsa4096_dir: Path, vault: OperatorCryptoVault) -> None:
        """Verify browser/Node.js WebCrypto RSA-OAEP(SHA-256) + AES-256-GCM decrypts cleanly in Python."""
        node_script = r"""
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;
const pem = process.env.OP_PUB_PEM;
const b64Body = pem.replace(/-----BEGIN [A-Z0-9 ]+-----/g, '').replace(/-----END [A-Z0-9 ]+-----/g, '').replace(/\s+/g, '');
const spki = Buffer.from(b64Body, 'base64');
(async () => {
  const fpBuf = await subtle.digest('SHA-256', spki);
  const fpHex = Buffer.from(fpBuf).toString('hex');
  const rsaKey = await subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['wrapKey']);
  const aesKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify({ apple_id: 'webcrypto@test.th', password: 'interop-99!' }));
  const wrapped = await subtle.wrapKey('raw', aesKey, rsaKey, { name: 'RSA-OAEP' });
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, pt);
  process.stdout.write(JSON.stringify({
    version: 1,
    alg: 'RSA-OAEP-256+A256GCM',
    key_fingerprint_sha256: fpHex,
    wrapped_key_b64: Buffer.from(wrapped).toString('base64'),
    iv_b64: Buffer.from(iv).toString('base64'),
    ciphertext_b64: Buffer.from(ct).toString('base64'),
  }));
})();
"""
        node_proc = subprocess.run(
            ["node", "-e", node_script],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "OP_PUB_PEM": vault.public_key_pem},
            timeout=15,
        )
        envelope = json.loads(node_proc.stdout)
        decrypted = vault.decrypt_envelope(envelope)
        assert decrypted == {"apple_id": "webcrypto@test.th", "password": "interop-99!"}


# ======================================================================
# 2. Job Sandbox & 1-Click PDPA Purge Tests
# ======================================================================
class TestJobSandbox:
    @pytest.mark.parametrize(
        "bad_id",
        ["../escape", "..\\escape", "job/../evil", "/etc/passwd", "C:\\Windows\\System32", "abc", "job with spaces", "CON", ""],
    )
    def test_path_traversal_and_invalid_job_ids_rejected(self, tmp_path: Path, bad_id: str) -> None:
        mgr = JobSandboxManager(staging_root=tmp_path / "MigrationJobs")
        with pytest.raises(ValueError):
            mgr.allocate_sandbox(bad_id)

    def test_onedrive_path_detection(self) -> None:
        assert is_onedrive_path(r"C:\Users\User\OneDrive\MigrationJobs") is True
        assert is_onedrive_path(r"D:\MigrationJobs") is False

    def test_dynamic_cdp_port_isolation(self, tmp_path: Path) -> None:
        mgr = JobSandboxManager(staging_root=tmp_path / "MigrationJobs")
        sb1 = mgr.allocate_sandbox("job_alpha_001")
        sb2 = mgr.allocate_sandbox("job_beta_002")

        assert 9301 <= sb1["cdp_port"] <= 9399
        assert 9301 <= sb2["cdp_port"] <= 9399
        assert sb1["cdp_port"] != sb2["cdp_port"]
        # Re-allocating same job returns identical port (idempotent)
        assert mgr.allocate_sandbox("job_alpha_001")["cdp_port"] == sb1["cdp_port"]

    def test_pdpa_purge_blocks_active_process_and_wipes_to_zero(
        self, tmp_path: Path, vault: OperatorCryptoVault
    ) -> None:
        mgr = JobSandboxManager(staging_root=tmp_path / "MigrationJobs")
        sb = mgr.allocate_sandbox("job_purge_001")

        # Populate files (including nested & read-only files) in all 3 sensitive dirs
        f1 = Path(sb["staging_dir"]) / "2020" / "IMG_0001.JPG"
        f1.parent.mkdir(parents=True, exist_ok=True)
        f1.write_bytes(b"fake-jpeg-bytes-12345")

        f2 = Path(sb["chrome_profile_dir"]) / "Default" / "Cookies"
        f2.parent.mkdir(parents=True, exist_ok=True)
        f2.write_bytes(b"sensitive-chrome-cookie")
        os.chmod(f2, stat.S_IREAD)

        f3 = Path(sb["icloud_session_dir"]) / "session.cookiejar"
        f3.write_text("icloud-session-token", encoding="utf-8")

        # Simulate an active subprocess — purge MUST refuse
        class _FakeRunningProc:
            def poll(self) -> int | None:
                return None

        fake_proc = _FakeRunningProc()
        mgr.register_process("job_purge_001", fake_proc)  # type: ignore[arg-type]
        with pytest.raises(RuntimeError, match="active worker subprocess"):
            mgr.execute_pdpa_purge("job_purge_001", vault)

        # Unregister process, then run 1-Click PDPA Purge
        mgr.unregister_process("job_purge_001", fake_proc)  # type: ignore[arg-type]
        cert = mgr.execute_pdpa_purge("job_purge_001", vault)

        assert cert["job_id"] == "job_purge_001"
        assert cert["deleted_file_count"] == 3
        assert cert["remaining_files"] == 0
        assert vault.verify_pdpa_certificate(cert) is True

        # Confirm zero files remain inside sensitive subdirectories
        info_after = mgr.get_sandbox_info("job_purge_001")
        assert info_after["sensitive_total_files"] == 0
        assert not Path(sb["staging_dir"]).exists()
        assert not Path(sb["chrome_profile_dir"]).exists()
        assert not Path(sb["icloud_session_dir"]).exists()
        # Audit receipt written to logs/
        assert (Path(sb["logs_dir"]) / "pdpa_purge_certificate.json").exists()


# ======================================================================
# 3. iCloud Engine & 5-Lock Safety Gate Tests
# ======================================================================
class TestICloudEngine:
    def test_helpers_and_windows_filename_sanitization(self, tmp_path: Path) -> None:
        assert normalize_year(2563) == 2020
        assert normalize_year(2020) == 2020
        assert get_year_folder_name(2020) == "2020 (พ.ศ. 2563)"
        assert get_month_folder_name(1) == "01 - มกราคม"
        assert get_month_folder_name(12) == "12 - ธันวาคม"

        assert sanitize_windows_filename("IMG_1234.JPG") == "IMG_1234.JPG"
        assert sanitize_windows_filename("2563-02-19 16:31:09.mp4") == "2563-02-19 16-31-09.mp4"
        assert sanitize_windows_filename('a<b:c"d/e\\f|g?h*i.mov') == "a-b-c-d-e-f-g-h-i.mov"
        assert sanitize_windows_filename("..") == "unnamed"

        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"cloudvault-test-data")
        assert compute_sha256(sample) == hashlib.sha256(b"cloudvault-test-data").hexdigest()

    def test_binary_search_year_bounds(self) -> None:
        # Descending CloudKit stream: newest (rank 0) -> oldest (rank N-1)
        stream_years = [2024, 2024, 2023, 2023, 2023, 2022, 2021, 2021]
        assert binary_search_year_bounds(len(stream_years), 2023, lambda r: stream_years[r], margin=0) == (2, 4)
        assert binary_search_year_bounds(len(stream_years), 2024, lambda r: stream_years[r], margin=0) == (0, 1)
        assert binary_search_year_bounds(len(stream_years), 2021, lambda r: stream_years[r], margin=0) == (6, 7)
        assert binary_search_year_bounds(len(stream_years), 2019, lambda r: stream_years[r], margin=0) == (0, -1)

    def test_verify_five_locks_fail_closed_for_every_lock(self, tmp_path: Path) -> None:
        approved_ts = "2026-11-23T07:10:00Z"

        # Baseline: ALL 5 locks pass
        manifest_ok = _make_valid_manifest(2019, count=3)
        res_ok = verify_five_locks(manifest_ok, 2019, approved_ts)
        assert res_ok["passed"] is True
        assert res_ok["can_soft_delete"] is True
        assert res_ok["blocking_reasons"] == []

        # Lock 1 failure: 1 file not uploaded to Google Photos
        m1 = _make_valid_manifest(2019, count=3)
        m1["years"]["2019 (พ.ศ. 2562)"]["months"]["03 - มีนาคม"]["files"][1]["gphotos_uploaded"] = False
        r1 = verify_five_locks(m1, 2019, approved_ts)
        assert r1["passed"] is False
        assert r1["locks"]["lock_1_gphotos_uploaded"]["passed"] is False

        # Lock 2 failure: invalid SHA-256 length
        m2 = _make_valid_manifest(2019, count=3)
        m2["years"]["2019 (พ.ศ. 2562)"]["months"]["03 - มีนาคม"]["files"][0]["sha256"] = "short_hash"
        r2 = verify_five_locks(m2, 2019, approved_ts)
        assert r2["passed"] is False
        assert r2["locks"]["lock_2_local_sha256"]["passed"] is False

        # Lock 3 failure: missing original_filename
        m3 = _make_valid_manifest(2019, count=3)
        m3["years"]["2019 (พ.ศ. 2562)"]["months"]["03 - มีนาคม"]["files"][2]["original_filename"] = ""
        r3 = verify_five_locks(m3, 2019, approved_ts)
        assert r3["passed"] is False
        assert r3["locks"]["lock_3_identity_1to1"]["passed"] is False

        # Lock 4 failure: manifest count < catalog count
        m4 = _make_valid_manifest(2019, count=3)
        m4["year_catalog_counts"]["2019"] = 4
        r4 = verify_five_locks(m4, 2019, approved_ts)
        assert r4["passed"] is False
        assert r4["locks"]["lock_4_catalog_completeness"]["passed"] is False

        # Lock 5 failure: missing customer approval timestamp
        r5 = verify_five_locks(manifest_ok, 2019, None)
        assert r5["passed"] is False
        assert r5["locks"]["lock_5_customer_approval"]["passed"] is False

        # Engine soft_delete MUST raise PermissionError when any lock fails
        engine = ICloudJobEngine("job_lock_001", tmp_path / "s", tmp_path / "c", tmp_path / "l")
        with pytest.raises(PermissionError, match="5-Lock Safety Gate blocked"):
            engine.soft_delete_verified_year(manifest_ok, 2019, None, dry_run=False)

    def test_generate_standalone_audit_html_escapes_xss(self, tmp_path: Path) -> None:
        manifest = _make_valid_manifest(2020, count=1)
        manifest["years"]["2020 (พ.ศ. 2563)"]["months"]["03 - มีนาคม"]["files"][0][
            "original_filename"
        ] = '<script>alert("xss")</script>.jpg'
        out_html = tmp_path / "audit.html"
        generate_standalone_audit_html(
            {"job_code": "CV-XSS-01", "customer_display_name": '"><img src=x onerror=alert(1)>'},
            manifest,
            out_html,
        )
        content = out_html.read_text(encoding="utf-8")
        assert "<script>alert(" not in content
        assert "<img src=x onerror=" not in content
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;.jpg" in content


# ======================================================================
# 4. FastAPI Operator Workbench Server Integration Tests
# ======================================================================
class TestOperatorServer:
    def test_create_job_token_hashing_envelope_otp_and_pdpa_purge(
        self, tmp_path: Path, shared_rsa4096_dir: Path
    ) -> None:
        state_file = tmp_path / "local_state" / "jobs.json"
        staging_root = tmp_path / "MigrationJobs"
        app = create_app(
            staging_root=staging_root,
            keys_dir=shared_rsa4096_dir,
            local_state_path=state_file,
            public_web_url="https://vault.example.com",
            supabase_url="",
            service_role_key="",
        )
        client = TestClient(app)

        # 1. Health & UI check
        health = client.get("/api/operator/health")
        assert health.status_code == 200
        hdata = health.json()
        assert hdata["brand"] == "CloudVault Concierge"
        assert hdata["bind_host"] == "127.0.0.1"
        assert hdata["port"] == 8790

        ui_resp = client.get("/")
        assert ui_resp.status_code == 200
        assert "CloudVault Concierge" in ui_resp.text

        # 2. Reject OneDrive staging drive
        bad_resp = client.post(
            "/api/operator/jobs",
            json={
                "customer_name": "Test User",
                "service_mode": "copy_only",
                "staging_drive": r"C:\Users\User\OneDrive\Jobs",
            },
        )
        assert bad_resp.status_code == 400

        # 3. Create Job -> verify raw token returned ONCE and ONLY SHA-256 hash stored
        create_resp = client.post(
            "/api/operator/jobs",
            json={
                "customer_name": "คุณสมศรี",
                "service_mode": "move_free_space",
                "album_prefix": "Somsri_Archive",
                "target_years": [2019],
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        job_id = created["job"]["id"]
        raw_token = created["raw_token"]
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        assert f"/job/{job_id}?t={raw_token}" in created["customer_tracking_link"]
        assert created["job"]["token_hash_sha256"] == expected_hash
        assert "raw_token" not in created["job"]

        # Verify raw_token is NEVER stored on disk in local state or returned by GET /jobs
        persisted_raw_text = state_file.read_text(encoding="utf-8")
        assert raw_token not in persisted_raw_text
        assert expected_hash in persisted_raw_text

        jobs_list_resp = client.get("/api/operator/jobs")
        assert jobs_list_resp.status_code == 200
        assert raw_token not in jobs_list_resp.text

        # 4. E2E Credential Envelope consume & immediate shred
        env_cipher = app.state.vault.encrypt_envelope(
            {"provider": "icloud", "apple_id": "somsri@icloud.com", "password": "MySecretPassword!"}
        )
        app.state.relay.enqueue_envelope_local(job_id, "icloud", env_cipher)
        consume_resp = client.post(f"/api/operator/jobs/{job_id}/consume-envelope", json={"provider": "icloud"})
        assert consume_resp.status_code == 200
        cdata = consume_resp.json()
        assert cdata["envelope_shredded"] is True
        assert "MySecretPassword!" not in consume_resp.text
        # Second consume MUST 404 (already shredded!)
        assert client.post(f"/api/operator/jobs/{job_id}/consume-envelope", json={}).status_code == 404

        # 5. Interactive 2FA OTP request + consume & shred
        otp_req = client.post(
            f"/api/operator/jobs/{job_id}/request-otp",
            json={"provider": "icloud", "prompt_message": "กรอกรหัส 6 หลัก", "ttl_seconds": 300},
        )
        assert otp_req.status_code == 200
        challenge_id = otp_req.json()["challenge"]["id"]
        otp_cipher = app.state.vault.encrypt_envelope({"otp_code": "654321"})
        app.state.relay.submit_otp_local(job_id, challenge_id, otp_cipher)

        otp_consume = client.post(f"/api/operator/jobs/{job_id}/consume-otp", json={"challenge_id": challenge_id})
        assert otp_consume.status_code == 200
        assert otp_consume.json()["otp_shredded"] is True
        assert "654321" not in otp_consume.text

        # 6. Verify 5-Lock Gate endpoint (blocked without approval -> passed with approval)
        manifest = _make_valid_manifest(2019, count=2)
        fl_blocked = client.post(
            f"/api/operator/jobs/{job_id}/verify-five-locks",
            json={"target_year": 2019, "manifest_data": manifest},
        )
        assert fl_blocked.status_code == 200
        assert fl_blocked.json()["passed"] is False

        fl_pass = client.post(
            f"/api/operator/jobs/{job_id}/verify-five-locks",
            json={
                "target_year": 2019,
                "manifest_data": manifest,
                "customer_approved_at": "2026-11-23T07:20:00Z",
            },
        )
        assert fl_pass.status_code == 200
        assert fl_pass.json()["passed"] is True

        # 7. Populate sandbox sensitive files & execute 1-Click PDPA Purge endpoint
        sb_root = staging_root / job_id
        (sb_root / "staging" / "photo1.heic").write_bytes(b"heic-payload")
        (sb_root / "chrome_profile" / "Login Data").write_bytes(b"chrome-data")
        (sb_root / "icloud_session" / "cookies.txt").write_text("cookie", encoding="utf-8")

        purge_resp = client.post(f"/api/operator/jobs/{job_id}/pdpa-purge")
        assert purge_resp.status_code == 200
        pdata = purge_resp.json()
        cert = pdata["pdpa_certificate"]
        assert pdata["status"] == "COMPLETED"
        assert cert["deleted_file_count"] == 3
        assert cert["remaining_files"] == 0
        assert app.state.vault.verify_pdpa_certificate(cert) is True
        assert app.state.sandbox.get_sandbox_info(job_id)["sensitive_total_files"] == 0

    def test_refuses_binding_to_0_0_0_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORKBENCH_HOST", "0.0.0.0")
        with pytest.raises(RuntimeError, match="127.0.0.1"):
            run_server()
