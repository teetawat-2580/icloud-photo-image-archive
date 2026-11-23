"""
TDD Test Suite for CloudVault Concierge — Zero-Knowledge Encrypted AI Search Vault.

Seams tested:
1. `workbench.search_vault_crypto` — One-Way Public-Key E2EE (RSA-OAEP-256 + AES-256-GCM + PBKDF2-SHA256 600k iter).
2. `workbench.media_source_adapter` — Pluggable Media Source Adapter (Google Photos Shared -> Future NAS/Immich zero-reindex remap).
3. `workbench.r2_storage_client` — Pure-Python Cloudflare R2 AWS SigV4 signer + path-confined Local Encrypted NAS fallback.
4. `workbench.search_vault_indexer` — Face cosine clustering, Thai/English OCR & semantic tag indexing, ciphertext-only publish, and plaintext purge.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from workbench.media_source_adapter import (
    EXAMPLE_SHARED_ALBUMS_TEMPLATE,
    MediaSourceConfig,
    remap_index_media_source,
    resolve_asset_destination,
)
from workbench.r2_storage_client import (
    CloudflareR2Config,
    LocalEncryptedNasStorage,
    build_sigv4_headers,
    validate_object_key,
)
from workbench.search_vault_crypto import (
    PBKDF2_ITERATIONS_DEFAULT,
    decrypt_private_key_with_passphrase,
    decrypt_search_index_bundle,
    decrypt_vault_blob_aes_gcm,
    encrypt_private_key_with_passphrase,
    encrypt_search_index_bundle,
    encrypt_vault_blob_aes_gcm,
    generate_customer_rsa_keypair,
    unwrap_vault_data_key,
    wrap_vault_data_key_for_customer,
)
from workbench.search_vault_indexer import (
    SearchVaultIndexer,
    cluster_face_embeddings_cosine,
)


def test_one_way_public_key_e2ee_roundtrip_and_tamper_rejection():
    customer_passphrase = "Mom-Secret-Vault-Passphrase-2569!"
    keypair = generate_customer_rsa_keypair(key_size=2048)

    # Passphrase-protect private key (mirrors Browser WebCrypto PBKDF2-SHA256 + AES-256-GCM)
    enc_priv = encrypt_private_key_with_passphrase(
        keypair["private_key_pkcs8_pem"],
        customer_passphrase,
        iterations=10_000,  # Fast iteration override strictly for unit tests; default is 600_000
    )
    assert PBKDF2_ITERATIONS_DEFAULT >= 600_000
    assert enc_priv["kdf"] == "PBKDF2-SHA256"
    assert enc_priv["alg"] == "AES-256-GCM"

    # Wrong passphrase must fail cleanly
    with pytest.raises(InvalidTag):
        decrypt_private_key_with_passphrase(enc_priv, "Wrong-Passphrase")

    # Correct passphrase recovers PKCS#8 private key PEM
    recovered_priv_pem = decrypt_private_key_with_passphrase(enc_priv, customer_passphrase)
    assert recovered_priv_pem == keypair["private_key_pkcs8_pem"]

    # Operator PC wraps a fresh 32-byte vault data key ONE-WAY using ONLY customer's public key
    vault_data_key = hashlib.sha256(b"ephemeral-vault-data-key-seed").digest()
    wrapped_key_b64 = wrap_vault_data_key_for_customer(vault_data_key, keypair["public_key_pem"])

    # Unwrap with customer's private key
    unwrapped_key = unwrap_vault_data_key(wrapped_key_b64, recovered_priv_pem)
    assert unwrapped_key == vault_data_key

    # Other keypair (e.g., Operator PC's own key) CANNOT unwrap customer's vault data key
    attacker_keypair = generate_customer_rsa_keypair(key_size=2048)
    with pytest.raises(ValueError):
        unwrap_vault_data_key(wrapped_key_b64, attacker_keypair["private_key_pkcs8_pem"])

    # Encrypt + decrypt Thai/English Search Index Bundle with AAD binding
    vault_id = "vault-mom-2026"
    sample_index = {
        "schema_version": 2,
        "vault_id": vault_id,
        "media_source_type": "google_photos_shared",
        "people": [{"person_id": "person_001", "default_label": "คนที่ 1", "photo_count": 2}],
        "assets": [
            {
                "sha256": "a" * 64,
                "filename": "IMG_2018_CAKE.JPG",
                "captured_at": "2018-12-31T21:12:24+07:00",
                "year": 2018,
                "thumb_key": "thumbs/a" + "0" * 15 + ".enc",
                "face_ids": ["person_001"],
                "ocr_text": "สวัสดีปีใหม่ 2562 Happy New Year",
                "semantic_tags": ["เค้ก", "ครอบครัว", "birthday cake"],
                "media_ref": {
                    "provider": "google_photos_shared",
                    "album_key": "2005-2008",
                    "url": "https://photos.app.goo.gl/ExampleShared2005To2008",
                },
            }
        ],
    }

    encrypted_bundle, index_sha256 = encrypt_search_index_bundle(sample_index, vault_data_key, vault_id)
    assert len(index_sha256) == 64
    assert b"2562" not in encrypted_bundle
    assert "สวัสดีปีใหม่".encode("utf-8") not in encrypted_bundle

    decrypted_index = decrypt_search_index_bundle(encrypted_bundle, unwrapped_key, vault_id)
    assert decrypted_index == sample_index

    # Wrong vault_id (AAD mismatch) or tampered ciphertext byte MUST fail authentication
    with pytest.raises(InvalidTag):
        decrypt_search_index_bundle(encrypted_bundle, unwrapped_key, "wrong-vault-id")

    tampered = bytearray(encrypted_bundle)
    tampered[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_search_index_bundle(bytes(tampered), unwrapped_key, vault_id)

    # Thumbnail blob AES-GCM roundtrip
    raw_webp = b"RIFF\x24\x00\x00\x00WEBPVP8 fake-thumbnail-bytes"
    enc_thumb = encrypt_vault_blob_aes_gcm(raw_webp, vault_data_key, aad=f"{vault_id}:thumb_01".encode("utf-8"))
    assert b"WEBP" not in enc_thumb
    assert decrypt_vault_blob_aes_gcm(enc_thumb, unwrapped_key, aad=f"{vault_id}:thumb_01".encode("utf-8")) == raw_webp


def test_pluggable_media_source_adapter_resolves_and_remaps_gphotos_to_nas_without_reindexing():
    assert len(EXAMPLE_SHARED_ALBUMS_TEMPLATE) == 8
    assert EXAMPLE_SHARED_ALBUMS_TEMPLATE["2014-2016"]["short_url"] == "https://photos.app.goo.gl/ExampleShared2014To2016"

    gp_cfg = MediaSourceConfig(
        source_type="google_photos_shared",
        albums=EXAMPLE_SHARED_ALBUMS_TEMPLATE,
    )
    resolved = resolve_asset_destination(
        {"sha256": "1" * 64, "year": 2015, "filename": "IMG_1001.JPG"},
        gp_cfg,
    )
    assert resolved["provider"] == "google_photos_shared"
    assert resolved["url"] == "https://photos.app.goo.gl/ExampleShared2014To2016"

    # Reject dangerous XSS / javascript: URLs strictly
    with pytest.raises(ValueError):
        resolve_asset_destination(
            {"sha256": "2" * 64, "year": 2015, "direct_url": "javascript:alert(1)"},
            gp_cfg,
        )

    # Zero-Reindex Remap: Google Photos Shared -> Home NAS / Immich preserving all AI metadata 100%
    index_before = {
        "schema_version": 2,
        "vault_id": "vault-mom",
        "media_source_type": "google_photos_shared",
        "assets": [
            {
                "sha256": "1" * 64,
                "filename": "IMG_1001.JPG",
                "year": 2015,
                "face_ids": ["person_001", "person_002"],
                "ocr_text": "สวัสดีปีใหม่ 2562",
                "semantic_tags": ["เค้ก", "ครอบครัว"],
                "media_ref": resolved,
            }
        ],
    }
    nas_cfg = MediaSourceConfig(
        source_type="nas_immich",
        nas_base_url="https://photos.momhome.example.com",
    )
    remapped = remap_index_media_source(
        index_before,
        nas_cfg,
        sha256_to_new_ref={"1" * 64: {"asset_id": "immich-uuid-999", "relative_path": "2015/01/IMG_1001.JPG"}},
    )
    assert remapped["media_source_type"] == "nas_immich"
    asset_after = remapped["assets"][0]
    assert asset_after["face_ids"] == ["person_001", "person_002"]
    assert asset_after["ocr_text"] == "สวัสดีปีใหม่ 2562"
    assert asset_after["semantic_tags"] == ["เค้ก", "ครอบครัว"]
    assert asset_after["media_ref"]["provider"] == "nas_immich"
    assert asset_after["media_ref"]["url"] == "https://photos.momhome.example.com/photos/immich-uuid-999"


def test_r2_sigv4_signer_and_local_encrypted_nas_storage_confinement(tmp_path: Path):
    # Path traversal validation
    assert validate_object_key("vaults/v1/index_bundle.json.gz.enc") == "vaults/v1/index_bundle.json.gz.enc"
    with pytest.raises(ValueError):
        validate_object_key("../etc/passwd")
    with pytest.raises(ValueError):
        validate_object_key("/absolute/path.enc")

    # Pure-Python AWS SigV4 headers for Cloudflare R2 (zero boto3 dependency)
    r2_cfg = CloudflareR2Config(
        account_id="acct1234567890",
        access_key_id="AKIAEXAMPLEKEY",
        secret_access_key="SecretExampleKey1234567890",
        bucket_name="cloudvault-search-blobs",
    )
    headers = build_sigv4_headers(
        method="PUT",
        url=r2_cfg.object_url("vaults/v1/thumbs/abc.enc"),
        payload_bytes=b"encrypted-ciphertext-payload",
        config=r2_cfg,
        content_type="application/octet-stream",
        amz_date="20261123T080000Z",
    )
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY/20261123/auto/s3/aws4_request")
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in headers["Authorization"]
    assert headers["x-amz-date"] == "20261123T080000Z"
    assert headers["x-amz-content-sha256"] == hashlib.sha256(b"encrypted-ciphertext-payload").hexdigest()

    # Local Encrypted NAS fallback (PC acting as NAS)
    store = LocalEncryptedNasStorage(tmp_path / "encrypted_blobs")
    store.put_encrypted_object("vaults/v1/thumbs/abc.enc", b"\x00\x01cipherbytes")
    assert store.get_encrypted_object("vaults/v1/thumbs/abc.enc") == b"\x00\x01cipherbytes"
    deleted = store.delete_vault_prefix("vaults/v1")
    assert deleted == 1
    assert store.get_encrypted_object("vaults/v1/thumbs/abc.enc") is None


def test_search_vault_indexer_clusters_faces_extracts_thai_ocr_encrypts_all_blobs_and_purges_plaintext(tmp_path: Path):
    # Cosine face clustering check
    clusters = cluster_face_embeddings_cosine(
        [
            {"asset_sha256": "a" * 64, "embedding": [1.0, 0.0, 0.0, 0.0]},
            {"asset_sha256": "b" * 64, "embedding": [0.98, 0.1, 0.0, 0.0]},
            {"asset_sha256": "c" * 64, "embedding": [0.0, 0.0, 1.0, 0.0]},
        ],
        similarity_threshold=0.75,
    )
    assert len(clusters) == 2
    assert clusters[0]["photo_count"] == 2
    assert clusters[1]["photo_count"] == 1

    # End-to-end Zero-Knowledge Indexing -> Encrypted Publish -> Customer Browser Decryption
    media_dir = tmp_path / "source_media" / "2018" / "12"
    media_dir.mkdir(parents=True)
    img1 = media_dir / "IMG_2018_CAKE.JPG"
    img2 = media_dir / "IMG_2018_FAMILY.JPG"
    img1.write_bytes(b"\xff\xd8\xff\xe0FAKEJPEG-CAKE-PLAINTEXT-SECRET")
    img2.write_bytes(b"\xff\xd8\xff\xe0FAKEJPEG-FAMILY-PLAINTEXT-SECRET")

    customer_keys = generate_customer_rsa_keypair(key_size=2048)
    blob_store = LocalEncryptedNasStorage(tmp_path / "r2_or_pc_nas_store")
    temp_work_dir = tmp_path / "indexer_tmp"

    def fake_face_extractor(path: Path) -> list[dict]:
        if "CAKE" in path.name:
            return [{"embedding": [1.0, 0.0, 0.0, 0.0], "bbox": [10, 10, 80, 80]}]
        return [
            {"embedding": [0.99, 0.05, 0.0, 0.0], "bbox": [15, 15, 90, 90]},
            {"embedding": [0.0, 1.0, 0.0, 0.0], "bbox": [120, 15, 190, 90]},
        ]

    def fake_ocr_extractor(path: Path) -> str:
        if "CAKE" in path.name:
            return "สวัสดีปีใหม่ 2562"
        return "บ้านคุณยาย 2018"

    def fake_tag_extractor(path: Path) -> list[str]:
        if "CAKE" in path.name:
            return ["เค้ก", "birthday cake", "ครอบครัว"]
        return ["ครอบครัว", "family"]

    def fake_thumb_maker(path: Path) -> bytes:
        return b"RIFF\x10\x00\x00\x00WEBPVP8-" + path.name.encode("utf-8")

    indexer = SearchVaultIndexer(
        face_extractor=fake_face_extractor,
        ocr_extractor=fake_ocr_extractor,
        tag_extractor=fake_tag_extractor,
        thumbnail_maker=fake_thumb_maker,
    )

    source_cfg = MediaSourceConfig(
        source_type="google_photos_shared",
        albums=EXAMPLE_SHARED_ALBUMS_TEMPLATE,
    )

    pub = indexer.build_and_publish_encrypted_vault(
        vault_id="vault-mom-test-01",
        source_files=[
            {"path": img1, "year": 2018, "captured_at": "2018-12-31T21:12:24+07:00"},
            {"path": img2, "year": 2018, "captured_at": "2018-12-31T20:00:00+07:00"},
        ],
        customer_public_key_pem=customer_keys["public_key_pem"],
        storage_client=blob_store,
        media_source_config=source_cfg,
        temp_work_dir=temp_work_dir,
    )

    assert pub["total_assets"] == 2
    assert pub["total_faces"] == 2
    assert pub["total_ocr_assets"] == 2
    assert pub["plaintext_purged"] is True
    assert not temp_work_dir.exists() or list(temp_work_dir.rglob("*")) == []

    # Verify ZERO plaintext OCR text or WebP headers appear in stored encrypted objects
    enc_index_bytes = blob_store.get_encrypted_object(pub["index_object_key"])
    assert enc_index_bytes is not None
    assert "สวัสดีปีใหม่".encode("utf-8") not in enc_index_bytes
    assert b"IMG_2018_CAKE" not in enc_index_bytes

    # Customer decrypts the vault using ONLY their own Private Key
    recovered_vault_key = unwrap_vault_data_key(pub["wrapped_vault_key_b64"], customer_keys["private_key_pkcs8_pem"])
    decrypted_index = decrypt_search_index_bundle(enc_index_bytes, recovered_vault_key, "vault-mom-test-01")

    assert len(decrypted_index["assets"]) == 2
    assert len(decrypted_index["people"]) == 2
    cake_asset = next(a for a in decrypted_index["assets"] if a["filename"] == "IMG_2018_CAKE.JPG")
    assert "สวัสดีปีใหม่ 2562" in cake_asset["ocr_text"]
    assert cake_asset["media_ref"]["url"] == "https://photos.app.goo.gl/ExampleShared2005To2008"

    # Decrypt thumbnail blob and verify original bytes
    enc_thumb = blob_store.get_encrypted_object(cake_asset["thumb_key"])
    assert enc_thumb is not None
    assert b"WEBPVP8-" not in enc_thumb
    dec_thumb = decrypt_vault_blob_aes_gcm(
        enc_thumb,
        recovered_vault_key,
        aad=f"vault-mom-test-01:{cake_asset['thumb_key']}".encode("utf-8"),
    )
    assert dec_thumb.startswith(b"RIFF")
    assert b"IMG_2018_CAKE.JPG" in dec_thumb


def test_fastapi_operator_vault_endpoints_create_build_and_serve_ciphertext_only(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient

    from workbench.server import create_app

    monkeypatch.setenv("SEARCH_VAULT_BLOBS_ROOT", str(tmp_path / "encrypted_blobs"))
    monkeypatch.delenv("R2_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("R2_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("R2_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("R2_BUCKET_NAME", raising=False)

    app = create_app(
        staging_root=tmp_path / "staging",
        keys_dir=tmp_path / "keys",
        local_state_path=tmp_path / "local_state.json",
        public_web_url="https://icloud-photo-image-archive.vercel.app",
        supabase_url="",
        service_role_key="",
    )
    client = TestClient(app)

    # 1. Create Search Vault
    res = client.post(
        "/api/operator/vaults",
        json={
            "owner_display_name": "Family Archive Demo",
            "storage_backend": "pc_tunnel_nas",
            "media_source_type": "google_photos_shared",
            "media_source_config": {"albums": EXAMPLE_SHARED_ALBUMS_TEMPLATE},
        },
    )
    assert res.status_code == 200
    created = res.json()
    vault_id = created["vault"]["id"]
    assert created["customer_vault_url"].startswith(
        f"https://icloud-photo-image-archive.vercel.app/vault/{vault_id}?t="
    )
    assert "access_token_hash_sha256" not in created["vault"]

    # 2. Prepare temp source folder and register customer's public key
    src_dir = tmp_path / "photos" / "2018"
    src_dir.mkdir(parents=True)
    (src_dir / "IMG_2018_001.JPG").write_bytes(b"\xff\xd8\xff\xe0MOCK-IMAGE-DATA")
    customer_keys = generate_customer_rsa_keypair(key_size=2048)

    # 3. Build & publish encrypted index using ONLY customer public key
    build_res = client.post(
        f"/api/operator/vaults/{vault_id}/build-index",
        json={
            "source_dir": str(tmp_path / "photos"),
            "customer_public_key_pem": customer_keys["public_key_pem"],
        },
    )
    assert build_res.status_code == 200
    pub = build_res.json()["published"]
    assert pub["total_assets"] == 1
    assert pub["plaintext_purged"] is True

    # 4. Serve opaque encrypted index blob from PC NAS endpoint and decrypt with customer private key
    blob_res = client.get(f"/api/operator/vaults/{vault_id}/blobs/{pub['index_object_key']}")
    assert blob_res.status_code == 200
    assert b"IMG_2018_001" not in blob_res.content

    recovered_key = unwrap_vault_data_key(pub["wrapped_vault_key_b64"], customer_keys["private_key_pkcs8_pem"])
    dec_index = decrypt_search_index_bundle(blob_res.content, recovered_key, vault_id)
    assert dec_index["assets"][0]["filename"] == "IMG_2018_001.JPG"

    # 5. Cross-vault blob access MUST be rejected (403)
    cross_res = client.get(f"/api/operator/vaults/other-vault-id/blobs/{pub['index_object_key']}")
    assert cross_res.status_code == 403

