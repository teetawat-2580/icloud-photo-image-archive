export type ServiceMode = 'copy_only' | 'move_free_space' | 'move_and_export';

export type JobStatus =
  | 'CREATED'
  | 'AWAITING_CREDENTIALS'
  | 'CREDENTIALS_RECEIVED'
  | 'AWAITING_2FA_ICLOUD'
  | 'SCANNING_CATALOG'
  | 'YEAR_SELECTION'
  | 'DOWNLOADING_VERIFYING'
  | 'AWAITING_2FA_GOOGLE'
  | 'UPLOADING_GPHOTOS'
  | 'AUDIT_READY'
  | 'AWAITING_5LOCK_APPROVAL'
  | 'CLEANING_ICLOUD'
  | 'PURGING_PDPA'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type CredentialProvider = 'icloud' | 'google_photos';

export type OtpChallengeStatus =
  | 'WAITING_CUSTOMER'
  | 'SUBMITTED'
  | 'CONSUMED'
  | 'EXPIRED';

export interface EncryptedEnvelope {
  version: 1;
  alg: 'RSA-OAEP-256+A256GCM';
  key_fingerprint_sha256: string;
  wrapped_key_b64: string;
  iv_b64: string;
  ciphertext_b64: string;
}

export interface OperatorNodePublic {
  id: string;
  label: string;
  public_key_pem: string;
  key_fingerprint_sha256: string;
  last_heartbeat_at: string;
}

export interface FiveLockStatus {
  lock1_local_sha256?: boolean | string;
  lock2_gphotos_uploaded?: boolean | string;
  lock3_album_isolated?: boolean | string;
  lock4_audit_reconciled?: boolean | string;
  lock5_customer_approved?: boolean | string;
  [key: string]: boolean | string | number | null | undefined;
}

export interface JobYearProgress {
  id: string;
  job_id: string;
  year: number;
  catalog_count: number;
  downloaded_count: number;
  verified_count: number;
  uploaded_count: number;
  cleaned_count: number;
  total_bytes: number;
  gphotos_album_title: string | null;
  gphotos_album_url: string | null;
  five_lock_status: FiveLockStatus;
  updated_at: string;
}

export interface OtpChallenge {
  id: string;
  job_id: string;
  provider: CredentialProvider;
  prompt_message: string;
  status: OtpChallengeStatus;
  expires_at: string;
  created_at: string;
}

export interface PdpaPurgeCertificate {
  certificate_id?: string;
  job_code?: string;
  customer_display_name?: string;
  purged_at?: string;
  operator_node_label?: string;
  operator_key_fingerprint_sha256?: string;
  key_fingerprint_sha256?: string;
  shred_method?: string;
  items_purged?: {
    local_staging_files?: number;
    local_staging_bytes?: number;
    session_cookies_shredded?: boolean;
    credential_envelopes_shredded?: boolean;
    otp_challenges_shredded?: boolean;
    audit_hashes_only_retained?: boolean;
  };
  verification_hash_sha256?: string;
  payload_sha256?: string;
  signature_algorithm?: string;
  signature_b64?: string;
  notes?: string;
}

export interface TelemetrySnapshot {
  current_step_label?: string;
  current_year?: number | null;
  current_file?: string | null;
  transfer_speed_mbps?: number | null;
  last_operator_note?: string | null;
  sha256_mismatch_count?: number;
  isolation_guard_passed?: boolean;
  [key: string]: unknown;
}

export interface MigrationJob {
  id: string;
  operator_node_id: string;
  job_code: string;
  customer_display_name: string;
  service_mode: ServiceMode;
  status: JobStatus;
  target_years: number[];
  album_prefix: string;
  total_files: number;
  downloaded_files: number;
  verified_sha256_files: number;
  uploaded_files: number;
  total_bytes: number;
  reclaimed_bytes: number;
  five_lock_approved_by_customer_at: string | null;
  pdpa_purged_at: string | null;
  pdpa_purge_certificate: PdpaPurgeCertificate | null;
  telemetry_snapshot: TelemetrySnapshot;
  created_at: string;
  updated_at: string;
}

export interface PendingEnvelopeSummary {
  id: string;
  provider: CredentialProvider;
  key_fingerprint_sha256: string;
  consumed_at: string | null;
  expires_at: string;
  created_at: string;
}

export interface JobStatusResponse {
  job: MigrationJob;
  operator: OperatorNodePublic | null;
  years: JobYearProgress[];
  active_otp_challenges: OtpChallenge[];
  recent_envelopes: PendingEnvelopeSummary[];
  server_time: string;
}
