"""
CloudVault Concierge — Standalone 1:1 HTML Audit Report Generator.

Applies strict `html.escape(..., quote=True)` to every dynamic value (OWASP A03 XSS defense)
and writes atomically via `.tmp` + `os.replace`.
"""

from __future__ import annotations

import html
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _esc(val: Any) -> str:
    return html.escape("" if val is None else str(val), quote=True)


def generate_standalone_audit_html(
    job_meta: dict[str, Any],
    manifest_data: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """
    Generate a self-contained CloudVault Concierge 1:1 Audit HTML Report.
    Applies strict `html.escape(..., quote=True)` to every dynamic string (OWASP A03).
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    customer_name = _esc(job_meta.get("customer_display_name") or job_meta.get("customer_name") or "Customer")
    job_code = _esc(job_meta.get("job_code") or job_meta.get("id") or "N/A")
    service_mode = _esc(job_meta.get("service_mode") or "copy_only")
    album_prefix = _esc(job_meta.get("album_prefix") or "iCloud_Archive_Google")
    generated_at = _esc(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    years_data = manifest_data.get("years", {}) if isinstance(manifest_data, dict) else {}
    total_files = 0
    total_photos = 0
    total_videos = 0
    total_bytes = 0
    verified_local = 0
    verified_gphotos = 0
    summary_rows: list[str] = []
    file_rows: list[str] = []

    for yr_key in sorted(years_data.keys()):
        months = years_data[yr_key].get("months", {}) if isinstance(years_data[yr_key], dict) else {}
        for mn_key in sorted(months.keys()):
            files = months[mn_key].get("files", []) if isinstance(months[mn_key], dict) else []
            f_count = len(files)
            p_count = sum(1 for x in files if not x.get("is_video", False))
            v_count = sum(1 for x in files if x.get("is_video", False))
            m_bytes = sum(int(x.get("size", 0) or 0) for x in files)
            loc_ok = sum(1 for x in files if x.get("local_verified") is True)
            gp_ok = sum(1 for x in files if x.get("gphotos_uploaded") is True)

            total_files += f_count
            total_photos += p_count
            total_videos += v_count
            total_bytes += m_bytes
            verified_local += loc_ok
            verified_gphotos += gp_ok

            yr_esc = _esc(yr_key)
            mn_esc = _esc(mn_key)
            loc_cls = "ok" if f_count > 0 and loc_ok == f_count else "warn"
            gp_cls = "ok" if f_count > 0 and gp_ok == f_count else "warn"

            summary_rows.append(
                "<tr>"
                f"<td><strong>{yr_esc}</strong></td>"
                f"<td>{mn_esc}</td>"
                f"<td class='num'>{f_count:,}</td>"
                f"<td class='num'>{p_count:,}</td>"
                f"<td class='num'>{v_count:,}</td>"
                f"<td class='num'>{m_bytes / (1024 ** 2):.2f} MB</td>"
                f"<td><span class='badge {loc_cls}'>{loc_ok:,}/{f_count:,}</span></td>"
                f"<td><span class='badge {gp_cls}'>{gp_ok:,}/{f_count:,}</span></td>"
                "</tr>"
            )

            for item in files:
                orig_fn = _esc(item.get("original_filename") or item.get("filename") or "")
                disk_fn = _esc(item.get("filename") or orig_fn)
                created_s = _esc(str(item.get("created") or "")[:19])
                size_i = int(item.get("size", 0) or 0)
                sha_short = _esc(str(item.get("sha256") or "")[:16])
                loc_txt = "SHA-256 Verified" if item.get("local_verified") else "Pending"
                gp_txt = "Uploaded" if item.get("gphotos_uploaded") else "Pending"
                file_rows.append(
                    "<tr>"
                    f"<td>{yr_esc} / {mn_esc}</td>"
                    f"<td><code>{orig_fn}</code></td>"
                    f"<td><code>{disk_fn}</code></td>"
                    f"<td>{created_s}</td>"
                    f"<td class='num'>{size_i:,} B</td>"
                    f"<td><code>{sha_short}</code></td>"
                    f"<td>{_esc(loc_txt)}</td>"
                    f"<td>{_esc(gp_txt)}</td>"
                    "</tr>"
                )

    summary_html = "".join(summary_rows) or "<tr><td colspan='8'>ยังไม่มีรายการไฟล์</td></tr>"
    files_html = "".join(file_rows) or "<tr><td colspan='8'>ยังไม่มีรายการไฟล์</td></tr>"

    document = f"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudVault Concierge — 1:1 Audit Report ({job_code})</title>
<style>
  :root {{
    --bg: #F7F8FA; --surface: #FFFFFF; --ink: #0F172A; --muted: #475569;
    --teal: #0F766E; --cobalt: #0369A1; --amber: #B45309; --border: #E2E8F0;
  }}
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: var(--bg); color: var(--ink); margin: 0; padding: 32px; line-height: 1.5; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px; }}
  h1 {{ font-size: 24px; margin: 0 0 8px 0; color: var(--ink); }}
  .meta {{ color: var(--muted); font-size: 14px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .metric {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
  .metric .label {{ color: var(--muted); font-size: 13px; }}
  .metric .val {{ font-size: 22px; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }}
  h2 {{ font-size: 18px; margin: 28px 0 12px 0; color: var(--ink); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }}
  th {{ background: #F1F5F9; color: var(--ink); font-weight: 600; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  code {{ font-family: Consolas, monospace; font-size: 12px; background: #F1F5F9; padding: 2px 5px; border-radius: 4px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
  .badge.ok {{ background: #CCFBF1; color: var(--teal); }}
  .badge.warn {{ background: #FEF3C7; color: var(--amber); }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>CloudVault Concierge — รายงานตรวจสอบไฟล์ 1:1 (Audit Report)</h1>
    <div class="meta">
      รหัสงาน: <code>{job_code}</code> &nbsp;|&nbsp; ลูกค้า: <strong>{customer_name}</strong>
      &nbsp;|&nbsp; แพ็กเกจ: <code>{service_mode}</code> &nbsp;|&nbsp; อัลบั้มปลายทาง: <code>{album_prefix}</code>
      &nbsp;|&nbsp; สร้างรายงานเมื่อ: {generated_at}
    </div>
  </header>
  <section class="metrics">
    <div class="metric"><div class="label">จำนวนไฟล์ทั้งหมด</div><div class="val">{total_files:,} ไฟล์ ({total_bytes / (1024 ** 2):.2f} MB)</div></div>
    <div class="metric"><div class="label">รูปภาพ / วิดีโอ</div><div class="val">{total_photos:,} รูป / {total_videos:,} วิดีโอ</div></div>
    <div class="metric"><div class="label">ตรวจสอบ SHA-256 ครบถ้วน</div><div class="val">{verified_local:,} / {total_files:,}</div></div>
    <div class="metric"><div class="label">อัปโหลด Google Photos สำเร็จ</div><div class="val">{verified_gphotos:,} / {total_files:,}</div></div>
  </section>
  <h2>1. สรุปแยกตามปีและเดือน (Year &amp; Month Summary)</h2>
  <table>
    <thead><tr><th>ปี (ค.ศ. / พ.ศ.)</th><th>เดือน</th><th>ไฟล์ทั้งหมด</th><th>รูปภาพ</th><th>วิดีโอ</th><th>ขนาดรวม</th><th>SHA-256</th><th>Google Photos</th></tr></thead>
    <tbody>{summary_html}</tbody>
  </table>
  <h2>2. รายการตรวจสอบระดับรายไฟล์ (1:1 Original Filename &amp; SHA-256)</h2>
  <table>
    <thead><tr><th>ปี / เดือน</th><th>ชื่อไฟล์เดิม</th><th>ชื่อไฟล์บนดิสก์</th><th>วัน-เวลาถ่าย</th><th>ขนาด</th><th>SHA-256</th><th>Local</th><th>Google Photos</th></tr></thead>
    <tbody>{files_html}</tbody>
  </table>
</div>
</body>
</html>
"""
    tmp_path = out_file.with_suffix(out_file.suffix + f".{os.getpid()}.tmp")
    tmp_path.write_text(document, encoding="utf-8")
    os.replace(tmp_path, out_file)
    return out_file
