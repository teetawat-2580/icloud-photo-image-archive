# ADR-0003: Per-Customer Dedicated Chrome Automation Profile CDP

- **Status**: Accepted
- **Date**: 2026-11-23

## Context
Google Photos Library API enforces strict daily upload quotas (`10,000` requests/day) and strips/restricts album workflows compared to the Google Photos Web uploader. Conversely, attaching CDP to the operator's personal Chrome profile risks cross-customer cookie mixing, personal tab interference, and Chrome 144+ `Allow` remote-debugging consent prompts on every session.

## Decision
Launch a **Dedicated Chrome Automation Profile** per customer job (`workbench/cdp/dedicated_chrome_manager.js`):
- Each `job_id` spawns Chrome with `--user-data-dir=D:\MigrationJobs\<job_id>\chrome_profile` and an isolated dynamic CDP port (`9301..9399`).
- All upload automation enforces the generalized `3-Layer Personal Album Isolation Guard`, `Strict Single-Line Album Menu Item Isolation` (blocking `Animation`, `Collage`, `Highlight video`, `Shared album`), and `100% Selection Completeness Gate`.
- Upon `1-Click PDPA Purge`, the job's Chrome process is terminated and `chrome_profile` is permanently wiped from disk.

## Consequences
- `0` Chrome `Allow` confirmation prompts during automated upload runs.
- `0` Google Photos API daily quota bottlenecks (capable of migrating `100,000+` photos per customer).
- `0%` cookie, session, or album cross-contamination between customers or with the operator's personal browser.
