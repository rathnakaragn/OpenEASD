Here is the full **OpenEASD Product Requirements Document (PRD)** converted into a clean and structured **Markdown format** for clarity and documentation use.

***

# OpenEASD Product Requirements Document (PRD)

**Product:** OpenEASD — Automated External Attack Surface Detection (Multi‑tenant)
**Author:** Rathnakara G N / Cybersecify
**Version:** 2.1 (Multi‑Org + Scheduling)
**Date:** October 2025
**Target Audience:** Product Managers, Engineering, Security Analysts, Operations, Sales

***

## 1. Executive Summary

OpenEASD will be extended to support simultaneous scanning of multiple organizations (multi‑tenant) and flexible notification cadences (daily, weekly, biweekly, monthly, plus real‑time critical alerts). The system performs high‑impact unauthenticated external checks for startups: passive and active subdomain discovery, port/service scans, web misconfiguration checks, certificate and email hygiene, and public credential/secret exposure.

Results will be delivered per customer according to their configured cadence and alert channels (Slack, Email, PagerDuty). Analyst triage for critical items and scheduled outreach (every 15 days) are integrated into the workflow to drive conversions and trust.

***

## 2. Goals and Success Metrics

**Goals**
- Scan multiple customers concurrently with isolated per‑organization results.
- Deliver actionable, low‑noise alerts and 1‑page executive summaries.
- Provide configurable reporting cadences (daily/weekly/biweekly/monthly) plus immediate critical alerts.
- Enable Sales/Ops to convert critical findings into paid authenticated pentests.

**Success Metrics**
- Time to first scan after onboarding ≤ 24 hours.
- Average time from critical detection → analyst triage ≤ 8 hours.
- False positive rate for criticals ≤ 10%.
- Outreach conversion ≥ 8% in 90 days for orgs with at least one validated critical.
- Scale: System supports 200 orgs with daily incremental scans (MVP scale).

***

## 3. Scope (MVP vs Out of Scope)

**MVP (Must‑Have)**
- Multi‑tenant scheduling & configuration per org.
- Passive + active subdomain discovery.
- Fast TCP scan (naabu) + targeted Nmap fingerprinting.
- Web misconfiguration checks (Nuclei templates).
- Certificate & email hygiene checks (SPF/DKIM/DMARC).
- Public credential/secret monitoring (GitHub, paste monitoring).
- Risk scoring + 1‑page executive report + technical appendix.
- Alert channels: Slack & Email. Export support (CSV/Jira/GitHub).
- Analyst triage for critical findings.
- Re‑scan verification and auto‑closure on fixes.

**Out of Scope**
- Authenticated credentialed scanning (paid).
- Full ticketing system (integrations only).
- Complex admin UI (minimal dashboard).
- ML‑powered false positive reduction.
- Paid marketplace, billing, multi‑region features (Phase 2).

***

## 4. Users and Personas

- **Founder/Tech Lead:** Wants high‑level assurance and summaries.
- **DevOps Engineer:** Needs appendices, repro steps, Jira/GitHub exports.
- **Security Analyst:** Triages, validates, and performs outreach.
- **Sales/Customer Success:** Uses reports for remediation and upsells.
- **Platform Admin:** Configures orgs and manages scanning infra.

***

## 5. Functional Requirements

### 5.1 Multi‑Org Management
1. Manage organization records (domains, contacts, alert channels, schedule).
2. Isolated data and customizable scan exclusions per org.
3. Bulk onboarding via CSV/API for MSPs.

### 5.2 Scanning Capabilities (Unauthenticated)
- Passive subdomain discovery using CT logs, DNS history, OSINT feeds.
- Active DNS and takeover checks.
- TCP port scans via naabu; fingerprinting via Nmap.
- Web checks with Nuclei templates (headers, admin pages, exposures).
- TLS/certificate and email hygiene validation.
- Secret and credential monitoring on GitHub and paste sites.

### 5.3 Risk Scoring & Prioritization
- Deterministic scoring (Critical/High/Medium/Low).
- Findings mapped to business impact (e.g., exposed DB → high).
- One‑line remediation guidance.

### 5.4 Notification & Reporting
- Cadence options: Real‑time, daily, weekly, biweekly, monthly.
- Channels: Slack, Email (HTML + PDF), PagerDuty webhook.
- Export: CSV, JSON, Jira/GitHub templates.

### 5.5 Analyst Triage & Workflow
- Criticals go to analyst queue before alerts.
- Findings can be marked as Validated / False Positive / Accepted Risk.
- Re‑scans confirm and close remediated issues.

### 5.6 Scheduling & Concurrency
- Scheduler launches per‑org scans based on cadence.
- Parallel execution with concurrency/rate limits.

### 5.7 Onboarding & Authorization
- Form captures authorization, domains, exclusions, cadence.
- Consent record and timestamp stored for legal compliance.

### 5.8 Security & Data Privacy
- Data isolation and role‑based access.
- Evidence retention policy (90–365 days).
- Encryption at rest/in transit.
- Restrict PII and scrub sensitive data per policy.

***

## 6. Non‑Functional Requirements

- Availability ≥ 99%.
- MVP scales to 200 orgs.
- Critical alert latency ≤ 5 minutes.
- Safe‑scanning defaults to avoid disruption.
- Memory ≤ 1GB per worker; containerized workers.
- False positives ≤ 10%.
- Logging for all alerts, triage, communications.

***

## 7. Data & System Design (High-Level)

**Data Model**
- `org_id`, `org_name`, `primary_domains`, `cadence`, `consent_record`
- Findings table: `finding_id`, `type`, `severity`, `evidence_links`, `triage_status`
- Runs table: `run_id`, `run_type`, `start_time`, `summary_counts`

**Architecture Components**
- Orchestrator: Prefect/Celery for scheduling.
- Containerized scan workers (naabu, nmap, nuclei, repo/paste collectors).
- Post‑processing: deduplication, scoring, CVE enrichment.
- Triage UI, Notification service (Slack/Email).
- Storage: Postgres + Object Store (S3).
- APIs for onboarding, querying, re‑scan, and export.

***

## 8. Workflows

**Onboarding**
1. Customer submits authorization form.
2. System records consent and schedules full scan within 24 h.
3. Analyst reviews criticals before alerting.

**Scan & Alert**
1. Scheduler launches scans.
2. Post‑processing dedupes and scores results.
3. Analyst validates; validated issues trigger real‑time alerts.
4. Non‑criticals grouped into reports.

**Re‑scan & Auto‑Close**
- After fix submissions, re‑scan verifies and auto‑closes if resolved.

***

## 9. User Interfaces & Reports

**Customer‑Facing**
- Email with 1‑page executive summary + CSV appendix.
- Slack messages for criticals with evidence links.

**Internal Dashboard**
- Analyst queue with filters (org, severity).
- Evidence view, action buttons, triage status.
- Org management and consent records.

**Executive Report Template**
- Org name, scan date, and risk summary.
- Top 3 issues with recommended next steps.
- CTA: “Request 30‑min remediation review”.

***

## 10. Integrations

- Slack Webhooks
- Email (HTML + PDF)
- PagerDuty optional
- Jira & GitHub integration
- S3‑compatible object store
- API for MSP usage

***

## 11. Security, Compliance & Legal

- Unauthenticated public scanning only.
- Explicit consent required for intrusive scans.
- Onboarding disclaimer outlines scope and limitations.
- Encrypted storage for secrets and evidence.
- Defined procedure for takedown and PII exposure handling.

***

## 12. Operational Considerations

- Per‑org rate limit and scanning window controls.
- Triage SLA: critical → review within 8 hours; alert within 1 hour after validation.
- Capacity: 2 scan workers per 50 orgs (MVP).
- Daily backups and per‑org retention.
- Worker monitoring and requeue logic.

***

## 13. MVP Acceptance Criteria

- Multi‑org onboarding and consent flow works end-to-end.
- Baseline scan launched within 24 hours of onboarding.
- Reliable scheduler and segregated results.
- Critical findings triaged and alerted with evidence.
- Reports (exec PDF + CSV) delivered per cadence.
- Re‑scan and auto‑close operate correctly.
- Slack/Email notifications function with attachments.

***

## 14. Roadmap & Phasing

**Phase 1 — MVP (2–4 weeks)**
Core multi‑org scanning, triage queue, Slack/Email alerts.

**Phase 2 — Hardening (4–6 weeks)**
Jira/GitHub integration, UI enhancements, retention policies.

**Phase 3 — Stickiness & Upsell (6–10 weeks)**
Ticketing automation, enrichment, MSP API, PagerDuty integration.

**Phase 4 — Paid Services (12+ weeks)**
Authenticated scans, remediation validation, billing integration.

***

## 15. KPIs

- Scans per day/org.
- Triage response times.
- False positive and re‑scan success rates.
- Conversion: validated criticals → paid pentests.
- Outreach response and uptime metrics.

***

## 16. Sample Onboarding Form Fields

- Organization name
- Primary & additional domains
- Exclusions
- Authorized contacts and alert channels
- Preferred cadence
- Consent confirmation
- Scanning time window restrictions

***

## 17. Sample Critical Alert Email

**Subject:** `[URGENT] Critical Exposure — org.example.com`

“Hi [Name],
We have validated a critical exposure on your assets: Exposed MongoDB on 203.0.113.45.
Please review the attached 1‑page summary and technical appendix.
We will reach out to schedule a 15–30 minute remediation review.
— Cybersecify Analyst Team”

***

## 18. Final Notes

- Default configuration should prioritize safe, legal unauthenticated scans.
- Analyst validation for all criticals builds trust.
- 15‑day outreach acts as a structured touchpoint for upsells.
- Ship the executive summary and outreach script first for impact.
