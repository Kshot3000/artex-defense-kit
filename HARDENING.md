# Hardening checklist: defending against the ARTEX playbook

ARTEX doesn't win with exotic zero-days. It wins on **overlooked surfaces** — peripheral portals, anonymous uploads, SSRF, leaked secrets, over-consented cloud apps, and APIs with no speed limits — chained faster than a human team can respond. Every item below comes from a named advisory; the source is noted so you can read the original wording. Work top-down: the first section is the FBI's "immediate actions."

---

## FBI — FLASH-20261113-001 (Nov 13, 2026)

### Reduce the external attack surface

- [ ] **Inventory ALL internet-facing applications — including the peripheral ones.** Partner and supplier portals, mobile backends, employee applications, sales-support systems, legacy services, third-party integrations, and apps built by other business units. The Korean bank breaches went through a loan-broker portal and an employee support app, not the main banking app.
- [ ] **Restrict management and publishing interfaces to trusted networks.** Cloud administration, network device management, application publishing interfaces (**Kudu/SCM endpoints**), hypervisors, and **backup platforms** should not be internet-reachable; use private connectivity or dedicated administrative paths.
- [ ] **Disable basic publishing authentication where not required**; restrict deployment/publishing credentials; limit SCM access to approved management networks or deployment infrastructure. Consider run-from-package deployment so deployed files can't be modified in place.
- [ ] **Govern public IP allocation** — require architecture review before any workload or management interface is exposed directly to the internet. Move enterprise apps behind Zero Trust access where feasible.

### Harden identity and access

- [ ] **Apply least privilege to multi-tenant application permissions and consent grants.** Monitor credential additions, privilege assignments, and anomalous app-only activity — especially on apps holding high-privilege scopes.
- [ ] **If you ever installed or authorized the affected ConnectWise applications, review every Microsoft 365 tenant involved** — search by application ID, not display name, including integrations no longer in use. Review service-principal sign-ins (successes and failures separately) for unfamiliar sources, and review Entra audit records for new credentials, apps, owners, role assignments, and consent grants. If suspicious: revoke and **rotate**.
- [ ] Monitor unusual certificate enrollment involving privileged users or unexpected systems; enable Extended Protection for Authentication on CA web interfaces where supported.

### Strengthen application protections

- [ ] **Put guardrails around high-impact business APIs:** rate limits, recipient limits, **transaction thresholds**, and abuse controls appropriate to the function — and **alert when an application operates materially outside normal volume**.
- [ ] **On partner/employee portals, alert on sequential lookups** and unusually high numbers of records accessed per session; rate-limit those endpoints; enforce server-side authorization for customer records and return only the fields the operation needs.
- [ ] **Stop leaking internals:** no detailed stack traces, compiler messages, SQL errors, internal paths, or framework details to unauthenticated users. Keep diagnostics in internal logs. (An agent reads your error messages as a map.)

### Secrets

- [ ] **Review configurations, environment variables, infrastructure-as-code, deployment scripts, CI/CD pipelines, and databases for embedded secrets.**
- [ ] **Implement continuous scanning** of repositories, container images, build artifacts, and pipelines for exposed secrets.
- [ ] **Rotate exposed credentials promptly** — see also the Microsoft section: deleting is not rotating.

### Preserve evidence and respond

- [ ] Preserve Entra sign-in/audit records, Microsoft Purview Audit records, SIEM data, and Graph telemetry — but don't delay containment waiting for exports.
- [ ] For ConnectWise-related activity, **review back to at least October 1, 2026**, including failed authentications and volume anomalies. Keep affected ConnectWise connections disabled until ConnectWise issues formal restoration instructions; don't delete enterprise applications as a first response (preserve configuration and evidence first).

---

## Microsoft Threat Intelligence (Nov 5–6, 2026, and the Oct 21 supply-chain report)

- [ ] **Close anonymous file upload.** Unauthenticated upload endpoints were a primary initial-access vector (Storm-3358 scanned for and exploited anonymous file uploads and SSRF, then installed remote-access tools). If uploads must be public, quarantine them: no execution, no web-accessible path, strict type validation.
- [ ] **Close SSRF.** Server-side request forgery against internal/metadata endpoints is a standard ARTEX move (the FLASH records metadata-service queries via XXE as well). Egress-allowlist what your servers may call; block link-local and metadata addresses from app-tier requests.
- [ ] **Treat exposed secrets in public repos as compromised — rotate, don't just delete.** Microsoft watched threat actors systematically search public GitHub repositories for passwords, keys, and application secrets. Deleting a key from a repo does nothing: history, forks, and the attacker's copy remain. Revoke and reissue, then purge history if needed.
- [ ] **Plant honeypots and decoys for agentic traffic.** Decoy credentials, canary records, and honeypot endpoints are disproportionately effective against agents that enumerate sequentially and grab everything reachable — a canary hit is a high-fidelity alarm with almost no false positives, and it fires at machine speed, which is the speed you need.

---

## AWS — Amazon Threat Intelligence (Nov 2026)

AWS's campaigns were about stolen AI credentials and deepfake KYC fraud. The fundamentals AWS calls out:

- [ ] **No default or hardcoded credentials** anywhere — consoles, gateways, app builders, appliances.
- [ ] **No keys in code.** LLM/API keys belong in a secrets manager with scoped, rotatable credentials — never in source, images, or compose files.
- [ ] **No unauthenticated inference endpoints.** LLM gateways and AI app builders (One API, New API, LiteLLM, Dify, Langflow, Open WebUI, Ollama, etc.) must require auth and should not be internet-exposed by default.
- [ ] **Patch the named CVEs in this stack** — including **Langflow CVE-2025-3248** (unauthenticated remote code execution) — and keep the whole AI tooling layer on the same patch cadence as your public web tier, because that's what it is.
- [ ] **Watch LLM spend like a fraud signal.** Token-consumption and billing anomalies are a stolen-key tripwire; alert on them the way you'd alert on payment anomalies.
- [ ] **Hold the liveness verdict server-side.** AWS observed ARTEX-generated deepfake video defeating live selfie checks and forged photos passing document checks at crypto exchanges. Keep KYC/liveness decisions and their evidence on your servers, apply risk scoring and step-up verification, and never let a client-side "passed" flag be the whole control.

---

## CERT-In — Advisory CIAD-2026-0058, "CRAFTY FALCON" (Nov 4, 2026)

India's finance-sector advisory focuses on payment/disbursement API abuse. Its lessons generalize to any money-moving API:

- [ ] **Isolate UAT/staging from production — and never share keys between them.** Test environments with production credentials (or production data) are a standing invitation.
- [ ] **Sign API requests** with nonces and timestamps so captured requests can't be replayed; reject stale or unsigned calls on disbursement endpoints.
- [ ] **Velocity rules and cooling-off periods:** cap disbursement velocity per account/API key, and put a **cooling period on new beneficiaries** before large transfers can flow to them.
- [ ] **Remediate fully or expect a return visit.** CERT-In notes the campaign succeeded against organizations that had *already been warned and attempted remediation* — partial fixes left the door open. Eradicate forensically: find the access path, the persistence, and the credential exposure, and close all three, not just the one you saw first.

---

## If you run your code on GitHub

- [ ] Turn on **secret scanning and push protection** for every public repo, and work the alert queue — `tools/self-scan.sh github <your-account>` gives you the open-alert count per repo.
- [ ] Assume anything ever committed publicly — even briefly, even deleted — is harvested. Rotate first (Microsoft, above).
- [ ] Check your repos' Docker Compose files for the backdoored `tomicdd/artex` / `congdonglinux/artex` images (see README warning). **637 repos still referenced the poisoned image in early November 2026.** If you deployed it, treat the host as compromised, not merely misconfigured.
