# Detection: finding ARTEX exposure and campaign fingerprints

Two different hunts live here:

1. **Is an ARTEX console exposed on infrastructure you operate?** (Yours to fix — an exposed console means anyone can drive an attack platform sitting on your network, and if you pulled the poisoned Docker image, you may have deployed a backdoor too. See the warning in [README.md](README.md).)
2. **Is ARTEX-style activity hitting you?** (Behavioral signals and IOCs from the campaigns, mostly from FBI FLASH-20261113-001.)

All IPs below are **defanged** (`[.]`). The FBI is explicit that these are **historically observed** indicators: cloud IPs get reassigned, so **vet every indicator against your own telemetry before blocking anything**.

---

## 1. Exposed ARTEX console fingerprints

### HTML page titles

An ARTEX web console identifies itself in the page `<title>`:

| Title | Variant |
|---|---|
| `ARTEX — 自主渗透测试控制台` | Chinese ("autonomous penetration testing console") — the title string that first tied the South Korea bank campaign to ARTEX |
| `ARTEX — Autonomous Penetration Testing Console` | English |
| `자율 침투 테스트 콘솔` | Korean ("autonomous penetration test console") |
| `ARTEX Restricted` | Shown when the console sits behind HTTP basic auth |

### Ports

- **8787/tcp** — default console port.
- **8790, 443, 80/tcp** — also observed hosting consoles.
- **8788/tcp** — ARTEX's MITM proxy port; seeing it exposed alongside a console is a strong corroborating signal.

### Favicon hash (Shodan)

```
http.favicon.hash:-1898746557
```

### Shodan queries

```
http.title:"ARTEX — Autonomous Penetration Testing Console"
http.title:"ARTEX — 自主渗透测试控制台"
http.title:"자율 침투 테스트 콘솔"
http.title:"ARTEX Restricted"
http.favicon.hash:-1898746557
port:8787 http.title:"ARTEX"
```

Use these against **your own netblocks** (Shodan lets you scope with `net:`). Finding someone else's console is a reporting matter ([REPORTING.md](REPORTING.md)), not an invitation to connect to it.

### Censys

Censys tracks ARTEX as a threat label — filter hosts by the **ARTEX** label, or search `services.http.response.html_title` for the title strings above. Censys' write-up ("ARTEX: Agentic Asbestos," Nov 5, 2026) is the best public census of the exposure problem.

### Exposure counts, for scale

- **1,465 hosts** running an exposed ARTEX console identified by Censys, Nov 3–4, 2026.
- **"Over 1,600"** publicly exposed ARTEX console instances as of early November 2026 (FBI), with total deployments "likely significantly higher" once private networks are counted.

### Check your own hosts

`tools/self-scan.sh hosts <file-of-your-hosts>` probes hosts **you operate** for the title fingerprints on the console ports and, when Python's `mmh3` is available, the favicon hash. See the script header — it is a self-assessment tool, not a scanner for other people's infrastructure.

---

## 2. Is your AI stack a target? Check the key-theft surface

One ARTEX campaign's whole job was stealing AI credentials to power more agents. Amazon Threat Intelligence observed the agents hunting keys for, and abusing, LLM gateways and AI application builders. If you run any of these, treat them as in-scope for your review — look for unauthenticated endpoints, default credentials, and keys you didn't issue being used:

- **LLM gateways/proxies:** One API, New API, Veloera, Sub2API, LiteLLM (and self-hosted reseller software such as CLIProxyAPI showing up in egress logs).
- **AI app builders / front-ends:** Dify, FastGPT, Langflow, RAGFlow, Open WebUI, LobeChat, Ollama.

Tripwires that cost nothing:

- **LLM spend/token anomalies.** A sudden jump in token consumption or API billing is a stolen-key indicator — the FBI explicitly lists "token consumption patterns or API billing anomalies" in what it asks reporters to look for.
- **Unexpected egress to LLM APIs** from servers that have no business calling them (see behavioral signals below).

---

## 3. Behavioral signals (FBI FLASH-20261113-001, citing Zscaler ThreatLabz)

None of these is proof alone; together, in a compressed burst, they are the ARTEX shape:

- **Unexpected outbound API calls** to LLM endpoints from your infrastructure: `api.anthropic.com`, `api.deepseek.com`, `open.bigmodel.cn`, `api.x.ai` — investigate any such egress that isn't a sanctioned application, especially alongside other signals here.
- **High-frequency automated requests with sequential enumeration** against login and search endpoints — agents walk IDs and records one by one, fast.
- **Sequential lookups / unusually high numbers of records accessed per session** on partner and employee portals, and API rate-limit violations or volumetric anomalies.
- **Web shells in unexpected paths** — `*.aspx` or `*.jsp` files appearing in web application directories where they don't belong (also PHP/JSP shells generally; the FBI notes shells deployed "including via MySQL log poisoning").
- **Tunneling tools** — traffic via **Chisel** or **SoftEther**, residential proxies, Tor, or SOCKS relays.
- **Exfiltration to webhook endpoints** — command output and staged data sent to rotating **webhook.site** endpoints; outbound transfers of structured data (names, phone numbers, financial information) over HTTPS to unauthorized external destinations.
- **Persistence artifacts the FBI names:** open-source RATs **WISP**, **vshell**, **AdaptixC2**; **BLOODALCHEMY** C2 components; newly created accounts and SSH keys; Elastic IP allocations; credentials added to existing OAuth applications; account takeovers via password reset.
- **Cloud-specific tells:** Azure ARM deployment *validation dry-runs* across many resource types; test blob writes/deletes with sub-second timing; Kudu/SCM API abuse; cloud metadata service queries; unexpected IAM role assumptions or PassRole operations.
- **Attack "texture":** compressed bursts of activity; high volumes of failed attempts with iterative, incremental changes; duplicate/overlapping requests that look like multiple sub-agents overwriting each other. Human attackers don't usually look like that. Agents do.

For host- and network-level detection rules (YARA/Sigma-style), use the MalwareMustDie MMD-072-2026 ARTEX detection pack — published by the MalwareMustDie team and linked here with credit, not copied: https://blog.malwaremustdie.org/2026/11/mmd-072-2026-artex-detection-signature.html

---

## 4. IOCs (defanged, historical — vet before blocking)

Source: FBI FLASH-20261113-001 indicator tables, which attribute each item to Microsoft, CrowdStrike, or Censys reporting. The FBI cautions that this infrastructure "may be hosted on cloud or virtualized platforms where IP addresses can be dynamically or temporarily assigned" and should be "interpreted as historically observed infrastructure within the activity window." **Corroborate with your own telemetry before taking blocking action.**

### ARTEX host / open directory — South Korea financial campaign (CrowdStrike, Censys)

| Indicator | Context |
|---|---|
| `38.244.50[.]120` | ARTEX host and open directory |

### ConnectWise Cloud Backup campaign (Microsoft)

| Indicator | Context |
|---|---|
| `144.172.64[.]60` | Sign-ins and Graph API activity in customer environments |
| `144.172.64[.]99` | Sign-ins and Graph API activity in customer environments |
| `144.172.64[.]128` | Sign-ins and Graph API activity in customer environments |
| `187.15.88[.]186` | Graph API access via compromised apps (transient VPN IPs, relevant Oct 15–16, 2026) |
| `187.15.90[.]217` | Graph API access via compromised apps (transient VPN IPs, relevant Oct 15–16, 2026) |
| `187.15.89[.]186` | Graph API access via compromised apps (transient VPN IPs, relevant Oct 15–16, 2026) |

### Proxy IPs — South Korea financial campaign (CrowdStrike)

| Indicator |
|---|
| `101.53.80[.]20` |
| `205.214.59[.]31` |
| `124.155.252[.]63` |
| `154.201.79[.]246` |
| `23.248.249[.]90` |
| `23.158.220[.]98` |
| `103.248.148[.]84` |
| `203.160.133[.]172` |
| `209.209.85[.]38` |

### WISP C2 nodes — Storm-3358 campaign (Microsoft; active as of Nov 6, 2026)

| Indicator |
|---|
| `199.19.95[.]66` |
| `199.19.95[.]67` |
| `199.19.95[.]68` |

### ARTEX servers — Storm-3358 campaign (Microsoft; active as of Nov 6, 2026)

| Indicator |
|---|
| `91.92.240[.]238` |
| `85.11.168[.]45` |
| `178.16.54[.]129` |
| `31.77.229[.]35` |

### C2 server — Storm-3358 campaign (Microsoft; active as of Nov 6, 2026)

| Indicator |
|---|
| `85.11.167[.]52` |

### Domains

| Indicator | Context | Source |
|---|---|---|
| `xcai[.]pro` | LLM API reseller (South Korea financial campaign) | CrowdStrike |

### Also watch (from the FLASH TTP tables)

- `api.db-ip[.]com` queries — used by ARTEX for victim geolocation during recon. Legitimate services exist; unexpected calls from a server are a weak signal worth correlating.
- Rotating **webhook.site** endpoints receiving command output (see behavioral signals).
