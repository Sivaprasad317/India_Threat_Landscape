# India Threat Landscape Intelligence

Multi-source threat intelligence for Indian organisations. Collects from
ransomware leak sites, exploited-vulnerability catalogues, malware
infrastructure feeds, certificate transparency, phishing feeds, CERT-In,
hacktivist claim tracking and your own dark web notes — then scores Indian
sector risk across all of them and maps activity to CERT-In Annexure I.

---

## Setup

```bash
cd India_Threat_Landscape
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
python main.py sources
```

`sources` shows which collectors can run now and which need a key.

**Nine collectors work with no key at all.** Get the free abuse.ch and OTX
keys and you are at thirteen; Shodan (paid) makes fourteen.

---

## Sources

| Collector | What it gives you | Key |
|---|---|---|
| `ransomware_live` | Leak-site victims, India-filtered | none |
| `ransomlook` | Second independent leak-site source | none |
| `cisa_kev` | Vulnerabilities confirmed exploited in the wild, with EPSS | none |
| `nvd_critical` | Critical CVEs in Indian enterprise technology | none |
| `crtsh_typosquat` | Lookalike domains for 30+ Indian brands | none |
| `openphish` | Live phishing pages hitting Indian brands and .in | none |
| `certin_advisories` | Official CERT-In vulnerability notes | none |
| `hacktivism` | Hacktivist claims against Indian targets | none |
| `leak_tracker` | Your dark web forum observations | none |
| `threatfox` | Malware C2 on Indian infrastructure | abuse.ch (free) |
| `urlhaus` | Payload URLs on Indian hosts | abuse.ch (free) |
| `malwarebazaar` | Samples from India-targeting families | abuse.ch (free) |
| `otx` | Campaign reporting naming India | OTX (free) |
| `shodan_exposure` | Aggregate Indian attack surface | Shodan (paid) |

Get the two free keys at https://auth.abuse.ch/ and https://otx.alienvault.com.

---

## Commands

```bash
python main.py sources                    # collector status
python main.py collect                    # run everything ready
python main.py collect --only cisa_kev,crtsh_typosquat
python main.py sectors --days 60 --verbose
python main.py correlate                  # cross-source findings
python main.py bulletin --days 30 --prepared-by "Siva prasad Boddu"
python main.py bulletin --days 30 --public   # TLP:CLEAR edition, victims anonymised
python main.py pulse --days 7             # 1-page executive brief
python main.py certin --incident "..." --sector BFSI
python main.py clock --noticed "2026-09-05 08:30"
python main.py stats
```

Run `collect` daily, `bulletin` weekly.

### Scoring window

Scoring is anchored to a fixed window end date so repeated runs give
identical numbers (the QA gate checks this). To score against current data,
set `SCORING_ANCHOR` in `.env` to an ISO timestamp (naive = IST) or `now`.

### Tests

`python -m unittest tests.test_threat_intel` (needs `PyMuPDF`, in
`requirements.txt`, for the PDF QA tests).

---

## Why multiple sources changes the answer

The single-source version scored on victim counts. That misses the sector
that is *about* to have victims.

In testing, Banking ranked first on **one** victim — because it also carried
three actively exploited CVEs in banking technology, four lookalike domains
impersonating Indian banks, a SOVA banking-trojan C2, and a data-sale listing
on BreachForums. Six sources agreeing. The victim-only model ranked it fourth.

Government scored zero under the old model — no victims. Under this one it
scores on an exploited Fortinet CVE plus an Income Tax lookalike domain. That
is a sector with the preconditions in place and no incident yet, which is
exactly when advice is worth giving.

### Scoring components

| Component | Weight | Measures |
|---|---|---|
| Impact | 30% | Confirmed victims and data-sale listings |
| Exploit | 20% | Actively exploited CVEs in sector technology |
| Infra | 15% | Malware C2, phishing, lookalike domains |
| Pressure | 10% | Hacktivist claims, campaign reporting |
| Exposure | 10% | Aggregate attack surface on Indian networks |
| Criticality | 15% | Section 70A designation |

Every signal carries its own `india_relevance` and `confidence`, so an
unverified hacktivist claim contributes a fraction of what a corroborated
breach does. Signals decay with a 21-day half-life.

---

## Correlation

The part a single feed cannot produce. Three passes:

**Shared artefacts** — the same CVE, domain or organisation appearing in
signals from different sources. In testing this caught CVE-2026-21042 named
by both CISA KEV and a CERT-In advisory, and Sundaram Finance appearing both
as a ransomware victim and as a BreachForums data listing. Corroborated
signals get a confidence uplift, capped at 0.97.

**Actor chains** — a group named on a leak site also showing up in malware
infrastructure or hacktivist claims.

**Exploit-to-victim links** — an actively exploited CVE affecting a sector
that is concurrently seeing victims. A known way in, plus proof it is being
used against that sector now. This is the most actionable output in the tool.

---

## Scope boundaries, deliberately

**Attack surface is aggregate only.** Shodan is queried through the count
endpoint, which returns totals and no host records. A named list of
vulnerable Indian hospital servers is a targeting package whoever holds it,
and it is not needed to tell a client their sector has an exposure problem.

**Dark web tracking records claims, not data.** The leak tracker stores that
an organisation was named, what the seller claims to hold and what they are
asking. It does not retrieve, store or index leaked data. Knowing a company
is listed is defensive intelligence; holding their stolen data is not, and
would create legal exposure for you.

**Hacktivist claims are recorded as claims.** Groups are carried with a
reliability figure reflecting how often past claims held up. Unverified
claims score low by design, because most are recycled or inflated. The value
is being able to tell a client "this group named you, here is their track
record", not repeating the claim.

---

## Feeding it your own work

Two collectors read local JSON you maintain, which turns manual monitoring
into bulletin content.

`data/hacktivist_claims.json` — from your Telegram and X monitoring:

```json
{"group": "Team Insane PK", "target": "example.gov.in",
 "sector": "GOVERNMENT", "claim_type": "DDoS",
 "claimed_at": "2026-09-01T10:00:00Z",
 "evidence": "check-host screenshot only", "verified": false,
 "source_url": "https://t.me/..."}
```

`data/leak_observations.json` — from your forum monitoring:

```json
{"forum": "BreachForums", "seller": "handle",
 "target": "Example Bank Ltd", "sector": "BFSI",
 "claimed_records": 1200000, "data_types": ["PII", "KYC"],
 "asking_price_usd": 5000, "observed_at": "2026-09-01T00:00:00Z",
 "verified": false}
```

---

## Adding a source

Create a module in `core/collectors/`, subclass `BaseCollector`, decorate
with `@register`, emit `Signal` objects, and import it in
`core/collectors/__init__.py`. Scoring, correlation and the bulletin pick it
up with no further changes.

---

## Limitations

Stated on every bulletin, because a client will otherwise over-read the
numbers.

Leak-site data is a biased sample — organisations that paid quietly never
appear. Exploited-CVE signals mean a product is under attack globally, not
that a specific Indian organisation is unpatched. Sector attribution from
company names is imperfect. Small signal counts move scores noticeably, so
early bulletins are directional rather than precise.

Scores are relative to observed activity in the window, not probabilities.
