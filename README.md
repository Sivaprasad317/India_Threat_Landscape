# India Threat Landscape Intelligence

[![CI](https://github.com/Sivaprasad317/India_Threat_Landscape/actions/workflows/ci.yml/badge.svg)](https://github.com/Sivaprasad317/India_Threat_Landscape/actions/workflows/ci.yml)

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

**Ten collectors work with no key at all.** Get the free abuse.ch and OTX
keys and you are at fourteen; Shodan (paid) makes fifteen.

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
| `security_news` | Security news headlines naming India or high-impact events | none |
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
python main.py health                     # feed freshness and failures
python main.py validate                   # check the data files you edit
python main.py backtest --write docs/BACKTEST.md
python main.py export --format both --public   # STIX 2.1 + MISP JSON
```

Run `collect` daily, `bulletin` weekly. `health` before a bulletin tells you
whether any feed is failing or stale; the bulletin repeats it on the cover,
along with how old the newest record is and how many indicators are still
active. A feed whose API key is not set shows as NO KEY and is not counted
as a failure.

### What the bulletin contains

| Section | What it covers |
|---|---|
| Cover | Key numbers, a "Bottom line" summary, sector risk chart, contents |
| 01 Threats in Focus | The month's headline incidents: an at-a-glance index, full cards (what happened, why it matters for India, what to do, sources) for Critical and India-direct incidents, a compact table for the rest, plus recent news |
| 02 Executive Summary | Analytical judgements and a 7-day action plan (headline actions first) |
| 03-09 | Regional hotspots, adversaries, sector scores, sector detail, correlation, priority signals, extortion telemetry |
| 10 | CERT-In Directions mapping (internal) or hardening guidance (public) |
| 11 | Methodology, confidence scale, provenance |

Each `bulletin` run writes exactly two files to `output/<Mon>/<MM-DD-YYYY>/`:
the bulletin PDF and its IOC sheet (CSV, opens in Excel). `--public` gives the
TLP:CLEAR versions of both instead. The 1-page brief is only made when you
run `pulse` yourself.

### Scoring window

Scoring is anchored to a fixed window end date so repeated runs give
identical numbers (the QA gate checks this). To score against current data,
set `SCORING_ANCHOR` in `.env` to an ISO timestamp (naive = IST) or `now`.

### Tests

`python -m unittest tests.test_threat_intel` (needs `PyMuPDF`, in
`requirements.txt`, for the PDF QA tests).

---

## How the score is built, and how far to trust it

Each sector gets two 0-100 scores: a **composite** from the six components
below, which sets the ranking, and an **activity** score from the five data
components alone (criticality left out, weights rescaled), which shows how
much the data actually saw. The bulletin prints both.

| Component | Weight | Measures |
|---|---|---|
| Impact | 30% | Named victims and data-sale listings |
| Exploit | 20% | Actively exploited CVEs in sector technology |
| Infra | 15% | Malware C2, phishing, lookalike domains |
| Criticality | 15% | Section 70A designation |
| Pressure | 10% | Hacktivist claims, campaign reporting, advisories |
| Exposure | 10% | Aggregate attack surface on Indian networks |

Every signal is weighted by its own `confidence` and `india_relevance` and
decays with a 21-day half-life. Scores are relative to the window, not
probabilities. The full method is in [METHODOLOGY.md](METHODOLOGY.md).

**Backtest.** `python main.py backtest` scores sectors at past dates using
only data seen by then and checks the ranking against the next 30 days of
leak-site victims. On the bundled data (24 monthly anchors):

| Ranking | Spearman rho | Next-month victims in its top 3 |
|---|---|---|
| This model | 0.53 | 48% |
| Activity score (no criticality weight) | 0.61 | 59% |
| Ranking by recent victims only | 0.62 | 59% |
| Random | 0.00 | 21% |

Rankings are well above random, but none beats counting recent victims, so
the bulletin makes no forecasting claim. The criticality weight lifts CII
sectors that see fewer leak-site postings; it is a statement of priority, so
the bulletin shows each sector's activity score (no criticality) next to the
composite. The exploit, infra, pressure and exposure components have no
stored history before late August 2026 and are not yet tested; the daily
scheduled run builds that history. Details and a recommendation:
[METHODOLOGY.md](METHODOLOGY.md#7-has-the-score-been-tested),
[docs/BACKTEST.md](docs/BACKTEST.md).

---

## Correlation

Matches between feeds are graded, and every one carries its evidence:

- **Exact artefact**: the same CVE, hash, domain, IP or URL.
- **Same organisation**: the same named organisation after normalisation.
- **Name only**: just an actor or malware-family name in common. Listed as
  a possible link, never counted.

A match is **independent** only when its feeds come from different families
(CISA KEV and NVD share CVE data; ransomware.live and ransomlook.io scrape
the same leak sites; the abuse.ch feeds share an operator). Only independent
matches raise confidence (x1.15, capped at 0.85, once per signal).

**Exploit-to-victim links** show an actively exploited CVE in a sector's
technology while that sector is also seeing victims: a known way in, not
proof it was the way in.

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

## Threats in Focus: covering the incidents everyone is asking about

Feeds only score what they can see. Big incidents such as a PHP engine RCE, a
poisoned PyPI package or a bank confirming leaked customer records reach
people through the news first. The bulletin covers them in section 01 from two
inputs:

**`data/headline_threats.json`**: one entry per incident, written by you from
public reporting. Entries dated between the window start and the day you run
the bulletin are shown, most severe first, and their first action is added to
the 7-day action plan.

```json
{"id": "php2shell", "title": "PHP2Shell: unauthenticated RCE in the PHP engine",
 "category": "Critical vulnerability", "severity": "Critical",
 "date": "2026-10-21", "status": "Patched; exploitation attempts observed",
 "india_link": "Broad: PHP runs many Indian government and SME sites",
 "sectors": ["GOVERNMENT", "EDUCATION"], "cves": ["CVE-2026-109618"],
 "keywords": ["PHP2Shell"], "scope": "Websites and PHP servers",
 "owner": "Web / Infra teams",
 "summary": "What happened...", "india_impact": "Why it matters...",
 "actions": ["First thing to do...", "..."], "indicators": [],
 "confidence": "high", "last_verified": "2026-10-28",
 "evidence": "What the best source confirms, and what is still unverified.",
 "sources": [{"name": "Canadian Centre for Cyber Security AL26-026",
              "url": "https://...", "type": "primary",
              "published": "", "retrieved": "2026-10-28"}]}
```

**Evidence is required.** Each source has a `type`: `primary` (the affected
vendor or organisation, a regulator, a government CERT), `research` (original
technical analysis) or `news`, plus `published` and `retrieved` dates (leave
one empty when unknown; `retrieved` is when you last confirmed the source
supports the claim). `confidence` is `high` only with a primary source;
`medium` for consistent research or reporting without one; `low` for a single
report or unconfirmed claims. At least one source must carry a `retrieved`
date. Every card prints its confidence, verification date and evidence note,
tags each source with its type and dates, and flags entries with no primary
source. Re-verify before each edition and update `last_verified`.

`severity` is Critical, High, Medium or Low. Set `"india_direct": true` when
the incident hit an Indian organisation or came from CERT-In; those entries and
anything Critical get a full card, and the rest go in a compact table (add an
optional one-line `"brief"` for it). `keywords` stop the same story being
repeated in the news list. Entries with missing fields are skipped with a
warning.

**`security_news` collector**: reads RSS feeds (The Hacker News,
BleepingComputer, SecurityWeek, The Record, MediaNama) during `collect` and
keeps stories that name India or describe exploited flaws, supply-chain
attacks, breaches or ransomware. The last 14 days appear under "Also in the
News". Use this list to decide what deserves a headline entry. Change the feeds
with `NEWS_FEEDS="Name|https://url,Name|https://url"` in `.env`.

Neither input changes sector scores: headlines are analysis, not telemetry.

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

## Data files you maintain

| File | What it holds |
|---|---|
| `data/headline_threats.json` | Threats in Focus entries, with sources |
| `data/entity_overrides.json` | Reviewed corrections for named organisations: display name, sector, state, with a reason and date. The code never guesses a state; unknown stays "Location Unresolved" |
| `data/hacktivist_claims.json` | Hacktivist claims from your Telegram and X monitoring |
| `data/leak_observations.json` | Dark web forum observations |
| `data/host_asn_cache.json` | Hosting ASN lookups for IOC hosts. Hosts not listed are reported as `unresolved` |

Run `python main.py validate` after editing; CI runs it on every push.

---

## Running it on a schedule

**GitHub Actions (recommended).** `.github/workflows/scheduled-run.yml` runs
every day at 06:47 IST: it collects every feed, builds the public (TLP:CLEAR)
bulletin and IOC sheet, uploads them as a run artifact (Actions tab, open the
run, Artifacts), and fails, so GitHub emails you, when a feed is failing or
stale (feeds without a key are skipped, not failed). The signal database is carried between runs in the Actions cache. Add
`ABUSECH_AUTH_KEY` and `OTX_API_KEY` under Settings, Secrets and variables,
Actions to enable those feeds. Scheduled workflows run from the `main` branch.

**Windows Task Scheduler.** Create a daily task that runs, in the project
folder:

```powershell
python main.py collect; python main.py health
```

`.github/workflows/ci.yml` runs the tests, validates the data files and
builds a sample bulletin on every push (Python 3.10 and 3.12).

---

## Exports for CTI platforms

`python main.py export --format both [--public]` writes the IOC sheet as a
STIX 2.1 bundle and a MISP event to `exports/`. Roles, recommended actions,
confidence and 14-day expiry match the CSV; IDs are stable across runs so
platforms update rather than duplicate. Both formats are for loading into
detection, so **expired indicators are left out**; `--include-expired` keeps
them for a historical export, and MISP then marks them `to_ids: false`. Public edition is marked TLP:WHITE
(STIX 2.1's built-in marking, the TLP 2.0 CLEAR equivalent) and `tlp:clear`
in MISP; internal is TLP:GREEN.

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

Scores are relative to observed activity in the window, not probabilities,
and so far only the impact and criticality parts have been backtested (see
[METHODOLOGY.md](METHODOLOGY.md)).
