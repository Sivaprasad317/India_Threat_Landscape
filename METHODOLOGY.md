# Methodology

How the bulletin turns feed data into rankings, what each number means, how
far it has been tested, and where it should not be trusted. If a claim in the
bulletin cannot be traced back through this document to the code and data,
treat it as a bug.

---

## 1. What the bulletin is

A periodic, India-focused threat picture built from public feeds plus a small
amount of analyst-maintained data. It answers three questions for an Indian
organisation: what is being exploited, who is being hit in my sector, and
what should I do this week.

It is **not** a breach notification service, a forensic finding about any
named organisation, or legal advice on CERT-In reporting.

---

## 2. Sources and how much each is trusted

| Collector | Gives | Family | Stale after |
|---|---|---|---|
| `cisa_kev` | CVEs confirmed exploited in the wild, with EPSS | cve-catalogue | 7 days |
| `nvd_critical` | Critical CVEs in Indian enterprise technology | cve-catalogue | 3 days |
| `certin_advisories` | CERT-In vulnerability notes and advisories | CERT-In | 10 days |
| `ransomware_live` | Leak-site victims, India-filtered | leak-site-trackers | 3 days |
| `ransomlook` | Second leak-site tracker | leak-site-trackers | 3 days |
| `threatfox`, `urlhaus`, `malwarebazaar` | Malware infrastructure and samples | abuse.ch | 3-7 days |
| `openphish` | Live phishing pages | OpenPhish | 3 days |
| `crtsh_typosquat` | Lookalike domains for Indian brands | crt.sh | 14 days |
| `otx` | Campaign reporting naming India | AlienVault OTX | 14 days |
| `shodan_exposure` | Aggregate Indian attack-surface counts (no host lists) | Shodan | 14 days |
| `india_threat_tracker` | Curated APT and UPI-smishing campaigns (CC BY 4.0, Sohan Kanna) as campaign reporting | India Threat Tracker | 45 days |
| `security_news` | News headlines (kept out of scoring) | n/a | 3 days |
| `hacktivism`, `leak_tracker` | Analyst-logged claims from `data/*.json` | analyst | manual |

**Families.** Feeds that share an upstream are one family: CISA KEV and NVD
share CVE data; ransomware.live and ransomlook.io scrape the same leak sites;
the abuse.ch feeds share one operator. Agreement inside a family shows a
record exists, not that it is true (section 6).

**Source health** (`python main.py health`, and a table in every bulletin)
reports two dates per feed, because they answer different questions:

- *last collected*: the last collector run that did not fail outright
- *newest record*: the most recent item the feed returned

A feed is FAILING when its latest run returned nothing and logged errors,
DEGRADED when it returned data with errors (for example after retries), STALE
when either date is older than the limit above, and MANUAL for
analyst-maintained files. Collectors retry network errors, HTTP 429 and 5xx
three times with exponential backoff; other HTTP errors are final.

---

## 3. Signals

Every collector emits `Signal` records (`core/signals.py`) with:

- `source`, `source_url`: where the record came from
- `observed_at`: when the source says the event happened (KEV date added,
  leak-site posting date, IOC first seen). This is what the reporting window
  and recency decay use.
- `first_stored`, `last_seen`: when this platform first and last collected it
- `severity`, `confidence`: as assigned by the collector from the source's
  own fields; single-source leak-site claims are capped at 0.60 in the
  bulletin
- `india_relevance` (0-1) with `india_reason`: why the record is about India
  (country code, `.in` domain, named Indian brand, sector technology)
- `sectors`, `entities` (CVEs, domains, IPs, URLs, hashes, organisations,
  actors, malware families)

The reporting window is `[anchor - days, anchor]`. The anchor defaults to a
fixed date so repeated runs over the same database give identical numbers;
set `SCORING_ANCHOR=now` (or an ISO date) to score current data. Signals
observed after the anchor are excluded.

---

## 4. Sectors and locations

Victims are mapped to the 14-sector taxonomy in `core/sectors.py` from the
feed's activity label, then keywords. Known organisations whose names do not
classify cleanly are corrected in **`data/entity_overrides.json`**, which
sets display name, sector and state for each, with a reason and review date.
The code only reads that file.

States come from overrides, then city and district names in the
organisation name or description. **If neither matches, the state is
"Location Unresolved".** It is never guessed from words like "bank" or
"tech".

---

## 5. Sector risk score

For each sector (`core/scoring_multi.py`, version 2.5):

1. Each signal contributes
   `type weight x severity weight x confidence x india_relevance`.
   Type weights: victim 1.00, data leak 0.85, vulnerability 0.70, hacktivism
   0.60, malware infrastructure 0.55, phishing 0.50, typosquat 0.45,
   advisory 0.40, research 0.35, exposure 0.30.
2. Contributions decay with a **21-day half-life** from the anchor.
3. Signals are grouped into components: **impact** (victims, data leaks),
   **exploit** (vulnerabilities), **infra** (malware infrastructure,
   phishing, typosquats), **pressure** (hacktivism, research, advisories),
   **exposure** (attack-surface counts).
4. Each component is `log(1 + sum) / log(1 + cap) x 100`, where the cap is
   the largest sector's sum for that component in the same run. The log
   stops a flood of weak signals outranking a few severe ones; the shared cap
   makes scores relative within a run.
5. **Criticality** is 100 for Section 70A (NCIIPC) sectors and 30 otherwise.
6. Score = `0.30 impact + 0.20 exploit + 0.15 infra + 0.15 criticality +
   0.10 pressure + 0.10 exposure`.
   Bands: Critical 80+, High 60-79, Moderate 40-59, Low 20-39, Minimal <20.

**What a score means.** Relative attention warranted in this window, not a
probability. A sector at 70 is among the most heavily and broadly targeted
in the data seen, not "70% likely to be attacked". Criticality deliberately
raises sectors where an incident would matter more, even with less activity.

---

## 6. Correlation

`core/correlation.py` grades every match between feeds:

| Grade | Means | Counts as corroboration? |
|---|---|---|
| exact artefact | the same CVE, hash, domain, IP, URL or onion address | yes |
| same organisation | the same named organisation after name normalisation | yes |
| name only | only an actor or malware-family name in common | **no**: listed as a possible link |

A shared artefact is **independent** when its feeds come from two or more
families (section 2). Only independent matches raise a signal's confidence
(x1.15, capped at 0.85, once per signal). Every shared artefact carries the
first record from each feed as evidence, shown in the bulletin.

"Exploit-to-victim" rows mean an actively exploited CVE affects technology
mapped to a sector that also had leak-site victims in the window. That is
co-occurrence, not evidence of how any victim was breached.

---

## 7. Has the score been tested?

`python main.py backtest --write docs/BACKTEST.md` (`core/backtest.py`)
scores sectors at past anchor dates using only data observed by then, and
compares the ranking with the distinct organisations per sector named on
leak sites in the **next 30 days**. Full results:
[docs/BACKTEST.md](docs/BACKTEST.md).

Results on the bundled database (24 monthly anchors, Oct 2024 to Sep 2026):

| Ranking | Mean Spearman rho | Mean capture@3 |
|---|---|---|
| This model (v2.5 weights) | 0.525 | 0.478 |
| This model without the criticality weight | 0.609 | 0.592 |
| Recent victims only (baseline) | 0.622 | 0.585 |
| CII designation only | -0.254 | 0.115 |
| Random (expected) | 0.000 | 0.214 |

*capture@3 = share of next-month victim organisations that fell in the three
top-ranked sectors.*

**What this shows**

- Rankings are far better than random: sectors that are being hit tend to
  keep being hit.
- The published model is **worse than simply counting recent victims** at
  predicting where the next month's leak-site victims land (it won at 4 of
  24 anchors). Removing the criticality weight brings it level with that
  baseline. CII-designated sectors see *fewer* leak-site postings, so the
  criticality component pulls the ranking away from where victims appear.
- In this history the model is effectively impact plus criticality: the
  exploit, infrastructure, pressure and exposure components have no stored
  history before late August 2026 and **are not yet tested**. The daily
  scheduled run builds that history; re-run the backtest as it grows.

**Recommendation (not yet applied).** Report two numbers per sector instead
of one: an activity score (likelihood, from the five data components) and a
criticality flag (consequence). Mixing them hides the fact that the score is
partly a statement of priorities rather than a forecast. Changing the
published weights is an analyst decision and should follow a re-run of the
backtest once all components have history.

**Limits of the test.** The outcome is leak-site postings, a biased sample:
organisations that pay quietly never appear. Monthly victim counts are small
(roughly 5-40), so single anchors are noisy.

Weight sensitivity on the current ranking is in `docs/BACKTEST.md`: halving
or raising any one weight by 50% changes the top three only when the impact
weight rises.

---

## 8. Indicators (IOC sheet)

- Only indicators on Indian domains (`.in` country-code suffixes) are
  exported. "Indian" refers to the domain suffix, not the hosting location.
- **Role** comes from the feed: `compromised_legitimate` (public edition:
  `reported_compromised_by_feed`) when ThreatFox marks the IOC
  `is_compromised` or tags it `compromised`; `phishing_lookalike` for
  phishing feeds; otherwise `unverified_delivery_host`. This platform does
  not independently validate any indicator.
- **Action** never says "block" for a possibly hacked legitimate site: alert
  and notify the owner (or CERT-In/NIC for `.gov.in` and `.nic.in`).
- **ASN** comes from `data/host_asn_cache.json` (lookups recorded at
  collection time). A host with no recorded lookup is reported as
  `unresolved`, never guessed.
- Indicators expire 14 days after first seen. Text in the bulletin is
  defanged (`hxxp`, `[.]`); the CSV keeps both raw and defanged forms.

---

**Exports.** `python main.py export` writes the same indicators as a STIX 2.1
bundle (validated with the OASIS `stix2` library during development) and a
MISP event, with stable IDs, the CSV's roles, actions, confidence and expiry,
and TLP marking (public: TLP:WHITE / `tlp:clear`; internal: TLP:GREEN).

---

## 9. Analyst-written content

- **Threats in Focus** (`data/headline_threats.json`): incidents summarised
  by the analyst from cited public reporting. They are shown with their
  sources and never feed the scores.
- **Hacktivist claims and dark web observations**
  (`data/hacktivist_claims.json`, `data/leak_observations.json`): claims are
  recorded as claims, with low default confidence unless verified.
- `python main.py validate` checks all hand-maintained files; CI runs it on
  every push.

---

## 10. Quality gate

Every bulletin passes `core/qa.py` before it is kept: section order, no
orphan pages, the IOC sheet's SHA-256 printed in the bulletin matches the
file, no raw enum names, no victim names, edition-specific TLP rules,
pluralisation, and every statement the bulletin derives from data
(provenance dates, action due date) recomputed and compared. On the bundled
sample dataset it also checks exact counts.

---

## 11. Limitations

- Leak-site data under-counts: quiet payers and private recoveries never
  appear, and posting dates follow failed negotiations, not intrusions.
- KEV entries mean a product is exploited somewhere, not that an Indian
  organisation is unpatched.
- Sector attribution from company names is imperfect; check overrides when a
  sector looks wrong.
- Small numbers move scores noticeably. Early bulletins are directional.
