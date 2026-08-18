# Knowledge base corpus

What sits in `data/knowledge_base/`, where each file came from, and how much of
it survives into the vector index. Counts were read from the built index, not
estimated.

## Files

| File | Source | Downloaded | Size | Indexed | Retrievable |
|---|---|---|---|---|---|
| `enterprise-attack.json` | MITRE ATT&CK Enterprise, STIX 2.0 bundle | not determined | 38.5 MB | 2240 | 1254 |
| `ics-attack.json` | MITRE ATT&CK ICS, STIX 2.0 bundle | not determined | 2.4 MB | 282 | 228 |
| `mobile-attack.json` | MITRE ATT&CK Mobile, STIX 2.0 bundle | not determined | 3.4 MB | 380 | 243 |
| `stix-capec.json` | MITRE CAPEC, STIX 2.1 bundle | not determined | 4.3 MB | 1493 | 1493 |
| `nvdcve-2.0-modified.json` | NVD CVE JSON 2.0 "modified" feed — https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip | 2025-06-16 | 8.1 MB | 2118 | 2118 |
| `known_exploited_vulnerabilities.csv` | CISA Known Exploited Vulnerabilities catalog — https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv | not determined | 0.7 MB | 1366 | 1366 |
| | | | **Total** | **7879** | **6702** |

*Indexed* is how many documents the file contributes to the collection.
*Retrievable* is how many of those a query can actually reach, after the
metadata filter described below.

The source URLs for the four MITRE bundles are left blank on purpose: the exact
distribution they were pulled from could not be established from the files
themselves. See the note at the end of this file.

### How the dates were established

Only the NVD feed carries a download date: its root `timestamp` field reads
`2025-06-16T14:00:01.0271875`, which is when NVD generated the feed.

For the rest there is nothing in the file that records when it was fetched. The
newest content in each one gives a floor — the download cannot predate it — but
a floor is not a date, so the table says "not determined":

| File | Newest content |
|---|---|
| `enterprise-attack.json` | object modified `2025-05-02` |
| `ics-attack.json` | object modified `2025-04-28` |
| `mobile-attack.json` | object modified `2025-04-28` |
| `stix-capec.json` | object modified `2023-01-30` |
| `known_exploited_vulnerabilities.csv` | latest `dateAdded` `2025-06-16` |

## What gets dropped at ingestion

`setup_vector_db` walks the STIX bundles and skips two object types outright.
They carry no standalone prose worth embedding: a relationship is a pair of
identifiers, and a marking definition is a copyright statement.

| Reason | Enterprise | ICS | Mobile | CAPEC | Total |
|---|---|---|---|---|---|
| `relationship` | 20411 | 1367 | 1766 | 1172 | 24716 |
| `marking-definition` | 1 | 1 | 1 | 1 | 4 |

24720 objects skipped in total. Every remaining object needs a `name` to be
indexed; none were dropped for lacking one. The NVD and KEV records are indexed
in full: 2118 of 2118 and 1366 of 1366.

## What gets filtered at retrieval

`search_knowledge_base` excludes four STIX types from every query:

```python
where={"stix_type": {"$nin": ["malware", "tool", "intrusion-set", "campaign"]}}
```

These describe named entities — specific malware families, tools, threat groups
and campaigns observed elsewhere in the world. They dominated retrieval for
malware findings and pushed the report into naming families that appear nowhere
in the analysed log. They stay in the index, but queries cannot reach them.

| Type | Documents |
|---|---|
| `malware` | 814 |
| `tool` | 93 |
| `intrusion-set` | 212 |
| `campaign` | 58 |
| **Total** | **1177** |

By file: enterprise-attack 986, mobile-attack 137, ics-attack 54.

Chroma's `$nin` only tests documents that carry the key, so NVD and KEV records,
which have no `stix_type` at all, are unaffected and remain fully searchable.

## Note for the maintainer

The four MITRE source URLs are blank because they could not be confirmed from
the file contents. Two hints, in case they help you fill them in:

- The three ATT&CK bundles declare `spec_version: 2.0` at the bundle root, which
  points at the older STIX 2.0 distribution rather than the current STIX 2.1
  `attack-stix-data` repository.
- `stix-capec.json` carries no root `spec_version`, but its objects declare
  `2.1`, so it came from a different distribution than the ATT&CK bundles.
