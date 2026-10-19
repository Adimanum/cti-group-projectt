# Week 7 — Using MITRE CAR (Cyber Analytics Repository)

**Group:** CS-2426 · Dilnaz Estaikyzy, Ademi Akmaganbet  
**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

**Syllabus tasks (§3.3, Week 7):** (1) select an analytic from MITRE CAR and implement it in a SIEM; (2) map the analytic to related ATT&CK techniques.
Source: <https://car.mitre.org>. Recommended reading: MITRE CAR documentation.

| What we produced | File |
|---|---|
| The CAR analytic implemented and executed over our SIEM dataset | [`car/car_simultaneous_logins.py`](car/car_simultaneous_logins.py) → [`car/car_results.txt`](car/car_results.txt) |
| The same analytic as SIEM queries (Elastic ES\|QL + Splunk SPL) | [`car/car_queries_esql.txt`](car/car_queries_esql.txt) |

## 1. Analytics vs detections

A quick distinction the lecture asks for:

| | **Detection** (a rule) | **Analytic** (CAR) |
|---|---|---|
| Goal | Fire an alert on a known-bad pattern | Surface *suspicious behaviour* for an analyst to judge |
| Example (ours) | Sigma: sign-in with `axios` User-Agent | CAR: the same account active from two places at once |
| False positives | Tuned to be very low | Expected; needs triage |
| Output | Alert | A list of candidates to investigate |

MITRE **CAR** is a public library of such analytics, each written as data-model pseudocode plus the ATT&CK techniques it relates to. It is SIEM-independent, so you translate each one into your own query language.

## 2. The analytic we selected

**[CAR-2013-02-008 — "Simultaneous Logins on a Host"](https://car.mitre.org/analytics/CAR-2013-02-008/)**

Original pseudocode (from car.mitre.org):

```
users_list     = search UserSession:Login
users_grouped  = group users_list by hostname
users_grouped  = from users_grouped select min(time), max(time), count(user) by hostname
multiple_logins = filter where (max_time - min_time <= 1 hour and user_count > 1)
```

**Data model:** object `user_session`, action `login`, fields `user`, `hostname`.
**ATT&CK mapping given by CAR:** **T1078 Valid Accounts** (sub-techniques .002 Domain Accounts, .003 Local Accounts).

**Why we picked it.** CAR analytics are mostly Windows/Sysmon endpoint analytics, but this one is about *logon sessions*, which maps cleanly to our cloud sign-in data. Its core idea — **the same principal active in two places inside one hour** — is exactly what an AiTM attack looks like: the real victim and the attacker's relay use the one account at the same time.

## 3. Adapting it to cloud identity logs

The original flags **one host with several users**. In an AiTM attack it is instead **one account used from two networks at once**. We keep the exact structure and the 1-hour window, but:

| Original (endpoint) | Our adaptation (cloud) |
|---|---|
| group by **hostname** | group by **user** |
| count distinct **users** | count distinct **source ASNs** |
| flag `user_count > 1` | flag `asn_count ≥ 2` **and** at least one ASN is external (not the corporate net 64500 or staff ISP 64501) |

## 4. Implementing it in the SIEM

Elastic **ES|QL** ([`car/car_queries_esql.txt`](car/car_queries_esql.txt) also has the Splunk SPL):

```sql
FROM tycoon2fa-hunt
| WHERE log_type == "signin" AND result == "success"
| EVAL window = DATE_TRUNC(1 hour, @timestamp)
| STATS asn_count = COUNT_DISTINCT(asn),
        external  = COUNT_DISTINCT(CASE(asn IN (64500, 64501), NULL, asn)),
        asns = VALUES(asn_name), ips = VALUES(src_ip)
      BY user, window
| WHERE asn_count >= 2 AND external >= 1
| SORT window
```

We also implemented the analytic directly in Python (standard library) so it can be run and scored without a SIEM licence, over the same Week 5 dataset:

```text
$ python3 car/car_simultaneous_logins.py
user                              first login (ASN)                 second login (ASN)
aliya.zhaksybek@contoso.example   08:55 CONTOSO-CORP (192.0.2.20)   09:11 IT HOSTLINE LTD (142.252.171.135)
askar.karimov@contoso.example     14:04 CONTOSO-CORP (192.0.2.43)   14:59 M247 Europe SRL (2a0d:5600:8:94::...)
flagged users : 2   true positives : 2   false positives : 0
compromised users found : 2/3   not flagged : dana.abenova
```

**Result:** the analytic flags **2 of the 3** compromised accounts with **0 false positives**. For each, it shows the victim's real corporate session and the attacker's external session inside the same hour — the hallmark of a hijacked session.

**Why it misses dana (an honest result).** dana has no legitimate session that overlaps the attacker's within the hour, so there is no "simultaneous" pair to find. That gap is exactly why we keep several analytics: the Week 5 hunts **H1 (new MFA method)** and **H3 (Graph reconnaissance burst)** catch dana. One analytic is never full coverage — analytics complement each other, and CAR is meant to be combined.

## 5. Mapping the analytic to ATT&CK

| Technique | Why it applies |
|---|---|
| **T1078.004 Valid Accounts: Cloud Accounts** | The attacker signs in with the victim's valid account (CAR maps this analytic to T1078; we use the cloud sub-technique) |
| **T1557 Adversary-in-the-Middle** | The two concurrent sessions exist *because* of the AiTM relay — this is the signal the analytic sees |
| **T1550.004 Web Session Cookie** | The attacker's concurrent session is created by replaying the stolen cookie |

These techniques are already in our coverage from earlier weeks; the CAR analytic gives us an **independent, second way** to catch the same AiTM activity (sign-in anomalies) on top of the Week 5 behaviour hunts. Defence in depth: if the attacker evades one analytic, another still fires.

## 6. Summary of the week

- We explained the difference between an **analytic** (CAR) and a **detection** (a rule).
- We selected **CAR-2013-02-008 (Simultaneous Logins)** and **adapted it to cloud sign-ins**: the same account active from two ASNs within one hour.
- We **implemented it in the SIEM** (ES|QL + SPL) and ran it over our dataset: **2/3 compromised accounts, 0 false positives**, with an honest explanation of the third.
- We **mapped the analytic to ATT&CK** (T1078.004, T1557, T1550.004) — a second, independent way to catch the same activity (defence in depth).
