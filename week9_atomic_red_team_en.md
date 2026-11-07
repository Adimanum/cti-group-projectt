# Week 9 — Atomic Red Team

**Group:** CS-2426 · Dilnaz Estaikyzy, Ademi Akmaganbet
**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

**Syllabus tasks (§3.3, Week 9):** (1) run selected atomic tests (e.g. T1059, T1003); (2) record and analyze the test results in a SIEM.
Sources: Atomic Red Team GitHub repo, Red Canary docs. Recommended reading: Atomic Red Team Wiki and GitHub Repository.

| What we produced | File |
|---|---|
| An Atomic Red Team–style test suite for our techniques (safe placeholders) | [`atomic/atomics_tycoon2fa.yaml`](atomic/atomics_tycoon2fa.yaml) |
| A runner that runs the tests, **records** them in the SIEM and **analyses** them | [`atomic/run_atomics.py`](atomic/run_atomics.py) |
| The recorded SIEM events (same schema as our Week 5 index) | [`atomic/atomic_siem_events.ndjson`](atomic/atomic_siem_events.ndjson) |
| The analysis result (which test each detection caught) | [`atomic/atomic_results.txt`](atomic/atomic_results.txt) |
| SIEM analysis queries (ES\|QL + SPL) | [`atomic/analyze_esql.txt`](atomic/analyze_esql.txt) |
| Results chart + ATT&CK Navigator layer | [`atomic/atomic_results.png`](atomic/atomic_results.png), [`atomic/atomic_layer.json`](atomic/atomic_layer.json) |

## 1. What Atomic Red Team is

**Atomic Red Team** (by Red Canary) is an open library of small, portable **atomic tests**. Each test reproduces **one** ATT&CK technique with a short, documented command, so a blue team can answer a precise question: *"if this exact technique runs, does our detection fire?"*. Each test is written in YAML with a technique ID, a description, supported platforms, input arguments and an **executor** (the command).

The difference from Week 8 (CALDERA) is the *unit of work*:
- **CALDERA (Week 8)** runs a whole **ordered adversary profile** end to end.
- **Atomic Red Team (Week 9)** runs **one technique at a time**, to validate detection coverage technique by technique.

## 2. Safety

We do **not** run the real weaponised atomic tests. Every executor in our suite is a **harmless `echo`** placeholder. For the tests that have a real public counterpart we cite its reference (e.g. *"Atomic Red Team T1059.001 Test #1"*) for documentation only — we never reproduce the dangerous command. Running `run_atomics.py` performs **no attack**: it prints the step and writes the SIEM log record the real action *would* leave, against a fake tenant (`contoso.example`), so we can do the "record and analyse in a SIEM" part safely.

## 3. The tests we selected

The syllabus names **T1059** and **T1003** as examples. We included both as required, but they are **endpoint** techniques; Tycoon2FA is an **identity/cloud** attack, so we also selected four atomic tests that match *our* kill chain (from Weeks 6–8):

| # | ATT&CK | Atomic test | Scope | Maps to our detection |
|---|---|---|---|---|
| 1 | **T1059.001** | PowerShell execution marker (required example) | endpoint | — (out of our SIEM scope) |
| 2 | **T1003.001** | LSASS credential-dump marker (required example) | endpoint | — (out of our SIEM scope) |
| 3 | **T1550.004** | Replay stolen session cookie with a non-browser client | cloud | Sigma (axios UA) + hunt H1a |
| 4 | **T1098.005** | Register a new MFA device after a scripted sign-in | cloud | hunt H1 |
| 5 | **T1564.008** | Create a delete/hide inbox rule for finance mail | cloud | hunt H2 |
| 6 | **T1087.004** | Microsoft Graph reconnaissance burst | cloud | hunt H3 |

## 4. Record + analyse in the SIEM

`run_atomics.py` does the three Atomic-Red-Team steps:

1. **Execute** — runs each benign test command.
2. **Record** — writes the SIEM event(s) the real action would leave into `atomic_siem_events.ndjson` (37 events, in the exact 16-field schema of our Week 5 hunt index, so the same queries work). For example T1098.005 records a scripted sign-in **and** a "Register device" audit event 8 minutes later, so the sequence can be detected.
3. **Analyse** — runs our Week 5 detections (hunts H1/H2/H3 + the axios Sigma rule) over those events, in Python's built-in SQLite, and reports per test whether it was detected. The same analysis is written as ES\|QL/SPL in [`analyze_esql.txt`](atomic/analyze_esql.txt) for a real SIEM (upload the NDJSON to Elastic, index `atomic-tycoon2fa`).

## 5. Result

![Atomic Red Team results](atomic/atomic_results.png)

```text
# 6 atomic tests run; 4 detected by our identity/cloud SIEM detections.
# 2 not detected: the generic endpoint examples (T1059.001, T1003.001) -
#   Tycoon2FA is an identity attack, so endpoint execution is outside our current SIEM scope.
# 37 SIEM events recorded to atomic_siem_events.ndjson.
```

- **4 of 6 tests detected.** Every atomic test that maps to our Tycoon2FA kill chain (session-cookie replay, device registration, hiding rule, Graph recon) was caught by a detection we built in Weeks 3/5/7. This independently **validates those detections** technique by technique.
- **2 tests not detected — and that is the useful finding.** The generic endpoint examples (PowerShell execution, LSASS dumping) are **outside our SIEM's scope**: our telemetry and rules are built for identity and cloud sign-ins, not host-process events. Those would be caught by an **EDR** on the endpoint, not by us.

This is an honest **coverage boundary**: our project detects the *identity* attack that Tycoon2FA actually is, and Atomic Red Team made the limit of that coverage explicit — a natural piece of future work (add endpoint/EDR telemetry).

```bash
python3 atomic/run_atomics.py    # run tests, record SIEM events, analyse
python3 atomic/plot_atomic.py    # chart + Navigator layer
```

## 6. Summary of the week

- We built an **Atomic Red Team–style suite** of 6 tests (the required T1059/T1003 examples + 4 for our own techniques), all **safe placeholders**.
- We **recorded** every test in the SIEM (37 events in our Week 5 schema) and **analysed** them with our own detections, in SQLite and as ES\|QL/SPL.
- **4/6 tests were detected**; the 2 endpoint examples were not — an honest, expected gap that shows exactly where our identity-focused coverage ends.

## References

- Red Canary, *Atomic Red Team* — GitHub repository and Wiki. <https://github.com/redcanaryco/atomic-red-team> · <https://github.com/redcanaryco/atomic-red-team/wiki>
- Red Canary, *Atomic Red Team* documentation. <https://redcanary.com/atomic-red-team/>
- MITRE ATT&CK: T1059.001, T1003.001, T1550.004, T1098.005, T1564.008, T1087.004. <https://attack.mitre.org/>
