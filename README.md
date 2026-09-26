# CTI Group Project: Tycoon2FA AiTM Phishing-as-a-Service

**Course:** Introduction to Threat Hunting, Astana IT University, 2026–2027  
**Group:** CS-2426  
**Members:** Dilnaz Estaikyzy, Ademi Akmaganbet

## About the project

This project studies how a modern **Phishing-as-a-Service (PhaaS)** platform works and how it can be detected, using threat intelligence methods. Our case study is **Tycoon2FA**, an *Adversary-in-the-Middle (AiTM)* phishing kit that has been active since August 2023. Microsoft attributes it to Storm-1747.

Tycoon2FA is rented to other criminals as a ready-made service. It places a reverse proxy between the victim and the real Microsoft 365 or Google login page, and steals passwords, MFA codes and session cookies in real time. This allows attackers to bypass most common MFA methods. The kit hides from analysts with obfuscated JavaScript (including invisible Unicode characters), CAPTCHA filtering and anti-debugging code.

We follow the course's weekly structure. Each week adds one step of the threat intelligence cycle to the same case:

1. Build the theory base: glossary and threat classification.
2. Collect OSINT data about the kit and its infrastructure.
3. Process the data: build an IOC dataset, then filter and normalize it, store it in MISP, and write a detection rule.
4. Later weeks: map the attack to the Cyber Kill Chain and MITRE ATT&CK, build hunting hypotheses, and emulate the attack.

## Weekly progress

| Week | Syllabus topic | Task (syllabus §3.3) | Deliverable |
|---|---|---|---|
| 1 | Cyber Threat Intelligence Fundamentals | Glossary of CTI terms; classify threats and their sources | [`week1_glossary_classification_en.md`](week1_glossary_classification_en.md) |
| 2 | Data Collection Process | OSINT collection with Shodan, VirusTotal and Maltego; data source mapping | [`week2_osint_collection_en.md`](week2_osint_collection_en.md) |
| 3 | Data Processing and Exploitation | Deploy MISP and import IOCs; apply filtering and normalization | [`week3_misp_iocs_en.md`](week3_misp_iocs_en.md), [`dataset/`](dataset/), [`scripts/`](scripts/) |

## Dataset

The dataset is in [`dataset/`](dataset/). Its README describes every column.

![Dataset overview](images/dataset_overview.png)

- **Raw data:** three public Tycoon2FA IOC lists published by eSentire TRU (2025–2026).
- **Processed data:** `dataset/tycoon2fa_iocs.csv` has **667 unique, defanged indicators**: 229 URLs, 225 hostnames, 131 registered domains, 76 login egress IPs, plus kit artifacts from vendor reports.
- **MISP import:** `dataset/misp_event_tycoon2fa.json`.

## Repository structure

```
.
├── README.md
├── week1_glossary_classification_en.md
├── week2_osint_collection_en.md
├── week3_misp_iocs_en.md
├── dataset/
│   ├── README.md                    # data dictionary and processing steps
│   ├── raw/                         # original public IOC files (eSentire TRU)
│   ├── tycoon2fa_iocs.csv           # normalized dataset
│   └── misp_event_tycoon2fa.json    # MISP event for import
├── scripts/
│   ├── normalize_iocs.py            # filtering, normalization, dedup, MISP export
│   └── plot_dataset.py              # dataset overview chart
└── images/
    └── dataset_overview.png
```

To reproduce the results (Python 3, plus matplotlib for the chart):

```bash
python3 scripts/normalize_iocs.py
python3 scripts/plot_dataset.py
```

## Use of AI tools

In line with the course policy on generative AI, we disclose that we used an AI assistant (Claude, Anthropic) in this project for:

- **Formulating the data:** wording the glossary definitions, the threat classification and the descriptions of the collected indicators and dataset columns.
- **Preparing the report:** structuring the Markdown documents, improving the English text, and help with the helper scripts for processing the dataset.

The AI was not used as a source of facts. All technical information comes from the references listed below. The group checked it against those sources and is responsible for the final content. The topic choice, the OSINT collection, the MISP work and the conclusions are our own work.

## References

1. Sekoia TDR, "Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit", March 2024. <https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit/>
2. Microsoft Threat Intelligence, "Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale", Microsoft Security Blog, March 2026. <https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/>
3. Trustwave SpiderLabs, "Tycoon2FA New Evasion Technique for 2025", April 2025. <https://trustwave.com/en-us/resources/blogs/spiderlabs-blog/tycoon2fa-new-evasion-technique-for-2025>
4. eSentire TRU, "Tycoon 2FA Operators Adopt OAuth Device Code Phishing", May 2026. <https://www.esentire.com/blog/tycoon-2fa-operators-adopt-oauth-device-code-phishing>
5. eSentire TRU, public IOC repository, Tycoon2FA (dataset source). <https://github.com/eSentire/iocs/tree/main/Tycoon2FA>
6. Elastic Security Labs, "Detecting Tycoon 2FA AiTM attacks across Entra ID and Google Workspace", May 2026. <https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering>
7. MITRE ATT&CK: T1566.002 Spearphishing Link, T1557 Adversary-in-the-Middle, T1539 Steal Web Session Cookie. <https://attack.mitre.org/>
8. MISP Project, MISP Training Materials and User Guide. <https://www.misp-project.org/documentation/>
9. ENISA, ENISA Threat Landscape (recommended reading, Week 1). <https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape>
10. M. Bazzell, *Open Source Intelligence Techniques* (recommended reading, Week 2).
11. Recorded Future, *The Threat Intelligence Handbook* (Week 1 lecture source).
