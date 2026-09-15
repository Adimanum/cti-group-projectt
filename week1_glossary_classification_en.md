# Week 1 — Cyber Threat Intelligence Fundamentals

**Group project topic:** Detection and analysis of malware distributed via AI-era phishing-as-a-service kits, using YARA and CAPE Sandbox
**Case study:** Tycoon2FA — Adversary-in-the-Middle (AiTM) Phishing-as-a-Service (PhaaS) platform (active since 2023, actively evolving through 2025-2026)

## 1. Why this case

Tycoon2FA is one of the most active and technically documented phishing platforms of 2025-2026. It is sold as a subscription service to low-skill attackers (Phishing-as-a-Service), uses heavily obfuscated JavaScript to evade static analysis, bypasses MFA by relaying session cookies in real time, and has already had public YARA detection rules released against it (Trustwave). This makes it an ideal case for practicing the full pipeline: OSINT collection -> MISP storage -> dynamic analysis in CAPE Sandbox -> writing a YARA rule.

## 2. Glossary of key terms

| # | Term | Definition |
|---|---|---|
| 1 | **PhaaS (Phishing-as-a-Service)** | A subscription-based criminal business model where a ready-made phishing kit/infrastructure is rented to other attackers. |
| 2 | **AiTM (Adversary-in-the-Middle)** | A phishing technique where the attacker's server sits between the victim and the real login page, relaying credentials and session tokens in real time. |
| 3 | **Session cookie hijacking** | Stealing an active, already-authenticated session token to bypass the need for a password or MFA code. |
| 4 | **MFA bypass** | Any technique that defeats multi-factor authentication, e.g. by relaying the one-time code the moment the victim enters it (as AiTM kits do). |
| 5 | **Obfuscation** | Deliberately transforming code (renaming variables, encoding strings) to make it hard for humans or static tools to read. |
| 6 | **Anti-debugging / anti-analysis** | Code designed to detect when it's being inspected (dev tools, sandboxes) and change behavior or stop running. |
| 7 | **CAPE Sandbox** | An open-source automated malware analysis platform that runs a suspicious file/script in an isolated environment and records its behavior. |
| 8 | **YARA** | A pattern-matching tool used to write "rules" that identify malware families or specific tools by textual/binary patterns in files. |
| 9 | **IOC (Indicator of Compromise)** | A technical artifact (domain, file name pattern, hash) that shows evidence of a specific attack or kit. |
| 10 | **Reverse proxy** | A server that forwards requests to another server while appearing to be the destination itself - the core mechanism behind AiTM kits. |
| 11 | **Cloudflare Turnstile abuse** | Using a legitimate CAPTCHA service to filter out security scanners and automated analysis tools before showing the real phishing page. |
| 12 | **AI-generated phishing** | Phishing content (emails, landing pages, or even code) produced or refined with the help of generative AI to increase realism and reduce detection. |
| 13 | **Threat Intelligence Feed** | A stream of IOC/report data shared by vendors or communities (e.g. published YARA rules, MISP feeds). |

## 3. Threat classification

| Parameter | Value |
|---|---|
| **Threat type** | Commoditized AiTM credential- and session-theft phishing kit (PhaaS) |
| **Source** | Criminal service sold to multiple unrelated attacker groups, not a single actor |
| **Delivery vector** | Phishing email (payroll/bonus/document/update lures) with a link or QR code |
| **Payload** | Obfuscated JavaScript + reverse-proxy backend impersonating Microsoft 365/Gmail login |
| **Target** | Any organization using Microsoft 365 / Gmail with MFA - broad, opportunistic |
| **Motivation** | Financial (credential/session resale, business email compromise) |
| **Kill Chain classification** | Reconnaissance -> Weaponization (kit purchase/config) -> Delivery (email/QR) -> Exploitation (victim opens link) -> C2 (WebSocket relay) -> Actions on Objectives (account takeover, BEC) |

## Sources
Sekoia.io, "Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit"; Microsoft Security Blog, "Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale" (2026); Trustwave, Tycoon 2FA evasion technique analysis and YARA rule release.
