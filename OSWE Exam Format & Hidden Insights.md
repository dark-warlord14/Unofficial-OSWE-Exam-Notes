# OSWE Exam Unofficial Format & Hidden Insights

This document provides consolidated, non-official information about the OSWE exam’s format, setup, and operational nuances, all sourced and cited from reputable community experiences, Discord, Reddit, LinkedIn, blogs, and more. For each reference, the direct link is given.

***

## Table of Contents
- [Exam Structure & Scoring](#exam-structure--scoring)
- [Lab Machines & Environment](#lab-machines--environment)
- [Technical Constraints & Setup](#technical-constraints--setup)
- [Automation Scripts & Reporting](#automation-scripts--reporting)
- [Proctoring & Exam Experience](#proctoring--exam-experience)
- [Community, Discord, and Templates](#community-discord-and-templates)
- [Common Vulnerability Types](#common-vulnerability-types)
- [General Exam Tips & Management](#general-exam-tips--management)
- [Summary Table](#summary-table)
- [Reference Links](#reference-links)

***

## Exam Structure & Scoring

- The exam consists of **two targets**, each with several vulnerabilities, totaling **100 points** ([alaa.blog][1], [4xpl0r3r.com][2], [hesec.de][3], [r/OSWE][4]).
- Points are roughly allocated as:
  - **Authentication bypass:** 35 points per target.
  - **Remote Code Execution (RCE):** 15 points per target.
- Minimum passing score is **85/100** ([alaa.blog][1], [hesec.de][3], [OSWE Reddit][5]).
- Partial credit for partial exploitation is possible ([hesec.de][3], [alaa.blog][1], [Reddit][6]).

> **Sources:**  
> [alaa.blog][1], [hesec.de][3], [4xpl0r3r.com][2], [Reddit OSWE][5], [Reddit][6]


## Lab Machines & Environment

- Each target is comprised of **3 machines**: 
  - **Debug/RDP:** For live code analysis (read only).
  - **Production/Target:** For actual exploitation/exploit verification.
  - **Kali/Attack:** Launchpad for attacks ([hesec.de][3], [alaa.blog][1], [Reddit][4]).
- Codebases may contain up to **hundreds of thousands of lines** ([OSWE Reddit][7]), often across multiple languages.

> **Sources:**  
> [hesec.de][3], [alaa.blog][1], [Reddit][4], [4xpl0r3r.com][2], [Reddit OSWE][7]


## Technical Constraints & Setup

- **Poor RDP connectivity** is a recurring theme; frequent disconnects, lag, and refreshes reported ([Reddit][5], [mrlsecurity.com][8]).
- **VPN must be configured according to strict MTU values** ([OffSec Support][9]).
- Debug and prod machines are near-identical in environment but may have slight config differences (credentials, env vars) ([hesec.de][3]).
- Standard file transfers, SSHFS, or clipboard copying between host and exam VM are prohibited ([hesec.de][3], [Reddit][10]).

> **Sources:**  
> [Reddit][5], [mrlsecurity.com][8], [OffSec Support][9], [hesec.de][3], [Reddit][10]


## Automation Scripts & Reporting

- **You must provide a single, automated script** per target demonstrating the exploit chain—no manual input allowed beyond essential arguments ([Reddit][11], [GitHub][12], [LinkedIn][13]).
- The script should chain all vulnerabilities necessary for full compromise in seconds ([Reddit][11], [Payatu][14]).
- **Report must be heavily documented** with step-by-step screenshots (including console output, code, payloads, and flag retrieval) ([GitHub][15], [noraj GitHub][16], [SysReptor][17]).
- Report templates (Markdown/PDF) are available from the OSWE community ([noraj GitHub][16], [noraj GitHub2][18]).

> **Sources:**  
> [Reddit][11], [GitHub][12], [Payatu][14], [GitHub][15], [SysReptor][17], [noraj GitHub][16], [LinkedIn][13], [noraj GitHub2][18]


## Proctoring & Exam Experience

- Continuous online proctoring for 48 hours; **no AI tools, multiple screens, or suspicious windows** allowed ([LinkedIn][13], [Reddit][10], [mrlsecurity.com][8]).
- Bathroom and meal breaks must be announced in proctor chat; returning late may prompt checks ([Reddit][19], [LinkedIn][20]).
- Tightly monitored for clipboard, browser plugin, and external device usage ([OffSec][21], [StationX][22]).

> **Sources:**  
> [Reddit][19], [LinkedIn][13], [LinkedIn][20], [Payatu][14], [mrlsecurity.com][8], [OffSec][21], [StationX][22]


## Community, Discord, and Templates

- **Unofficial Discord server(s):** Active and supportive. Invitation links are shared within Reddit and user posts ([Reddit][23], [Reddit][24]).
- Community GitHub has code samples, report templates, and organization tips ([GitHub][12], [noraj GitHub][16]).
- Reddit is active with up-to-date walkthroughs, reviews, and feedback ([Reddit OSWE][5], [hesec.de][3], [Reddit][24]).

> **Sources:**  
> [Reddit][23], [Reddit][24], [GitHub][12], [noraj GitHub][16]


## Common Vulnerability Types

- **Authentication bypass:** Logic or flow flaws, parameter tampering.
- **SQL injection** (blind, classic, time-based).
- **XXE, SSTI, File upload bypass, Deserialization.**
- Targets are selected to require chaining multiple real-world style bugs ([HackMD][25], [Payatu][14], [LinkedIn][13]).

> **Sources:**  
> [HackMD][25], [Payatu][14], [LinkedIn][13], [alaa.blog][1]


## General Exam Tips & Management

- Most finish first machine in **8-12 hours, second in 12-20**; **5-8 hours** suggested for report writing ([Payatu][14], [hesec.de][3]).
- Points are awarded for each vulnerability, so partial progress can yield a pass if well documented ([Reddit][6]).
- **Sleep and break management:** success stories range from all-nighters to regular 8-hour sleep schedules ([Payatu][14], [mrlsecurity.com][8]).
- **Testing automation scripts** on both debug and prod VMs prior to submission is strongly recommended ([Reddit][11]).

> **Sources:**  
> [Payatu][14], [hesec.de][3], [Reddit][6], [mrlsecurity.com][8], [Reddit][11]


***

## Summary Table

| Category           | Detail/Requirement                                                                 |
|--------------------|------------------------------------------------------------------------------------|
| Machines           | 3 per target: Debug (RDP), Production (target), Kali (attack) [3][1][4]         |
| Points             | 100 total, 85 to pass; auth bypass (35), RCE (15) per machine [1][3][4]         |
| Automation Script  | Single, end-to-end chain per target, in Python recommended [11][12][13]            |
| Report             | Extensive, screenshot-heavy, step by step [15][17][16]                             |
| Connectivity       | Frequent RDP/VPN issues, MTU critical, no copy/paste [5][8][9]                  |
| Proctoring         | Strict, 48h monitored, no unauthorized tools/screens [13][10][21][22][8]          |
| Discord/Reddit     | Vibrant, for active updates, templates, troubleshooting [23][24][12][16]           |

***

## Reference Links

Each citation is linked directly for context and further reading:

1. [alaa.blog - OSWE journey][1]
2. [4xpl0r3r.com - OSWE review][2]
3. [Reddit: OSWE Discord & resources][23]
4. [GitHub - exploit-writing-for-oswe][12]
5. [SysReptor - OSWE exam report (PDF)][17]
6. [noraj GitHub OSWE report template][16]
7. [hesec.de - journey to OSWE][3]
8. [Reddit: OSWE exam attempt review][4]
9. [Payatu - OSWE exam debrief][14]
10. [Reddit: OSWE main channel][24]
11. [Reddit OSWE: exam reviews][5]
12. [mrlsecurity.com - OSWE insights][8]
13. [OffSec Support - VPN issues][9]
14. [noraj GitHub report template 2][18]
15. [LinkedIn OSWE review #1][13]
16. [Reddit automation script requirement][11]
17. [LinkedIn OSWE review #2][20]
18. [OffSec Blog - rules and AI][21]
19. [StationX OSWE Guide][22]
20. [GitHub - OSWE-exam-report-template_xl-sec][18]
21. [HackMD - AWAE prep][25]
22. [Reddit: partial point discussion][6]
23. [GitHub - OSWE report template][15]

***

### Full Link List
- [alaa.blog - OSWE experience][1]
- [4xpl0r3r.com review][2]
- [Reddit: Discord channels][23]
- [Reddit: OSWE main][24]
- [Payatu - How I cracked OSWE][14]
- [Reddit: OSWE firsthand pass][5]
- [hesec.de OSWE experience][3]
- [Reddit: exam attempt review][4]
- [Reddit: automation script discussion][11]
- [GitHub: exploit-writing-for-oswe][12]
- [SysReptor OSWE report PDF][17]
- [noraj Github Markdown template][16]
- [mrlsecurity.com - post-OSWE reflection][8]
- [OffSec Support on VPN issues][9]
- [GitHub: OSWE report template xl-sec][18]
- [LinkedIn: OSWE review][13]
- [LinkedIn: OSWE review 2][20]
- [StationX: OSWE guide][22]
- [Offsec blog post on AWAE/OSWE rules][21]
- [HackMD: AWAE exam prep][25]
- [Reddit thread on partial points][6]
- [GitHub: OSWE PDF report template][15]

***

### Direct References

- [alaa.blog - My AWAE/OSWE Journey](https://alaa.blog/2020/08/my-awae-oswe-journey-and-how-i-passed-the-exam/)  
- [4xpl0r3r.com - OSCE3 Review](https://www.4xpl0r3r.com/Certifications/OSCE3-Review-OSCP-OSEP-OSWE-OSED/)  
- [Reddit: OSWE Discord (resources, cert holders)](https://www.reddit.com/r/OSWE/comments/10jyxus/oswe_discord_with_resourceschannelsstudents_and/)  
- [Reddit: r/OSWE](https://www.reddit.com/r/OSWE/)  
- [Payatu - OSWE exam review 2023](https://payatu.com/blog/cracking-the-code-my-journey-to-conquering-the-oswe-exam/)  
- [Reddit: passed OSWE—firsthand experience](https://www.reddit.com/r/OSWE/comments/1hvsdlv/first_attempt_passed_oswe_about_one_and_a_half/)  
- [hesec.de - My journey to OSWE](https://hesec.de/posts/oswe/)  
- [Reddit: exam attempt review](https://www.reddit.com/r/OSWE/comments/dygn8u/exam_attempt_review/)  
- [Reddit: single script requirement](https://www.reddit.com/r/OSWE/comments/yn2ul2/oswe_single_script_requirement/)  
- [GitHub: exploit-writing-for-oswe](https://github.com/rizemon/exploit-writing-for-oswe)  
- [SysReptor - OSWE exam report PDF](https://docs.sysreptor.com/assets/reports/OSWE-Exam-Report.pdf)  
- [noraj GitHub: OSWE report template](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSWE-exam-report-template_noraj_v1.md)  
- [mrlsecurity.com - Passing OSWE in 2024](https://mrlsecurity.com/posts/oswe-in-2024/)  
- [OffSec Support: VPN/VM issues](https://help.offsec.com/hc/en-us/articles/360046293832-Common-VPN-and-Machine-VM-Issues)  
- [GitHub: OSWE report template xl-sec](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSWE-exam-report-template_xl-sec_v1.md)  
- [LinkedIn: Omar Hussein OSWE review](https://www.linkedin.com/pulse/offensive-security-web-expert-oswe-review-omar-hussein-ho5re)  
- [LinkedIn: Adrian Tiron OSWE review](https://www.linkedin.com/posts/tironadrian_oswe-offensivesecurity-websecurity-activity-7335580827562520579-lrrs)  
- [StationX: OSWE guide 2025](https://www.stationx.net/what-is-oswe-certification/)  
- [OffSec Blog: Attacking the Web the OffSec Way](https://www.offsec.com/blog/attacking-the-web-offsec-way/)  
- [HackMD: AWAE prep (Chivato)](https://hackmd.io/@Chivato/Hyflsx0ZI)  
- [Reddit: OSWE partial points discussion](https://www.reddit.com/r/OSWE/comments/bsods2/i_just_passed_the_oswe_exam_amaa_about_the_exam/)  
- [GitHub: Sample OSWE PDF Report](https://noraj.github.io/OSCP-Exam-Report-Template-Markdown/output/examples/OSWE-exam-report-template_noraj_v1.pdf)  

***

**All facts, details, and claims in this summary are directly linked to the above sources.**

Sources
- [1] My AWAE/OSWE Journey and how I passed the exam https://alaa.blog/2020/08/my-awae-oswe-journey-and-how-i-passed-the-exam/
- [2] OSCE3 Review (OSCP+OSEP+OSWE+OSED) - 4xpl0r3r's blog https://www.4xpl0r3r.com/Certifications/OSCE3-Review-OSCP-OSEP-OSWE-OSED/
- [3] My journey to OSWE :: hesec.de — Hacking and Fun https://hesec.de/posts/oswe/
- [4] Exam attempt review : r/OSWE - Reddit https://www.reddit.com/r/OSWE/comments/dygn8u/exam_attempt_review/
- [5] First attempt passed OSWE (About one and a half months ago) https://www.reddit.com/r/OSWE/comments/1hvsdlv/first_attempt_passed_oswe_about_one_and_a_half/
- [6] I just passed the OSWE exam. AMAA about the exam and course https://www.reddit.com/r/OSWE/comments/bsods2/i_just_passed_the_oswe_exam_amaa_about_the_exam/
- [7] Starting my journey to OSWE! : r/oscp - Reddit https://www.reddit.com/r/oscp/comments/16ttpnw/starting_my_journey_to_oswe/
- [8] How does it feel to have passed OSWE in 2024? - MRLSECURITY https://mrlsecurity.com/posts/oswe-in-2024/
- [9] Common VPN and Machine/VM Issues - OffSec Support Portal https://help.offsec.com/hc/en-us/articles/360046293832-Common-VPN-and-Machine-VM-Issues
- [10] Offsec Web Expert OSWE Review - $(H0j3n) https://h0j3n.github.io/posts/Offsec-Web-Expert-OSWE-Review/
- [11] OSWE Single Script requirement - Reddit https://www.reddit.com/r/OSWE/comments/yn2ul2/oswe_single_script_requirement/
- [12] rizemon/exploit-writing-for-oswe - GitHub https://github.com/rizemon/exploit-writing-for-oswe
- [13] Offensive Security Web Expert (OSWE) Review - LinkedIn https://www.linkedin.com/pulse/offensive-security-web-expert-oswe-review-omar-hussein-ho5re
- [14] How I cracked the OSWE exam in 2023 - Payatu https://payatu.com/blog/cracking-the-code-my-journey-to-conquering-the-oswe-exam/
- [15] [PDF] Offensive Security Web Expert Exam Report - GitHub Pages https://noraj.github.io/OSCP-Exam-Report-Template-Markdown/output/examples/OSWE-exam-report-template_noraj_v1.pdf
- [16] OSWE-exam-report-template_noraj_v1.md - GitHub https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSWE-exam-report-template_noraj_v1.md
- [17] [PDF] Offensive Security - SysReptor https://docs.sysreptor.com/assets/reports/OSWE-Exam-Report.pdf
- [18] OSWE-exam-report-template_xl-sec_v1.md - GitHub https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSWE-exam-report-template_xl-sec_v1.md
- [19] AWAE/OSWE review from a non-developer perspective https://infosecwriteups.com/awae-oswe-review-from-a-non-developer-perspective-2c2842cfbd4d
- [20] OSWE - Advanced Web Attacks and Exploitation - Review (2023) https://4pfsec.com/oswe
- [21] Attacking the Web: The Offensive Security Way https://www.offsec.com/blog/attacking-the-web-offsec-way/
- [22] Complete OSWE Certification Guide (2025 Edition) - StationX https://www.stationx.net/what-is-oswe-certification/
- [23] OSWE Discord with Resources/channels/students and cert holders https://www.reddit.com/r/OSWE/comments/10jyxus/oswe_discord_with_resourceschannelsstudents_and/
- [24] r/OSWE - Reddit https://www.reddit.com/r/OSWE/
- [25] AWAE (OSWE) preparation - HackMD https://hackmd.io/@Chivato/Hyflsx0ZI
