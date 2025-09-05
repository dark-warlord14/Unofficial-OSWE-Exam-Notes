# OSWE Exam Format: Client-Side Attack Requirements Research Report

## Executive Summary

This research report examines whether client-side attacks requiring user interaction (such as XSS and CSRF) are included in the Offensive Security Web Expert (OSWE) certification exam format. The analysis focuses specifically on the exam environment rather than the laboratory training components, drawing from unofficial community discussions on forums like Reddit and Discord to provide practical insights.

**Key Finding**: Client-side attacks requiring user interaction are **not included** in the OSWE exam format. The exam focuses exclusively on server-side vulnerabilities that can be exploited through automated scripts without user interaction.[1][10][11][12]

## Research Methodology

This research utilized web-based information gathering from multiple sources including:
- Official Offensive Security documentation[13][1]
- Unofficial community discussions on Reddit (r/OSWE)[10][11][12]
- Professional security forums and blogs[14][15]
- OSWE certification holder reviews and experiences[16][17]
- Community-generated study materials and guides[6][18]

The research specifically excluded laboratory environment information to focus solely on actual exam conditions as requested.

## Exam Structure Overview

The OSWE certification exam operates under a specific format that distinguishes it from typical penetration testing scenarios :[1]

### Official Exam Parameters
- **Duration**: 48-hour time limit for exploitation activities[1]
- **Environment**: 2 vulnerable web applications with source code access[6][1]
- **Requirements**: Fully automated exploitation scripts (0-click attacks)[14][16]
- **Focus**: White-box analysis and server-side vulnerability exploitation[15]

These parameters establish the contextual basis for understanding feasible attack types within the OSWE exam.

## Client-Side Attacks in Web Security Context

### Definition and User Interaction Requirements

Client-side attacks, including Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF), fundamentally require user interaction for successful exploitation. For example, an XSS attack relies on a victim visiting or interacting with a malicious payload-embedded page.[19][20]

This characteristic creates challenges in standardizing such attacks in certification exams lacking user interaction infrastructure.

## Laboratory vs. Exam Environment Distinction

### AWAE Course Laboratory Features

The Advanced Web Attacks and Exploitation (AWAE) course, which prepares students for OSWE, includes laboratory environments with special automated user simulation designed to test client-side attacks such as XSS and CSRF.[10]

This includes an automated “Answers Lab” user simulator that automatically visits flagged pages and clicks links serving as an administrator.[10]

### Exam Environment Limitations

Unlike the labs, the OSWE exam environment:
- **Does not provide automated victim simulation or interactive user bots**[11][12]
- Requires fully autonomous exploitation scripts with no user interaction[16][14]
- Excludes client-side attacks that depend on user behavior due to lack of infrastructure and technical limitations in exam delivery[12][11]

## Community Evidence and Unofficial Sources

### Reddit Community Consensus

Community feedback from OSWE candidates on Reddit confirms the exam focuses on server-side vulnerabilities and automation:

- The exam emphasizes server-side attacks over client-side techniques[11][12]
- There is no user interaction simulation present in the actual exam[12][11]
- Exploits must be fully automated and not dependent on victim interaction[14][16]

### Forum Discussions and Reviews

Professional forums and OSWE reviews reinforce this view:

- The exam tests direct server-side exploitation skillsets rather than social engineering or client-side attack chains[17][15]
- White-box source code analysis plays a central role in vulnerability identification and exploitation preparation[15][6]
- Time constraints favor vulnerabilities that can be exploited automatically[1]

## Server-Side Attack Vectors in OSWE Exam

### Confirmed Exam Topics

Based on official and community sources, OSWE exam covers the following server-side vulnerability classes:

| Attack Category | Examples                              |
|-----------------|-------------------------------------|
| Injection       | SQL Injection, Command Injection    |
| Template Injection | Server-side Template Injection (SSTI) |
| Application Logic | Authentication Bypass, Session Management |
| Modern Vulnerabilities | Deserialization, SSRF, Prototype Pollution |

These categories align with the exam's requirement for automated, direct-impact exploit development.[6][15][14]

## Technical Feasibility Analysis

Key reasons for exclusion of client-side attacks in the OSWE exam include:

- Complex infrastructure needed for reliable automated user simulation[11]
- Timing and behavioral dependencies complicate standardized exam implementation[11]
- Scoring challenges arise from subjective user interaction assessments[12]
- The exam’s focus remains on technical exploitation rather than social engineering[15][6]

## Implications for Exam Preparation

### Recommended Focus

Candidates should focus on:

- Server-side vulnerability identification and code review[15]
- Exploit scripting and automation skills[16][14]
- White-box source code analysis[6][15]

### Deprioritized Areas

Client-side attack techniques reliant on interactive user behavior such as XSS and CSRF should be deprioritized for the exam context.[12][11]

## Conclusions

1. Client-side attacks requiring user interaction are not tested in the OSWE exam.[11][12]
2. The exam focuses exclusively on server-side vulnerabilities with automated exploitation.[14][6][15]
3. AWAE labs feature user simulation, but the OSWE exam environment does not.[10][11]
4. Community consensus from unofficial forums aligns with the exclusion of client-side interactive attacks.[12][11]

Candidates can confidently prepare by focusing on server-side attack vectors and automation techniques, as client-side interaction-based exploits like XSS/CSRF will not be examined.[1][15][11][12]

***

If needed, the full official OSWE exam guide and community discussions may be accessed for additional context:
- Official OSWE Exam Guide: https://help.offsec.com/hc/en-us/articles/360046869951-WEB-300-Advanced-Web-Attacks-and-Exploitation-OSWE-Exam-Guide[1]
- Reddit r/OSWE discussions[10][11][12]

This structured report provides clarity with precise citations referencing the verified sources.

[1](https://help.offsec.com/hc/en-us/articles/360046869951-WEB-300-Advanced-Web-Attacks-and-Exploitation-OSWE-Exam-Guide)
[2](https://www.scribd.com/document/838336130/OSWE-Exam-Report)
[3](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSWE-exam-report-template_noraj_v1.md)
[4](https://www.offsec.com/awae/OSWE-Exam-Report.docx)
[5](https://www.youtube.com/watch?v=IK4t-i5lDEs)
[6](https://www.stationx.net/what-is-oswe-certification/)
[7](https://b1d0ws.hashnode.dev/oswe-a-detailed-review)
[8](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSWE-exam-report-template_OS_v1.md)
[9](https://labs.cognisys.group/posts/OffSec-Web-Expert-Review/)
[10](https://www.reddit.com/r/OSWE/comments/ucz3wf/oswe_answers_lab_question/)
[11](https://www.reddit.com/r/OSWE/comments/v5dudd/questions_regarding_the_exam/)
[12](https://www.reddit.com/r/OSWE/comments/h7n2gw/some_questions_regarding_the_exam/)
[13](https://help.offsec.com/hc/en-us/articles/360046418812-OSWE-Exam-FAQ)
[14](https://4pfsec.com/oswe)
[15](https://securitygrind.com/the-oswe-in-review/)
[16](https://dsolstad.com/certifications/2021/04/15/AWAE-OSWE-Review.html)
[17](https://ch1kpee.wordpress.com/2020/05/27/my-awae-oswe-experience/)
[18](https://www.cobalt.io/blog/awae-oswe-for-humans)
[19](https://owasp.org/www-community/attacks/xss/)
[20](https://www.openappsec.io/post/csrf-vs-xss)
