---
title: "Adventures in Misconfiguration, Supply Chain, and Critical Flaws"
date: 2026-07-13
summary: "This week, we're diving into a smorgasbord of cybersecurity news, from a hilarious misconfiguration revealing phishing ops to critical zero-day exploits and supply chain attacks."
tags: ["weekly", "misconfiguration", "phishing", "supply-chain", "zero-day", "vulnerability"]
draft: false
heroImage: "images/blog/2026-07-13-weekly-cyber-news.svg"
---

Hola, team! Juan here, back for another weekly dive into the wild world of cybersecurity. It's Monday, July 13th, 2026, and as usual, the threat landscape isn't taking any holidays. We've got a mixed bag this week – a touch of attacker sloppiness, some nasty zero-days, and the ever-present supply chain nightmares. Let's dig in.

## Misconfigured Server Reveals Three Evilginx Phishing Operations Targeting Microsoft 365

First up, we have a classic case of an attacker tripping over their own shoelaces. A live Microsoft 365 phishing operation was exposed because the operator left a Python web server listening on a public port with directory listing enabled. The cherry on top? The command `python3 -m http.server 8080` was still in their `.bash_history`. French security firm Lexfo seized the opportunity, lifted the entire toolkit, and even pivoted to uncover two more operations.

*My take:* This is a perfect example of why basic operational security (OpSec) is crucial, even for the bad guys. From a blue team perspective, this underscores the importance of continuous external scanning and monitoring. If Lexfo could find this misconfigured server, so could other threat actors, or worse, other security researchers. It's a reminder that attackers, like anyone else, can make mistakes. For us, it means keeping our eyes peeled for similar lapses on *our* perimeter – because if they can do it, so can our internal teams if we're not careful. Think about regular external vulnerability scans and asset discovery.

## iCagenda and Balbooa Forms Joomla Flaws Reportedly Exploited as Zero-Days

Moving on to something a bit more urgent: CISA has added two maximum-severity security flaws impacting iCagenda and Balbooa extensions for Joomla to its Known Exploited Vulnerabilities (KEV) catalog. These vulnerabilities, both rated a perfect 10.0 on the CVSS scale, are being actively exploited as zero-days in the wild.

*My take:* This is a big one. Any vulnerability with a 10.0 CVSS score and *active exploitation* should trigger an immediate response. If your organization uses Joomla with either the iCagenda or Balbooa Forms extensions, you need to prioritize patching or mitigation *now*. The fact that these are in CISA's KEV catalog means nation-states and sophisticated threat actors are already leveraging them. As sysadmins, we need to have robust asset inventory and patch management processes to quickly identify affected systems and apply updates. Don't wait for a patch cycle; this is an emergency.

## Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install

Supply chain attacks continue to be a persistent nightmare. The jscrambler npm package, a legitimate tool, was compromised in its 8.14.0 release. Simply installing this version would run a Rust infostealer on your machine via a `preinstall` hook. Socket flagged this malicious release just six minutes after it was published, which is impressive.

*My take:* This highlights the ongoing challenge of securing the software supply chain. Developers often pull in hundreds, if not thousands, of dependencies without deep scrutiny. For us on the blue team, this means implementing controls like package integrity checks, software composition analysis (SCA) tools, and potentially even sandboxing build environments. Educating developers about the risks of blindly installing packages, even from seemingly reputable sources, is also critical. Always verify, never fully trust.

## Hackers Weaponize Balochistan Police Portal in Multi-Group Espionage Campaigns

In a sobering turn, researchers have uncovered multi-group cyber espionage targeting several Pakistani law enforcement organizations, primarily by suspected China- and India-aligned threat actors. The Balochistan Police portal was weaponized, with compromised servers hosting web applications managing police and citizen data. This activity stretched from February 2024 to April 2026.

*My take:* This is a stark reminder that critical infrastructure and government services are constant targets. The weaponization of a police portal means attackers not only breached the organization but also repurposed its assets for further attacks or intelligence gathering. It emphasizes the need for comprehensive security for public-facing assets, including robust intrusion detection, threat hunting capabilities, and incident response plans. Data breaches in these sectors can have significant real-world consequences beyond just financial loss.

## Critical Zimbra Flaw Could Let Crafted Emails Run Malicious Code in User Sessions

Zimbra users, pay attention. A critical security vulnerability impacting the Classic Web Client has been discovered, and it could lead to arbitrary code execution. Described as a stored cross-site scripting (XSS) vulnerability, specially crafted emails could execute malicious scripts in a user's session. It hasn't received a CVE yet, but Zimbra is urging customers to update.

*My take:* Stored XSS in an email client is a particularly nasty vulnerability because it requires minimal user interaction once the malicious email is received. This essentially turns the email client into an attack vector. If your organization uses Zimbra, prioritize these updates immediately. Ensure your email security gateways are configured to detect and block suspicious email content, but don't rely solely on them; client-side patching is non-negotiable here.

## URGENT - Progress Tells ShareFile Customers to Shut Down Storage Zone Controllers Over Security Threat

Finally, Progress Software has issued an urgent directive to ShareFile customers: shut down the Windows servers running their Storage Zone Controllers. They've confirmed a "credible external security threat" and temporarily disabled access to affected accounts.

*My take:* When a vendor tells you to *shut down* critical infrastructure, you know it's serious. This suggests a potentially widespread or highly impactful vulnerability, likely involving remote code execution or unauthorized access. As sysadmins, these are the moments when our incident response plans are truly tested. We need clear communication channels with the vendor, a rapid assessment of our own deployments, and the ability to execute emergency shutdown or mitigation procedures swiftly. It also highlights the inherent risks of relying on third-party software and the importance of having contingency plans for such scenarios.

That's a wrap for this week. Stay vigilant, keep patching, and let's keep those systems secure. Until next time!