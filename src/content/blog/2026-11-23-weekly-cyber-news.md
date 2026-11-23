---
title: "MSP Vulnerabilities and the Persistence of Covert Access"
date: 2026-11-23
summary: "This week, we're diving into the exploitation of critical flaws in MSP tools like ScreenConnect and N-able Mail Assure, the dangers of supply chain vulnerabilities, and how threat actors are getting clever with tools like SoftEther VPN to maintain covert access."
tags: ["weekly", "vulnerabilities", "msp", "supply-chain", "vpn", "code-injection", "rce"]
draft: false
heroImage: "images/blog/2026-11-23-weekly-cyber-news.svg"
---

Alright team, another week, another stack of vulnerabilities to digest. It feels like every Monday brings a fresh wave, and this one's no different. We've got a lot to unpack, especially around supply chain issues and how attackers are getting creative to stay hidden once they're in. Let's get to it.

## Webworm Modifies SoftEther VPN for Evasion

First up, the China-aligned threat actor, Webworm, is reportedly modifying SoftEther VPN Bridge to remove detection fingerprints and disguise it as network monitoring software. Their goal? Covert remote access. This isn't groundbreaking in terms of TTPs – threat actors have always customized tools – but it's a solid reminder that standard signatures often aren't enough.

From a blue team perspective, this hits close to home. Relying solely on signature-based detection for network tools is a losing battle. We need to be focusing on behavioral analysis. What processes are running? What network connections are being established? Does this "network monitoring software" really need to connect to that IP in China? Always baseline your normal network activity. Anomalies are your friend here. Endpoint Detection and Response (EDR) with strong behavioral analytics is crucial for spotting these modified tools before they become a persistent headache.

## Weekly Recap: Shell Trouble and 0-Days

The Hacker News recap highlighted a trend: VMware 0-Day, Java4Shell, NGINX2Root, Ruby2Shell. The common theme? Shells, and the ease with which a small opening can lead to a full compromise. This reinforces the principle of defense in depth. A stolen key, a trusted message, a routine update – these are often the unassuming entry points.

For us sysadmins, this means every single piece of software, every update, every configuration change, needs scrutiny. It’s not just about patching. It’s about understanding the potential attack surface. Your VMware instance isn't just a hypervisor; it's a potential jump box. Your Java app isn't just a business application; it's a potential RCE vector. Assume compromise and build your monitoring and alerting accordingly.

## Critical binary-parser Flaw Enables JavaScript Injection

A critical flaw (CVE-2026-134814, CVSS 9.2/8.1) in the `binary-parser` library could allow arbitrary code execution via malicious parser definitions. This is a classic code injection vulnerability affecting versions prior to 2.3.1.

This is another supply chain special. How many of your applications, especially those built on Node.js, rely on this or similar libraries? It's a rhetorical question because the answer is "a lot." The only way to mitigate this effectively is robust Software Composition Analysis (SCA) tooling in your CI/CD pipeline, and regular dependency scanning for deployed applications. Keep those dependencies updated, especially the widely used ones. A single vulnerable library can be the weakest link in an otherwise strong chain.

## ScreenConnect Flaw Hijacks MSP Technician PCs

This one is a big red flag for anyone in an MSP or anyone *using* an MSP. Hackers are actively exploiting CVE-2026-84869 (CVSS 9.9), a critical ScreenConnect client flaw. This allows a guest to transfer and execute a malicious payload on a connecting technician's host.

This is a nightmare scenario. Your MSP, a trusted partner, becomes the vector for an attack on your internal network. If you're an MSP, patch immediately and audit your technician endpoints. If you're leveraging an MSP, demand proof of patching and understand their security posture. Is their remote access solution segmented? Are their technicians using hardened workstations? This is a direct path to sensitive systems, and it's being exploited *in the wild*. Don't delay patching or reviewing your MSP's security.

## N-able Discloses Critical Mail Assure Vulnerability During Breach Investigation

N-able disclosed a critical SSRF flaw (CVE-2026-134624) in Mail Assure and SpamExperts Hosted Cloud, found during a breach investigation. This allowed a user with high-level API access to open connections to internal systems.

Another MSP-focused hit, and this time it's email filtering, which is often a critical service for many organizations. The fact that it was discovered *during* a breach investigation highlights the importance of incident response in uncovering deeper issues. SSRF vulnerabilities are dangerous because they allow an attacker to pivot from an external-facing service to internal network resources. If you're using N-able Mail Assure, ensure you've applied any and all mitigations and patches. Also, review the principle of least privilege for API access. High-level API access should be extremely restricted and heavily monitored.

## Hackers Exploit Critical ASP.NET Anti-CSRF Library Flaw for Unauthenticated RCE

Finally, researchers are urging users to stop using the legacy ASP.NET anti-CSRF library `Idunno.AntiCsrf` due to an actively exploited critical vulnerability (CVE-2026-131914, CVSS 9.3). This allows unauthenticated RCE.

Legacy libraries are a ticking time bomb. Developers often pull them in, forget about them, and they sit there, unpatched, until they become a critical vulnerability. If you have any ASP.NET applications, especially older ones, check for this library immediately. It's a reminder to conduct regular code audits and ensure dependencies are current and actively maintained. "Legacy" in cybersecurity often means "actively vulnerable."

That's a wrap for this week. Stay vigilant, keep patching, and assume breach. Your network depends on it.

Juan Rodriguez
IT Systems Administrator & Cybersecurity Specialist, Intel Ireland