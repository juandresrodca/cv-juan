---
title: "The Wild West of AI, Botnets, and Ransomware's Rise"
date: 2026-06-18
summary: "This week, we're diving into the shady dealings of a botnet tied to a public firm, critical NGINX flaws, the looming threat of orphaned AI agents, the resurgence of INC Ransomware, and a new crypto-clipper campaign."
tags: ["weekly", "botnet", "nginx", "rce", "ai-security", "ransomware", "supply-chain", "cryptocurrency", "malware"]
draft: false
---

Alright, another week, another deep dive into the digital trenches. It's Juan here, and this week has been a mixed bag of the usual suspects and some emerging headaches that are definitely keeping us on our toes. Let's get into it.

## ‘Popa’ Botnet Linked to Publicly-Traded Israeli Firm

Kicking things off, Brian Krebs dropped a bombshell this week about the "Popa" botnet. For four years, this Android-based botnet has been hijacking millions of consumer TV boxes, forcing them to relay internet traffic for ad fraud, account takeovers, and data scraping. The kicker? Researchers have linked it directly to NetNut, a "residential proxy" provider operated by the publicly-traded Israeli firm, Ala.

My take as a sysadmin: This is a prime example of the murky waters of "legitimate" businesses blurring lines with illicit activities. Residential proxy services often get abused, but direct links to a botnet controlling consumer devices? That’s a whole new level of concern. From a blue-team perspective, it highlights the need for rigorous outbound traffic monitoring. Are your users' devices acting as unwilling proxies? Are you seeing unusual patterns in your network's external communications, especially from IoT or less-managed devices? This kind of operation thrives on unnoticed background activity. It also makes you question the supply chain – what services are your vendors using, and how transparent are they about their infrastructure?

## F5 Patches Two Critical NGINX Open Source Flaws Enabling Remote Code Execution

Next up, F5 released critical security updates for NGINX Open Source, addressing two severe vulnerabilities. Specifically, CVE-2026-42530, with a CVSS v4 score of 9.2, is a use-after-free vulnerability in the `ngx_http_v3_module`. This one can be triggered by a remote, unauthenticated attacker, potentially leading to remote code execution (RCE).

My take as a sysadmin: NGINX is absolutely everywhere, powering a massive chunk of the web. An RCE vulnerability, especially one that’s unauthenticated and remote, is about as bad as it gets. This needs to be at the top of every patch management list immediately. If you're running NGINX Open Source, check your versions and get these updates deployed. This is a classic "patch now or pay later" scenario. Make sure your change management process is swift for critical vulnerabilities like this, and consider setting up automated scanning for your web server configurations to quickly identify vulnerable instances.

## Orphaned AI Agents: How to Find Hidden Access Risks Inside Your Network

The rapid adoption of AI tools is generating new security challenges, and this piece from The Hacker News nails one of the biggest: "orphaned AI agents." These are AI tools left running with standing privileges after their creator or owner leaves the company. The question posed is simple: if an autonomous AI agent interacts with your core intellectual property, can your security team instantly name its authorizer? For most, the answer is no.

My take as a sysadmin: This is a ticking time bomb. We’ve seen this movie before with orphaned user accounts and service accounts – now imagine that with an AI agent that might have broad access to sensitive data and the ability to execute actions autonomously. The rush to adopt AI has created significant administrative debt. We need to implement robust lifecycle management for AI agents, treating them like any other privileged entity. This means clear ownership, regular access reviews, and immediate deactivation upon employee departure. Your identity and access management (IAM) strategy needs to evolve to include these AI entities, ensuring you can track, control, and revoke their permissions effectively.

## ThreatsDay Bulletin: Claude Chat Abuse, NastyC2 npm Packages, Device-Code Phishing + 25 More Stories

The latest ThreatsDay Bulletin is a sobering reminder that "the internet got used exactly as designed, which is worse." It highlights a slew of persistent threats: AI chat links morphing into malware delivery, macOS attacks leaving minimal traces, exposed edge gear, poisoned packages, and device-code phishing.

My take as a sysadmin: This bulletin serves as a consolidated "what's out there" warning. The mention of AI chat abuse and macOS attacks, in particular, caught my eye. The threat landscape is diversifying, and attackers are adapting to new technologies. We need to reinforce user education against phishing, particularly device-code phishing, which can bypass traditional email filters. For blue teams, the rise of in-memory macOS attacks means relying less on disk forensics and more on endpoint detection and response (EDR) with robust behavioral analysis. And poisoned npm packages? That’s supply chain risk manifesting in real-time – strict vetting of third-party libraries is crucial.

## Microsoft Details Windows Clipper Malware Campaign Using USB LNK Worm and Tor-Based C2

Microsoft Defender Security Research Team has detailed a Windows-based cryptocurrency clipper campaign active since February 2026. This clipper malware uses Windows Script Host and ActiveX logic to launch a bundled Tor proxy and poll a hidden-service C2 server. It often spreads via USB LNK worms.

My take as a sysadmin: This is a nasty one. USB LNK worms are an old trick, but they're still effective, especially in environments where USB drive policies are lax. The use of Tor for C2 makes detection and blocking more challenging for traditional perimeter defenses. For blue teams, endpoint monitoring is key here – watching for suspicious script host activity, unexpected Tor connections, and any attempts to modify clipboard contents. User awareness is also critical; remind staff about the dangers of plugging unknown USB drives into their machines. And ensure your security solutions are capable of detecting this kind of obfuscated C2 communication.

## INC Ransomware Emerges as Major RaaS Threat in 2026 with 830+ Victims Since 2023

Finally, cybersecurity researchers have charted the evolution of INC Ransomware as a major RaaS (Ransomware-as-a-Service) threat. Since August 2023, they've claimed over 830 victims. The disruption of LockBit and the shutdown of BlackCat seemingly created an opportunity for INC to expand, as affiliates migrated to alternative operations.

My take as a sysadmin: Ransomware continues to be a top-tier threat, and INC’s rise underscores the "whack-a-mole" nature of fighting these groups. When one falls, another rises to take its place. This reinforces the need for a holistic defense: robust backups (tested, isolated, and immutable), strong endpoint protection, multi-factor authentication (MFA) everywhere, network segmentation, and proactive vulnerability management. For blue teams, staying informed about the tactics, techniques, and procedures (TTPs) of emerging ransomware groups like INC is crucial for effective threat hunting and incident response. Don't assume that just because one major player is down, the threat has diminished.

---

That’s a wrap for this week. It’s clear that the bad actors are innovating, adapting, and finding new ways to exploit both human and technological vulnerabilities. Keep your systems patched, your users educated, and your vigilance high.

Stay safe out there,

Juan Rodriguez
IT Systems Administrator & Cybersecurity Specialist, Intel Ireland