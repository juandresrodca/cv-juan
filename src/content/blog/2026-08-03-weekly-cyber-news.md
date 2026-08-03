---
title: "August's First Week: Critical Vulnerabilities and Supply Chain Risks"
date: 2026-08-03
summary: "This week, we're looking at critical vulnerabilities in popular platforms, from remote management tools to hardware wallets, highlighting supply chain risks and the need for rigorous security."
tags: ["weekly", "vulnerability", "supply-chain", "rce", "patching", "malware", "hardware-wallet"]
draft: false
heroImage: "images/blog/2026-08-03-weekly-cyber-news.svg"
---

Welcome back to the weekly roundup, folks. This week has been a stark reminder of how quickly things can go sideways, especially when critical infrastructure or widely used platforms are involved. We're seeing everything from tampered scientific data to multi-million dollar crypto heists, and several instances of remote code execution. Let's dig in.

## Thermo Fisher Patches Flaw Affecting DNA File Integrity

Thermo Fisher Scientific has addressed a significant flaw, CVE-2026-17583, in their Applied Biosystems human identification software. This vulnerability could allow data files (.fsa and .hid outputs) to be altered before analysis, with changes being nearly undetectable if laboratory controls are bypassed.

From a blue-team perspective, this one really hits home. Imagine the potential for forensic evidence tampering or misdiagnosis in critical applications. While it requires circumvention of lab controls, the "nearly undetectable" aspect is terrifying. This highlights the crucial need for robust integrity checks and secure processing environments, especially with data that underpins scientific and legal decisions. We often focus on IT infrastructure, but software integrity in specialized fields like bio-informatics is just as, if not more, critical.

## N-able N-central Servers Compromised After Incomplete Fix

N-able reported that attackers exploited an authentication bypass (CVE-2026-18577) in their N-central remote monitoring and management (RMM) platform. What's worse is that their initial fix was incomplete, leading to subsequent takeovers of customer N-central servers and, by extension, access to systems managed through them. The fully patched version is 2026.3.1.7.

This is a classic supply chain attack vector. RMM tools are a goldmine for attackers, offering broad access to numerous customer environments. The fact that the first patch was incomplete is a huge concern; it underscores the difficulty of getting security right the first time and the need for rapid, thorough follow-up when new information emerges. For sysadmins, this is a clear warning to prioritize RMM security, ensure immediate patching, and segment your RMM environment heavily. Always assume compromise and monitor for anomalous activity originating from these critical tools.

## Hugging Face Diffusers Flaws Could Enable Arbitrary Code Execution

Researchers have uncovered three high-severity flaws in Hugging Face's Diffusers library. These vulnerabilities could allow specially crafted model repositories to execute arbitrary code on machines loading them, effectively bypassing the `trust_remote_code` safeguard. This opens up a significant security risk within the artificial intelligence (AI) supply chain.

AI is becoming ubiquitous, and this vulnerability highlights a major blind spot for many organizations. As AI models become integral to more applications, the supply chain for these models will be increasingly targeted. For us sysadmins, it means we need to extend our security considerations to include the provenance and integrity of AI models and libraries. Simply downloading a model from a public repository without understanding its underlying code can introduce serious risk. Static analysis and sandboxing for AI development environments are becoming non-negotiable.

## Coldcard Hardware Wallet Flaw Linked to $70 Million Bitcoin Theft

A major incident saw 1,196 Bitcoin addresses drained of approximately $70.2 million in just 41 minutes. This was traced back to a firmware flaw in Coldcard, a popular Bitcoin-only hardware wallet. The flaw, originating from a March 2021 firmware integration error, rerouted seed generation to a deterministic software pseudorandom number generator (PRNG) instead of a true random source.

This is a devastating illustration of how even seemingly minor coding errors can have catastrophic financial consequences. For anyone managing high-value digital assets, this reinforces the criticality of open-source scrutiny, independent audits, and understanding the complete chain of trust in hardware and software. Relying on a PRNG for cryptographic keys is a fundamental no-go, and this incident serves as a harsh lesson in cryptographic best practices. Always ensure your entropy sources are robust and verifiable.

## Hackers Poison Adform Script to Swap Crypto Wallet Addresses

Attackers successfully modified a JavaScript file served by advertising technology company Adform. This malicious script functioned as a browser-side tool, designed to rewrite cryptocurrency wallet addresses on websites carrying the affected script. The incident, detected by Adform on July 27, led to the swift removal of the malicious code and client notifications.

This is a classic supply chain attack, but on the client side, using compromised ad tech. It's a reminder that even legitimate third-party scripts loaded on your website can introduce significant risks. For organizations, it's about robust content security policies (CSPs), subresource integrity (SRI) checks for critical scripts, and continuous monitoring of assets loaded in your users' browsers. For users, it's a call to be extra vigilant when making crypto transactions and always double-check wallet addresses before confirming.

## Adobe Campaign Classic CVSS 10.0 Flaw Allows Arbitrary Code Execution

Adobe released security updates for a maximum-severity (CVSS 10.0) flaw, CVE-2026-48449, in their enterprise marketing automation platform, Campaign Classic (ACC). This vulnerability is an incorrect authorization issue that could lead to arbitrary code execution without user interaction.

A CVSS 10.0 is as bad as it gets – unauthenticated remote code execution. This is the kind of vulnerability that keeps sysadmins up at night. For organizations using ACC, patching needs to be the absolute top priority. This also highlights the inherent risk in complex enterprise software; even marketing platforms can expose critical attack surfaces if not rigorously secured. Ensure your patch management processes are robust, and always monitor your edge and internal networks for exploitation attempts targeting newly disclosed critical vulnerabilities.

---

That's the rundown for this week. A lot to think about, from the integrity of scientific data to the security of our wallets and critical IT infrastructure. Stay vigilant, patch everything, and question the trust you place in every link of your software supply chain.

Juan Rodriguez,
IT Systems Administrator and Cybersecurity Specialist