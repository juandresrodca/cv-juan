---
title: "Beyond the Network: Air-Gapped Leaks, Cross-Platform RATs, and AI Skill Evasion"
date: 2026-07-06
summary: "This week, we're looking at advanced data exfiltration from air-gapped systems via video cables, a new Java-based cross-platform RAT (QuimaRAT), an Opera GX flaw for data theft, AI skill evasion, a US govt. entity's $1M extortion payment, and North Korean malicious packages."
tags: ["data-exfiltration", "air-gap", "malware", "rat", "cross-platform", "browser-security", "ai-security", "ransomware", "extortion", "nation-state", "supply-chain", "weekly"]
draft: false
---

Alright team, let's dive into some of the more interesting cybersecurity headlines from the past few days. This week's news covers everything from physical-layer exfiltration to sophisticated cross-platform malware and the ongoing challenges in securing AI environments.

## TrojPix Attack Leaks Data From Air-Gapped Systems via Video Cable Emissions

First up, researchers at Shandong University have demonstrated a fascinating and concerning new technique called TrojPix. This attack allows data to be exfiltrated from air-gapped systems by subtly tweaking on-screen pixels in a way imperceptible to the human eye. These pixel changes then radiate faint radio signals via the video cable, which a nearby receiver can decode.

My take: This is a classic example of thinking outside the box for data exfiltration. As a blue teamer, air-gapped systems are often seen as the ultimate defense against network-based breaches. However, this reminds us that physical security and electromagnetic emanation security (TEMPEST) are still critical considerations. While TrojPix requires malware to already be on the machine, it underscores the need for robust endpoint security even on isolated systems. We can't just assume a physical air gap is enough; we need to be vigilant about what gets onto those machines in the first place, and perhaps even consider shielding or monitoring for unusual electromagnetic activity in sensitive areas.

## New Java-Based QuimaRAT MaaS Built to Run on Windows, Linux, and macOS

Next, we're seeing a new Java-based Remote Access Trojan (RAT) called QuimaRAT, which is particularly nasty because it targets Windows, Linux, and macOS environments. LevelBlue reports it's being advertised under a Malware-as-a-Service (MaaS) model, with subscription costs ranging from $150 to $1,200 for lifetime access.

My take: Cross-platform malware like QuimaRAT is a growing pain point for sysadmins. It simplifies the attacker's job by allowing them to use a single tool to target a diverse enterprise environment. The Java foundation means it's highly portable, and the MaaS model lowers the barrier to entry for less skilled attackers. Our defense here needs to be multi-layered: robust endpoint detection and response (EDR) on all OS types, strict access controls, and vigilant patching of Java runtimes and related applications. User awareness training against phishing and social engineering is also paramount, as RATs often rely on initial compromise through user interaction.

## Opera GX Flaw Let Malicious Sites Auto-Install Mods to Steal Data From Visited Pages

Moving to browser security, a flaw in Opera GX, the gaming-focused version of Opera, allowed malicious websites to silently install browser add-ons. These add-ons could then lift specific data from pages a victim visits. Researchers even showed a proof-of-concept where a full Gmail address was reconstructed from a single visit without any user clicks. Opera has patched the flaw and found no evidence of exploitation.

My take: This is a stark reminder of the dangers lurking in browser extensions and the permissions they can wield. Even legitimate extensions can be exploited or compromised. For us sysadmins, this highlights the need for strict browser configuration management, including limiting extension installations to approved lists or blocking them entirely in critical environments. Regular browser updates are non-negotiable, and it's worth reminding users about the risks of installing unverified extensions, even if this particular flaw was silent. Always assume any browser vulnerability could lead to data exfiltration.

## SkillCloak Lets Malicious AI Agent Skills Evade Static Scanners with Self-Extracting Packing

The world of AI security is heating up with a new study from Hong Kong University of Science and Technology. They've developed "SkillCloak," a technique that allows malicious add-on "skills" for AI coding agents to evade static scanners. Their strongest trick bypassed every scanner tested over 90% of the time, although the same team also built a runtime checker that caught most of them.

My take: This is where the rubber meets the road for AI adoption in the enterprise. If we're deploying AI agents that can integrate "skills" or plugins, the security implications are enormous. The fact that static analysis can be so easily bypassed means we can't rely solely on pre-deployment checks. We need robust runtime monitoring and behavioral analysis for AI agents. Treating AI skills like any other third-party code, with proper sandboxing, least privilege principles, and continuous monitoring, will be crucial. This is a new frontier, and attackers are already finding ways around early defenses.

## U.S. Government Entity Paid Kairos $1 Million in Data-Theft Extortion Case

In a concerning development, a U.S. government entity reportedly paid around $1 million to keep stolen files from being leaked. This case, documented by Rakesh Krishnan for Ransom-ISAC, is interesting because the group, Kairos, doesn't appear to be a traditional ransomware gang. There's no evidence they encrypted any files, suggesting a pure data-theft and extortion model.

My take: This confirms a worrying trend: attackers are moving beyond just encrypting files to focusing solely on data exfiltration and extortion. Even if you have robust backups and can recover from encryption, the threat of public data dumps or sales of sensitive information remains potent. This means our defense strategies must emphasize data loss prevention (DLP) and secure data handling even more aggressively. Incident response plans need to account for extortion without encryption, and organizations need clear policies on whether to pay ransoms/extortions, understanding the risks and ethical implications.

## North Korean Hackers Publish 108 Malicious Packages and Extensions in PolinRider Campaign

Finally, North Korean threat actors, linked to the "Contagious Interview" campaign, have been observed publishing 108 unique malicious packages and web browser extensions across platforms like npm, Packagist, Go, and Google Chrome as part of their "PolinRider" campaign. This campaign remains active, with new malicious packages likely to appear as maintainer accounts are compromised.

My take: This is a classic supply chain attack strategy, and nation-state actors like those from North Korea are increasingly using it. By injecting malicious code into popular software repositories and extension stores, they can reach a wide range of targets. For us, this means greater scrutiny of third-party libraries and dependencies, especially in development and CI/CD pipelines. Tools for software composition analysis (SCA) and rigorous vetting of any external code or browser extensions are essential. We also need to be aware of account compromises for package maintainers and apply strong authentication (MFA!) everywhere.

That's a wrap for this week's cyber news. Stay sharp out there, keep patching, and never underestimate the ingenuity of attackers.

Cheers,
Juan Rodriguez