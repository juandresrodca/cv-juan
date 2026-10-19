---
title: "Supply Chain Woes, AI Keys, and Broadcom's Unpatched Wi-Fi"
date: 2026-10-19
summary: "This week, we're diving into some wild supply chain attacks, the risks of AI keys in breaches, Broadcom's unpatched Wi-Fi vulnerability, and some shady dealings in ransomware negotiation."
tags: ["supply-chain", "ai", "broadcom", "wi-fi", "ransomware", "github", "npm", "weekly"]
draft: false
heroImage: "images/blog/2026-10-19-weekly-cyber-news.svg"
---

Alright, team. Another week, another round of cybersecurity news that keeps us on our toes. It feels like the digital landscape is constantly shifting, with new attack vectors popping up faster than we can patch the old ones. Let's dig into some of the more impactful stories from the past few days.

## Ransom Negotiator Suspected of Running ShinyHunters Extortion Site

This one is a real head-scratcher and, frankly, deeply concerning. KrebsOnSecurity reports that federal investigators suspect executives at *ransomware negotiation firms* of having unusually close ties with, and even assisting, the ShinyHunters group. One executive in the U.S. is even believed to have helped them operate.

**My Take:** As a sysadmin and blue teamer, this news hits hard. We're often caught in the terrible position of dealing with ransomware, and these negotiation firms are presented as a lifeline. To think that some individuals within these very firms might be complicit, or even actively involved with, the attackers undermines trust in a critical support structure. It highlights the murky ethics in the ransomware ecosystem and the need for extreme due diligence when selecting third-party negotiators. For us on the front lines, it reinforces the principle that our best defense is prevention and a robust recovery plan, rather than relying solely on external negotiators who might have compromised intentions.

## GhostAction Attackers Plant Credential Stealer Disguised as Font in GitHub Repos

The GhostAction threat actor is evolving, and not in a good way. Beyond injecting malicious GitHub Actions workflows, they're now phishing open-source developers and delivering stealer malware disguised as a font file within compromised GitHub repositories. This is a clear escalation of their supply chain attack methods.

**My Take:** This is a classic example of threat actors adapting to defenses. When their initial methods (malicious GitHub Actions) get flagged, they pivot to more subtle social engineering and malware delivery. For us managing environments with developer teams, this means we need to be hyper-vigilant about anything downloaded from open-source repositories, especially if it's not from a trusted, verified source. Training developers on identifying suspicious files, even if they appear benign like a font, is crucial. Furthermore, implementing stringent security scans on all code dependencies and binaries pulled into our build pipelines becomes even more critical. "Trust but verify" isn't enough; it's "verify everything, trust no one" in the supply chain.

## Inherited Agents Break Governance Built for Software (Salesforce Agentforce)

This article highlights a fascinating security blind spot in Salesforce's Agentforce platform: the chaining of standard features like Email-to-Case and Web-to-Case with Flows that pass data to AI agents. What's designed as individual, secure features can, when combined, bypass governance built for traditional software and potentially expose sensitive information.

**My Take:** This resonates strongly with the complexities of managing enterprise applications. It’s a stark reminder that the sum of secure parts can sometimes create an insecure whole, especially when AI agents are introduced into the mix. For any organization using Salesforce or similar platforms with integrated AI, we need to carefully review how data flows between these seemingly innocuous features. Our security audits must extend beyond individual component configurations to evaluate the cumulative risk of chained processes, particularly those involving sensitive customer data and AI decision-making. Governance needs to catch up with the capabilities of these new agent-based systems.

## Fake Web3 Accelerator Uses npm Packages to Spread Malware and Hijack AI Agent Traffic

Another supply chain attack, this time targeting Web3 developers through malicious npm packages. A fake Web3 accelerator is luring developers with promises of free AI credits and tools, only to deliver information stealers and backdoors to both Windows and macOS systems. They're even hijacking AI agent traffic.

**My Take:** npm continues to be a fertile ground for attackers. This scam preys on the desire for "free" resources and the excitement around emerging tech like Web3 and AI. For our developer teams, the message is clear: scrutinize every package, especially from unknown or unverified sources. Use private registries for internal dependencies, implement strong package integrity checks, and educate developers about the risks of downloading packages from unvetted accelerators or platforms. The hijacking of AI agent traffic is an interesting twist, suggesting attackers are looking for ways to monetize or exploit these new compute resources.

## Unpatched Broadcom Wi-Fi Flaw Lets Attackers in Range Run Code as Root on Routers

This is a pretty serious vulnerability: an unpatched flaw in Broadcom's Wi-Fi setup software allows an attacker within radio range to run code as root on Broadcom-based routers *without* the network password or any pairing step. The researcher demonstrated this against home gateways from major Belgian ISPs.

**My Take:** "Root access, no password, just proximity" – that's a nightmare scenario for any network administrator. While the examples shown are consumer-grade routers, the prevalence of Broadcom chips in enterprise access points and other network gear means this needs immediate attention. Even if direct exploitation isn't possible on all enterprise devices, the potential for related vulnerabilities is high. This highlights the ongoing challenge of firmware security and the often slow pace of vendor patching, especially for widely distributed components. As sysadmins, we need to identify all Broadcom-based network devices in our environments and be ready to deploy patches immediately when they become available. Until then, physical security and monitoring for unusual network behavior become even more critical for devices within radio range of public spaces.

## OpenCode Console Breach May Have Exposed OpenAI, Anthropic, and Google API Keys

OpenCode, a third-party AI provider, suffered a breach of a legacy system that may have exposed users' OpenAI, Anthropic, and Google API keys saved in their Console service.

**My Take:** This is a huge red flag regarding the security of third-party services that handle sensitive credentials, especially API keys for powerful AI models. These keys are essentially equivalent to root access to those AI services and can rack up massive bills or be used for malicious purposes. For us, this underscores the absolute necessity of:
1. Minimizing the storage of API keys in third-party services wherever possible.
2. Using granular permissions for any API keys that *must* be stored externally.
3. Implementing strict monitoring for API key usage and anomalous activity.
4. Having a rapid key rotation strategy in place.
5. Thoroughly vetting the security practices of *any* third-party service that handles credentials.

This breach is a wake-up call for the AI-driven future: key management is paramount.

---

That's a wrap for this week. Stay sharp, stay vigilant, and keep those patches deployed. The threat landscape isn't getting any easier, but neither are we.

Juan Rodriguez