---
title: "RATs, Supply Chains, and AI-Assisted Exploits: This Week in Cybersecurity"
date: 2026-09-21
summary: "This week, we're looking at a new RAT using Polygon for C2, North Korean APTs targeting developers, AI-assisted exploitation, the need for identity visibility, and a critical SolarWinds RCE."
tags: ["weekly", "threat-intelligence", "rat", "supply-chain", "identity", "vulnerability-management", "ai", "blue-team", "sysadmin"]
draft: false
heroImage: "images/blog/2026-09-21-weekly-cyber-news.svg"
---

Hey everyone, Juan here, back with the latest from the trenches of cybersecurity. It's been a busy week with some interesting developments that reinforce the need for robust blue-team practices. Let's dive in.

## ClickFix Lures Deploy ChainScript RAT Using Polygon for C2 Infrastructure

First up, we're seeing a new remote access trojan (RAT) called ChainScript being delivered via ClickFix-like lures. What's particularly interesting, and concerning, is the use of the Polygon blockchain for command-and-control (C2) infrastructure rotation. This isn't the first time we've seen blockchain used for C2, but it highlights a growing trend for threat actors to leverage decentralized platforms to make their infrastructure more resilient and harder to take down. The RAT itself is pretty standard fare, masquerading as legitimate software like Spotify or Zoom, but the C2 mechanism is a differentiator.

**My take:** As sysadmins and blue teamers, this means our network monitoring needs to evolve. Traditional IP-based C2 indicators are becoming less reliable when attackers can cycle through blockchain addresses. We need to focus more on egress traffic patterns, payload analysis, and behavioral detection. Blocking access to entire blockchain networks isn't feasible, so understanding and detecting the specific protocols and traffic associated with these RATs is crucial. Endpoint detection and response (EDR) and robust network traffic analysis (NTA) are key here to catch these guys before they get a foothold.

## Jade Sleet Linked to Indian IT Provider Breach With FLATROOF and ROOFDECK Backdoors

North Korean threat actor Jade Sleet is back in the news, this time for compromising a smaller Indian IT services provider. This reiterates a consistent theme: developers and IT service providers are prime targets for supply chain attacks. By breaching a smaller vendor, these groups gain a foothold into downstream customers, often larger organizations. The use of FLATROOF and ROOFDECK backdoors suggests a persistent and sophisticated approach once initial access is achieved.

**My take:** This is a recurring nightmare for anyone in IT. We rely heavily on third-party vendors, and their security posture directly impacts ours. For us, this means strengthening our vendor risk management. We need to ask tough questions about our vendors' security practices, their developer workstation hardening, and their incident response plans. Internally, isolating development environments, strict access controls, and continuous monitoring of developer accounts and build systems become even more critical. Assume compromise is a reality, and build your defenses around detecting and responding to lateral movement and privilege escalation, even from trusted sources.

## Claude Opus 5 Helped Researchers Take Over OpenAI Staff Accounts via Chained Flaws

This one is fascinating and a bit unnerving. Researchers used Anthropic's Claude Opus 5 – an AI – to help them chain two vulnerabilities and take over OpenAI employee accounts, eventually reaching an internal code repository. The flaws were in OpenAI's public help forum and their login system. This isn't AI *exploiting* vulnerabilities autonomously, but rather AI assisting in the *discovery and chaining* of vulnerabilities.

**My take:** This is the future of offensive security, and consequently, defensive security. AI is becoming a powerful tool for both red and blue teams. For us, it means that the window between vulnerability disclosure and potential exploitation is shrinking, exacerbated by AI's ability to quickly identify complex attack paths. We need to think about how AI can help us on the blue team side: automating vulnerability analysis, predicting attack vectors, and enhancing our threat intelligence. Patching is still fundamental, but our ability to identify and remediate complex, chained vulnerabilities needs to accelerate, perhaps even with AI assistance.

## Can You Prove a New CVE Is Exploitable Before Attackers Do? Learn How in This Webinar

This news item points to a webinar, but the core message resonates deeply with my experience. A new CVE drops, your scanner flags it as severe, but can it *actually* be exploited in your environment? Mythos-class AI is compressing the time between disclosure and working exploitation, yet many organizations still validate risk on weekly or quarterly cycles.

**My take:** This is the constant struggle: separating theoretical risk from actual, exploitable risk. Automated vulnerability scanning is a good first step, but it's not enough. We need to move towards continuous validation and threat modeling. Can we integrate dynamic application security testing (DAST) or even automated penetration testing tools to validate exploitability in our specific configurations? The "dangerous gap" they mention is real. Proactive threat hunting, understanding our unique attack surface, and being able to quickly prioritize and test fixes are paramount. Don't just rely on CVSS scores; understand the context of the vulnerability within your infrastructure.

## Identity Visibility in 2026: The Foundation of Identity Security

The emphasis on identity visibility as the foundation of identity security is spot on. Stolen and misused credentials are consistently a top initial access vector. In cloud and multi-cloud environments, managing identity has become incredibly complex.

**My take:** As a sysadmin, I can't stress this enough: identity is the new perimeter. If you don't have clear visibility into who has access to what, where they're accessing it from, and how they're using that access, you're flying blind. This means implementing robust Identity and Access Management (IAM) solutions, strong authentication (MFA everywhere!), and continuous auditing of access rights. Privilege escalation and lateral movement often start with compromised credentials. Tools that provide a holistic view of identities, entitlements, and their activity across on-prem and cloud environments are no longer optional – they are essential.

## SolarWinds Patches ARM Hard-Coded Key Flaw Enabling Unauthenticated RCE

Finally, SolarWinds has released patches for a high-severity flaw in their Access Rights Manager (ARM) product. This unauthenticated remote code execution (RCE) vulnerability (CVE-2026-28326, CVSS 8.8) affects all versions of ARM 2026.2 and prior. An RCE, especially an unauthenticated one, is about as bad as it gets.

**My take:** If you're running SolarWinds ARM, drop everything and patch *now*. Unauthenticated RCE means an attacker doesn't need any credentials to execute malicious code on your system. This is a critical entry point for an attacker to gain control. The fact that it's in an access management tool makes it even more dangerous, as it could potentially lead to widespread compromise. We've seen the devastating impact of supply chain attacks involving SolarWinds before; don't let this be another one. Prioritize this patch immediately and verify its successful application.

---

That's it for this week. Stay sharp, keep learning, and remember that our defensive posture needs to evolve just as quickly as the threats we face. Patch your systems, secure your identities, and keep an eye on those ever-innovating attackers.

Cheers,
Juan Rodriguez