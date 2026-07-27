---
title: "The Week in Cyber: From Telegram C2 to Exploding JSON and Malvertising Madness"
date: 2026-07-27
summary: "This week, we're diving into Telegram C2, Dependabot's new cooldown, browser-built malware, critical Fastjson and GitLab RCEs, and evolving real-time phishing attacks."
tags: ["weekly", "threat-intelligence", "supply-chain", "malware", "vulnerability", "phishing"]
draft: false
heroImage: "images/blog/2026-07-27-weekly-cyber-news.svg"
---

Hey everyone, Juan here, back with another rundown of the latest in cybersecurity. It's been a busy week, highlighting everything from nation-state activity to new twists on old attack vectors and critical vulnerabilities that need your immediate attention. Let's dig in.

## TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments

Kicking things off, we've got Zscaler ThreatLabz flagging a new threat actor, likely East Asian in origin, using Telegram for command and control (C2) in attacks targeting government entities in the Middle East. They've deployed new malware families: TELESHIM, MIXEDKEY, and BINDCLOAK.

From a sysadmin perspective, this is a classic example of threat actors leveraging legitimate, widely-used services for their operations. Telegram's popularity and encryption make it an attractive C2 channel. For us blue teamers, this means focusing on network traffic analysis, looking for unusual Telegram API calls from internal hosts, and strengthening endpoint detection. Application whitelisting for executables and regular threat hunting for these specific malware families are crucial. It's a reminder that relying solely on blocking known malicious IPs isn't enough; we need to understand the behavior.

## GitHub Adds 3-Day Dependabot Cooldown to Limit Poisoned Package Adoption

Good news for the software supply chain: GitHub has implemented a three-day cooldown for Dependabot. This means Dependabot will now wait at least three days after a new release before opening a pull request to update dependencies. This helps mitigate the risk of "poisoned package" attacks, where malicious versions are quickly pushed out.

This is a welcome development. As a sysadmin, the thought of an automated system instantly pulling in a malicious dependency is terrifying. This cooldown gives security teams, and even the community, a small window to identify and flag bad packages before they're widely adopted. While not a silver bullet, it adds a much-needed layer of defense. It emphasizes the importance of secure software development practices and supply chain security in general. Make sure your `dependabot.yml` is configured appropriately for your project's risk tolerance.

## Malvertising Sends Malware in Pieces, Then Makes the Browser Build the Executable

This one is truly wild: a malvertising operation called SourTrade is having victim browsers assemble the final Windows executable from pieces, using a legitimate Bun runtime. They're impersonating brands like TradingView and Solana to target retail traders.

This is a brilliant, albeit concerning, evasion technique. By delivering malware in fragments and having the browser construct it, they bypass many traditional network and endpoint security controls that look for complete malicious files. From my seat, this highlights the need for advanced endpoint detection and response (EDR) solutions that can analyze process behavior and identify suspicious activity even when the initial download seems benign. Also, strengthening browser security settings, blocking untrusted ads, and user education against clicking suspicious links are more critical than ever. It's a cat-and-mouse game, and they just added a new twist.

## Fastjson 1.x RCE Vulnerability Targeted in Attacks With No Patch Available

Here's a critical one you need to hear about: a remote code execution (RCE) vulnerability in Fastjson, Alibaba's JSON library for Java (CVE-2026-16723, CVSS 9.0), is being actively exploited. The kicker? There's no patch available for Fastjson 1.x. Attackers can execute code without authentication in affected Spring Boot applications.

If you're running Fastjson 1.x, you are in a high-risk situation. The advice from the security community is to upgrade to Fastjson 2.x immediately, as this version has a different architecture that isn't vulnerable to this specific attack. If upgrading isn't an immediate option, explore any available workarounds, like implementing strict allow-lists for deserialization or adding network-level filtering for malicious JSON payloads. This is a five-alarm fire for any Java-heavy environments. Patching or migrating *now* is your top priority.

## Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git

Speaking of RCEs, a researcher has published a proof-of-concept (PoC) for a GitLab RCE vulnerability that GitLab patched six weeks ago. The exploit allows any authenticated user who can push to a project to run commands as the `git` user on self-managed 18.11.3 servers that haven't been updated.

This is a textbook example of why timely patching is absolutely non-negotiable. GitLab pushed the patch, but the existence of a public PoC means that any unpatched instance is now a sitting duck for a wide range of attackers, not just sophisticated ones. If you're managing a self-hosted GitLab instance, check your version immediately and apply the latest updates. Regularly audit your user permissions and monitor for unusual activity from authenticated users. This is a reminder that even "minor" updates can contain critical security fixes.

## CTM360 Research Reveals How Insurance Phishing Has Evolved Into Real-Time Account Hijacking

Finally, we're seeing an evolution in phishing. CTM360's research indicates that insurance-focused phishing campaigns are moving away from simply harvesting credentials for later use. Instead, they're employing a more immediate, real-time account hijacking approach.

This is a significant shift. Attackers aren't just collecting; they're *acting* in real-time. This can bypass some multi-factor authentication (MFA) methods if the victim is tricked into providing the second factor during the live interaction. As a sysadmin, this means our defenses need to be equally real-time. Strengthen MFA with FIDO2 or hardware tokens, implement robust behavioral analytics for login attempts, and educate users about the dangers of *any* unsolicited requests for credentials, even if they appear to be part of a "live" interaction. This new approach demands a more dynamic and vigilant response.

That's the wrap-up for this week. Stay vigilant, patch everything, and keep those eyes peeled for anything out of the ordinary. Security is a continuous journey, not a destination.

Juan Rodriguez