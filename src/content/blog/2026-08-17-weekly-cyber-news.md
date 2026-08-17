---
title: "PoCs, Zero-Days, and Sneaky VPNs: This Week's Cybersecurity Rundown"
date: 2026-08-17
summary: "This week, we're diving into SharePoint auth bypasses, Lazarus Group's Windows zero-day exploitation, risky Chrome VPN extensions, AI API flaws, and the state of enterprise defenses."
tags: ["weekly", "vulnerability", "zeroday", "lazarus", "sharepoint", "ai", "privacy", "blue-team", "sysadmin"]
draft: false
heroImage: "images/blog/2026-08-17-weekly-cyber-news.svg"
---

Hola a todos, Juan here with your weekly dose of cybersecurity updates. It's been another busy week, with everything from critical vulnerabilities getting exploited post-PoC release to sophisticated state-sponsored groups leveraging zero-days. Let's dig in.

## Who's Tracking You? DecryptAds to the Rescue

First up, a neat tool for anyone concerned about privacy. Krebs on Security reported on a new, free service called DecryptAds. This service scrapes and compiles information about who's tracking you across websites and mobile apps, making previously obscure data more accessible.

**My Take:** From a blue-team perspective, this is a fantastic resource for understanding the attack surface related to user data. While not directly a defensive security tool, it helps us understand privacy risks and potentially identify data exfiltration vectors that might be leveraged by less obvious means. For a sysadmin, it's also a great way to show users *why* we enforce certain browser security policies or recommend specific privacy tools. Transparency is key, and DecryptAds provides just that.

## Attackers Exploit SharePoint Authentication Bypass After Public PoC Release

The Hacker News highlighted a concerning development: threat actors are actively exploiting CVE-2026-55040, a critical authentication bypass vulnerability in Microsoft SharePoint. This started happening shortly after a proof-of-concept (PoC) code was publicly released. The vulnerability, with a CVSS score of 9.1, was part of Microsoft's July 2026 Patch Tuesday.

**My Take:** This is a classic example of why timely patching is absolutely critical, especially for publicly exposed services like SharePoint. Once a PoC is out, the race is on. If you're running SharePoint, you should have patched this immediately with the July updates. If not, consider yourselves in the red zone. This bypass allows attackers to circumvent authentication, potentially leading to unauthorized access to sensitive data and critical system functions. As a sysadmin, this is the stuff that gives you sleepless nights. Verify your patching cycles, ensure all SharePoint instances are updated, and scan for any signs of compromise if you were late to the patch party.

## Lazarus Exploits Windows Zero-Day to Gain SYSTEM Access and Deploy Backdoor

The notorious North Korean Lazarus Group is at it again, as reported by The Hacker News. They've been attributed to exploiting a newly patched zero-day flaw in Microsoft Windows. This exploit, part of their "Operation Dream Job," targets defense and aerospace companies across France, Germany, Brazil, and India, delivering a previously unseen backdoor with SYSTEM-level access.

**My Take:** This is serious. Lazarus Group is a highly sophisticated state-sponsored actor, and their use of a Windows zero-day to achieve SYSTEM access is a prime example of advanced persistent threats (APTs). The "Dream Job" campaign, which uses social engineering to entice targets with fake job offers, is highly effective. For blue teams and sysadmins, this underscores the importance of a multi-layered defense. Patching immediately when zero-days are disclosed is paramount, but so is robust endpoint detection and response (EDR), strong email security to block phishing attempts, and continuous user awareness training. Assuming your users will never click a malicious link is a dangerous gamble. And with SYSTEM access, the damage potential is catastrophic.

## 737 Chrome VPN Extensions Caught Routing Traffic Through Proxies. Check If You Have One

In another alarming report from The Hacker News, a staggering 737 free VPN and proxy extensions for Chrome have been found to be malicious. These extensions, primarily targeting Russian-speaking users, intercept browser traffic and route it through a proxy infrastructure. They racked up over 75,000 installs and many impersonated legitimate services.

**My Take:** This highlights a massive blind spot for many organizations and individuals: browser extensions. While not always directly targeting corporate networks, these malicious extensions can compromise user data, session tokens, and credentials, creating a backdoor into enterprise systems. For sysadmins, this is a clear argument for strict control over browser extensions in corporate environments. Whitelisting approved extensions or using enterprise browser management tools is crucial. Educating users about the dangers of free VPN extensions and encouraging them to stick to reputable, paid services is also vital for personal devices that might still access corporate resources.

## OpenAI, Anthropic, Google API Flaw Let Weaker AI Models Decode Stronger Models' Reasoning

The Hacker News also covered a fascinating AI security flaw. Researchers discovered a weakness in the way OpenAI, Anthropic, and Google handle hidden AI reasoning between API calls. This flaw allowed weaker AI models to decode stronger models' internal reasoning and even recover sensitive data like API keys and passwords from session logs.

**My Take:** As AI integration becomes ubiquitous, understanding its security implications is paramount. This specific flaw, affecting encrypted reasoning objects, is a subtle but potent side-channel attack. For any organization building with or heavily relying on these AI APIs, this means a thorough review of how they handle sensitive data passed to and from these services. Even encrypted data isn't safe if the reasoning process itself can be reverse-engineered. This emphasizes the need for continuous security auditing of AI systems and their underlying APIs, treating them with the same rigor as any other critical infrastructure component.

## Enterprise Defenses Recovered at the Edge and Collapsed Inside

Finally, The Hacker News reported on Picus Labs' Blue Report 2026, which paints an interesting picture of enterprise defenses. While defenses are stronger at the edge, internal network protection is faltering, with attackers winning by "making no noise." The report measured over 338 million attack simulations.

**My Take:** This report resonates deeply with my experience. We've poured resources into perimeter defenses – firewalls, IDS/IPS, secure gateways – and they're largely effective against the "noisy" attacks. However, once an attacker breaches that initial perimeter, lateral movement and internal compromise become far too easy if internal defenses are neglected. This is a strong argument for zero-trust architectures, robust internal segmentation, host-based firewalls, and comprehensive internal monitoring. We need to shift from an "assume trust, verify perimeter" mindset to an "assume breach, verify everything" approach. Silent attacks are the most dangerous, and effective detection inside the network is now more critical than ever.

That's it for this week's roundup. Stay vigilant, patch your systems, and keep those internal defenses strong.

Juan Rodriguez