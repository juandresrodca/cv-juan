---
title: "Cloud Checklists, RMM Woes, and Router Takeovers: This Week in Cybersecurity"
date: 2026-09-07
summary: "This week, we're diving into cloud security's diverse risk profiles, worm-like ScreenConnect attacks, critical RCEs in Telerik and N-able, a new session-cookie stealing malware, and unauthenticated MikroTik router hijacks."
tags: ["weekly", "cloud-security", "patch-tuesday", "rce", "malware", "supply-chain", "remote-access"]
draft: false
heroImage: "images/blog/2026-09-07-weekly-cyber-news.svg"
---

Happy Monday, everyone. Juan here, back with another weekly roundup of the cybersecurity landscape. It's been a busy few days, with some critical vulnerabilities and ongoing threats keeping us on our toes. Let's dig into what caught my eye this week.

## Your Cloud Security Checklist Doesn't Work the Way You Think It Does

Kicking things off, a new report from Intruder highlights something many of us in IT already suspect: managing security across multiple cloud providers is a mess, and each one has its own unique pitfalls. The 2026 Cloud Security Index, which analyzed data from 3,000 organizations across AWS, Azure, and Google Cloud, found that risk profiles are significantly different. What works for AWS might not apply to Azure, and vice-versa.

My take: This isn't just about different UIs or terminology; it's about fundamentally different architectural approaches to security controls and default configurations. As sysadmins, we often try to standardize as much as possible, but this data strongly suggests that a "one-size-fits-all" cloud security checklist is naive. We need tailored strategies for each cloud provider, focusing on their specific weaknesses and common misconfigurations. This means dedicating time to understand each platform's nuances, not just ticking boxes. For blue teams, it reinforces the need for specialized training and tooling for each cloud environment you operate in.

## Rogue ScreenConnect Clients Spread Four-Stage VBScript Chain to Newly Connected Hosts

Huntress researchers have detailed some alarming worm-like activity leveraging ConnectWise ScreenConnect. Attackers are abusing ScreenConnect clients to push a malicious VBScript payload to newly connected systems. They've observed diverse initial access methods, including tech-support scams, phishing with MSI installers, and fake updates.

My take: This is a classic supply chain attack vector, albeit one that leverages legitimate remote access software. ScreenConnect, like any RMM tool, is a powerful double-edged sword. In the wrong hands, or when compromised, it provides an attacker with deep access into your network. For sysadmins, this underscores the critical importance of least privilege access for RMM agents and rigorous monitoring of their activity. Patching is essential, but so is understanding *how* these tools are being used. Any unusual script execution originating from an RMM client should set off alarm bells immediately. This is also a good reminder to continually educate users about social engineering tactics like tech-support scams and phishing.

## Telerik UI Padding-Oracle Bug Chained to Unauthenticated RCE — Public Exploit Released

TantoSec has released a proof-of-concept exploit for a padding oracle vulnerability in Telerik UI for ASP.NET AJAX, which can lead to unauthenticated remote code execution. The good news is that this only affects applications in a specific non-default configuration, and Progress (the vendor) patched the chain back in July. No in-the-wild exploitation has been confirmed yet.

My take: While patched, and impacting a specific configuration, the release of a public exploit for an unauthenticated RCE is always a concern. If you're running Telerik UI for ASP.NET AJAX, double-check your patching status immediately. Even if you're not using the specific non-default configuration, it's a good reminder to review all third-party components in your applications. Developers often pull in libraries without a full understanding of their security implications. For us on the blue team, it's about making sure developers are aware of these risks and that patching cycles for application dependencies are just as robust as for OS and infrastructure.

## N-able Issues Fourth N-central Hotfix in Five Weeks for Unauthenticated RCE Flaw

N-able has released its fourth hotfix in just five weeks for an unauthenticated RCE flaw in its N-central RMM platform. This means any on-premises N-central build below 2026.3.1.14, including servers updated to Hotfix 3 a day earlier, needs Hotfix 4. The incident notice claims in-the-wild exploitation, though the release notes state it's unconfirmed.

My take: Four hotfixes in five weeks for an RMM platform is a serious red flag. This situation highlights the inherent risks of RMM tools, which, by their very nature, are designed for deep network access. An unauthenticated RCE on such a platform is about as bad as it gets for network-facing systems. If you're an N-able N-central customer, drop everything and apply this hotfix. The conflicting information about in-the-wild exploitation further emphasizes the urgency. Assume it's being exploited and patch immediately. Beyond patching, reviewing your N-central security posture, including network segmentation and access controls, is crucial. This is a prime example of why robust vendor security practices and transparent communication are paramount for critical infrastructure tools.

## JSCeal Malware Can Bypass Google Authentication Using Stolen Session Cookies

Check Point Research has unveiled JSCeal, a sophisticated compiled V8 JavaScript (JSC) malware. This malware boasts credential harvesting, surveillance, and traffic-interception capabilities, and critically, it can bypass Google authentication using stolen session cookies. It's heavily obfuscated, making detection and analysis challenging.

My take: Session cookie theft is a persistent threat, and JSCeal's ability to bypass Google authentication is particularly concerning given how many organizations rely on Google Workspace or utilize Google accounts for various services. This malware underscores the need for robust endpoint detection and response (EDR) solutions that can identify malicious behavior even from highly obfuscated code. For users, multi-factor authentication (MFA) is still your best defense, but remember that some MFA implementations can be bypassed if the session cookie itself is compromised. This highlights the importance of strong account hygiene and being wary of phishing attempts that aim to steal your active sessions. Regular review of active sessions in your Google accounts is also a good habit.

## Attackers Hijack MikroTik Routers Through Internet-Exposed SSH Without Authentication

CERT Polska has issued a warning about attackers exploiting MikroTik routers with internet-exposed SSH services to gain full administrative control without authentication. Attacks have been observed since at least September 2nd.

My take: This is a straightforward, yet incredibly impactful, vulnerability. Exposing SSH to the internet without proper authentication is a fundamental security no-no. While the warning doesn't specify a particular CVE, the fact that it's unauthenticated access is terrifying. If you manage MikroTik routers, immediately review your firewall rules and ensure that SSH (port 22) is *not* exposed to the internet. If remote management is required, use a VPN or restrict access to specific, trusted IP addresses. Also, ensure your MikroTik devices are patched to the latest firmware. This isn't just about the router; it's about the entire network segment it protects. A compromised router is a gateway to everything behind it.

That wraps up this week's dive into the cyber trenches. Stay vigilant, patch diligently, and question everything. Your network's security depends on it.

Juan Rodriguez
IT Systems Administrator & Cybersecurity Specialist
Intel Ireland