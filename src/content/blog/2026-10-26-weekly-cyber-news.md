---
title: "Wasmtime Flaws, Token Replay, and AI Agents: This Week in Cybersecurity"
date: 2026-10-26
summary: This week, we're diving into critical sandbox escapes in Wasmtime, Microsoft 365 token-replay attacks, new Android spyware, GitHub token theft, and attempts to trick AI coding agents.
tags: ["weekly", "vulnerability", "cloud-security", "mobile-security", "identity", "ai-security"]
draft: false
heroImage: "images/blog/2026-10-26-weekly-cyber-news.svg"
---

Alright team, let's cut through the noise and get straight to what matters this week. We've got a mixed bag of threats, from low-level sandbox escapes to the ongoing saga of credential theft and some interesting developments in the world of AI security.

## Two Critical Wasmtime Flaws Could Let Malicious WebAssembly Modules Escape Sandboxes

This is a big one for anyone leveraging WebAssembly (Wasm) in their infrastructure. Two critical vulnerabilities have been found in Wasmtime, a prominent WebAssembly runtime. These flaws could allow a malicious Wasm module to break out of its intended sandbox. One of these affects only ARM64 systems, but the other is more general. Attackers would need to get a vulnerable Wasmtime build to compile their module.

My take: Sandbox escapes are the nightmare scenario for any isolation mechanism. If you're using Wasmtime, especially in environments where untrusted code might be executed, you need to ensure you're on the absolute latest patched versions. This highlights the ongoing challenge of securing environments that rely on executing external code; constant vigilance and immediate patching are non-negotiable.

## Between alerts: What Attackers Do in the Spaces Ordinary Detection Misses

This article hits close to home for any SOC team. We all drown in alerts, and the vast majority don't give the full picture of an attack's progression or origin. The piece rightly points out that network data, particularly from NDR platforms, is crucial for stitching together individual alerts into a coherent timeline.

My take: This is the essence of blue team operations. Alerts are just data points. Our job is to connect those dots. Relying solely on endpoint logs or individual system alerts leaves huge blind spots. A robust NDR solution, integrated with SIEM/SOAR, can provide that critical context by showing network flows and command-and-control communication that other systems might miss. It's about seeing the forest, not just the trees.

## uCreator Android Spyware Can Steal Telegram 2FA Passwords and Clone WeChat Accounts

Another day, another sophisticated mobile spyware kit. uCreator is a rentable Android spyware that goes after Telegram and WeChat accounts. It achieves this by embedding its malicious code directly into tampered versions of the legitimate apps, which are then distributed outside official app stores, or by getting users to run WeChat within the kit makers' own container app. It can even steal Telegram 2FA passcodes.

My take: This is a classic supply chain attack on mobile. Users downloading apps from unofficial sources are asking for trouble. For us sysadmins, the key takeaway is user education: never download apps from untrusted sources. For enterprise BYOD policies, ensuring devices are locked down against sideloading and using mobile threat defense (MTD) solutions becomes critical. The ability to grab 2FA codes is particularly alarming, effectively bypassing a core security control.

## Microsoft 365 Token-Replay Attacks Compromise 97 Accounts at 79 Organizations

This is a serious campaign leveraging Adversary-in-the-Middle (AiTM) techniques to capture and replay stolen Microsoft 365 sign-in tokens. Huntress observed 97 accounts compromised across 79 organizations between July and September 2026. This isn't a new technique, but its continued success shows how effective it remains.

My take: Token replay attacks are incredibly dangerous because they bypass MFA by directly using an active session token. This means even with strong MFA enabled, users can still be compromised. The best defense here is FIDO2 hardware keys, which are resistant to phishing and token theft, and implementing Conditional Access policies that check for unusual login locations or device states. Educating users about phishing is also crucial, as AiTM often starts with a convincing phishing page.

## Gheist Uses Stolen GitHub Tokens to Steal Private Repository Secrets via Actions Logs

Developers, pay attention. A campaign dubbed Gheist is actively using stolen GitHub tokens to inject malicious workflows into private repositories. These workflows are designed to print repository secrets directly into GitHub Actions logs, which the attackers then exfiltrate before deleting the log entries to cover their tracks. This is affecting private repos and GitHub Enterprise environments.

My take: This is a targeted attack on developer environments and CI/CD pipelines. Stolen GitHub tokens are gold for attackers. We need to implement strict token management policies: short-lived tokens, granular permissions, and regular rotation. Integrating secret scanning tools into CI/CD and monitoring GitHub Actions logs for anomalous activity are also essential. Never hardcode secrets in repositories, and ensure strong authentication for all developer accounts.

## Malicious File in Downloads Folder Tries to Trick AI Coding Agent Into Installing Malware

This is a glimpse into the future of AI security threats. A malicious instruction file placed in a developer's Downloads folder attempted to trick an AI coding agent into installing a known-malicious npm package. The security firm Forever Security caught and stopped the attempt, but the file's origin is unknown.

My take: This is a concerning development. As AI coding assistants become more ubiquitous, they represent a new attack surface. This "prompt injection" or "data poisoning" against an AI agent is a novel way to bypass human scrutiny. We need to treat AI agents like any other user account or system, with appropriate sandboxing, input validation, and security monitoring. Developers should be highly suspicious of any unexpected files, especially in common directories like "Downloads." This is a new frontier in defense.

That's the rundown for this week. Stay sharp, patch diligently, educate your users, and keep an eye on these evolving threats, especially as AI integrates further into our daily workflows.

Juan Rodriguez
IT Systems Administrator & Cybersecurity Specialist
Intel Ireland