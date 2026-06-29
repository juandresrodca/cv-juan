---
title: "The Quantum Leap, APTs, and Supply Chain Shenanigans"
date: 2026-06-29
summary: "This week, we're diving into the future of crypto with post-quantum, persistent threats from state-sponsored APTs, supply chain vulnerabilities in open-source and browser extensions, and a critical SSH client flaw."
tags: ["post-quantum-cryptography", "apt", "supply-chain", "steganography", "browser-extensions", "open-source", "libssh2", "credentials", "weekly"]
draft: false
---

Welcome back to the weekly breakdown, folks. Another busy week in cybersecurity, and it feels like we're constantly fighting on multiple fronts – from future-proofing our crypto to dealing with current, very real state-sponsored threats and supply chain nightmares. Let's get into it.

## Why Post-Quantum Cryptography Starts With Credentials

This piece from The Hacker News highlights an impending, but very real, long-term threat: quantum computers breaking our current public-key cryptography. While no quantum machine today can smash through RSA or elliptic curve crypto, the writing is on the wall. The article emphasizes that our existing encrypted data, especially credentials, won't remain confidential forever if captured today and decrypted by a future quantum computer. This concept, often called "harvest now, decrypt later," is why post-quantum cryptography (PQC) is becoming critical.

**My take:** As sysadmins and blue teamers, this might feel like a problem for future generations, but ignoring it is a mistake. Credentials are the keys to the kingdom. We need to start understanding and planning for the transition to PQC. This means pushing vendors to support PQC algorithms and beginning to audit our own systems for cryptographic agility. It's a massive undertaking, but the sooner we start, the less painful it will be. Think about the move from SHA-1 to SHA-2 – now imagine that, but with an entirely new mathematical foundation. Proactive planning for credential management and authentication protocols is where we need to focus first.

## Gamaredon Expands Ukraine Attacks with New Malware and Cloud Service Abuse

ESET reports that the Russian APT group Gamaredon (also known as Armageddon, Primitive Bear, or UAC-0010) has continued its relentless cyber campaign against Ukraine throughout 2025, evolving its malware arsenal and abusing cloud services. They've mounted 35 distinct spear-phishing campaigns, primarily targeting new victims in the second half of the year. This group is known for its high volume, low sophistication attacks, often relying on commodity malware and social engineering.

**My take:** This is a grim reminder of the persistent and evolving threat from state-sponsored actors. From a blue team perspective, Gamaredon's tactics, while often basic, are effective due to sheer volume and persistent targeting. The emphasis on spear-phishing and cloud service abuse means we need robust email security, user training, and vigilant monitoring of cloud environments. Detecting and preventing initial access, especially via social engineering, remains paramount. Incident response playbooks need to be sharp for these kinds of ongoing campaigns.

## Microsoft Removes 119 Edge Extensions That Hid Malware in Images and Fonts

Microsoft has taken down 119 malicious Edge extensions in an operation they've dubbed "StegoAd," a clever combination of steganography and adware. These extensions hid their payloads inside seemingly ordinary image and font files and lay dormant for days before activating to steal credentials and commit ad fraud. The threat actor behind this has been active since at least 2021.

**My take:** This is a classic supply chain attack vector, but instead of open-source libraries, it's browser extensions. The use of steganography to hide the payload is particularly cunning, making detection harder at the point of upload. For us, this highlights the continued need for strict control over browser extensions in enterprise environments, thorough vetting of any approved extensions, and robust endpoint detection and response (EDR) to catch post-installation malicious behavior. User education about suspicious extensions is also vital, but let's be honest, relying solely on that isn't enough. Centralized management of browser extensions is key.

## Public PoC Released for Critical libssh2 CVE-2026-55200 Client-Side SSH Flaw

A public proof-of-concept (PoC) is now available for CVE-2026-55200, a critical vulnerability in the `libssh2` client-side SSH library. With a CVSS 4.0 score of 9.2, this flaw allows a malicious or compromised SSH server to trigger memory corruption on a connecting client, potentially leading to remote code execution without requiring any credentials or user interaction. It affects all `libssh2` releases up to and including 1.11.1.

**My take:** This is a high-priority patch. `libssh2` is a fundamental library used by countless applications that initiate SSH connections. The fact that a *malicious server* can compromise a *client* without user interaction is a major concern. We need to identify all systems that use `libssh2` (which could be a lot of Linux and macOS boxes, developer workstations, automation scripts, etc.) and ensure they are patched immediately. This vulnerability turns the tables on the usual SSH server-side threats, making diligent client-side patching crucial. Don't assume your SSH client is safe just because you're connecting to trusted servers; a compromised legitimate server or an attacker-controlled honeypot could exploit this.

## Hijacked npm and Go Packages Use VS Code Tasks to Deploy Python Infostealer

Cybersecurity researchers have uncovered two hijacked npm packages and several Go packages that are designed to deploy a Python-based information stealer on Windows, Linux, and macOS hosts. What's interesting is how they achieve execution: by leveraging VS Code tasks rather than typical npm lifecycle scripts, potentially to bypass certain security hardenings in `npm v12`.

**My take:** Another day, another supply chain attack targeting developers. This one is particularly insidious because it abuses VS Code tasks, a feature developers frequently use for automation. It's a reminder that attackers are constantly looking for new execution paths and ways to blend in with legitimate developer workflows. For blue teams, this means expanding our monitoring beyond traditional execution points. We need to be scrutinizing developer environments, package dependencies, and unusual process execution, especially around build tools and IDEs. Secure development practices and dependency scanning are non-negotiable.

## Ukraine Says Russian Intelligence Used Fake Support Texts to Steal Messaging Credentials

The Security Service of Ukraine (SSU), in collaboration with the FBI, has uncovered a long-running campaign by Russian intelligence to steal messaging credentials from government officials, military personnel, politicians, and activists in Ukraine, Europe, and the U.S. This systematic attack relied on fake support texts to trick victims into revealing their sensitive information.

**My take:** This is a classic example of sophisticated social engineering combined with state-level targeting. The use of "fake support texts" is a common phishing tactic, but when executed with precision against high-value targets, it's incredibly effective. This reiterates the importance of robust multi-factor authentication (MFA), especially hardware-backed options, and continuous security awareness training that includes specific examples of current threats. No matter how many technical controls we put in place, the human element remains a primary attack vector for well-resourced adversaries. Always verify the source, especially for password reset or account recovery messages.

That wraps up this week's dive into the cyber landscape. Stay vigilant, stay curious, and keep those patches rolling!

Cheers,

Juan Rodriguez
