---
title: "Critical ICS Flaws, Resurgent Worms, and Sneaky AI Agents"
date: 2026-11-16
summary: "This week, we're looking at unpatched critical vulnerabilities in industrial control systems, a worm that came back from the dead, novel cryptomining tactics, AI agent attacks, Log4Shell's lasting impact, and a massive privacy fine for Meta."
tags: ["ics-scada", "malware", "cryptomining", "ai-security", "log4shell", "privacy", "weekly"]
draft: false
heroImage: "images/blog/2026-11-16-weekly-cyber-news.svg"
---

Another week, another batch of cybersecurity news. It's Monday, November 16th, and we've got some serious stuff to unpack today, from critical ICS vulnerabilities to AI agents turning on us. Let's dive in.

## Six Unpatched Danfoss Refrigeration Controller Flaws Could Allow Remote Takeover Without Login

This is a big one for anyone dealing with industrial control systems (ICS) or building management. Six unpatched flaws in Danfoss AK-SM800A refrigeration controllers could allow a remote attacker to take over a controller without authentication. Even worse, the latest firmware doesn't fix it, and there's no patch available right now. Government agencies in Belgium, Ireland (hey, that's home!), and Germany are already telling operators to take action.

**My take:** This is exactly why we need to treat OT/ICS environments with extreme caution. The "air gap" is often a myth, and when these systems are exposed, the impact can be severe. If you're running these Danfoss controllers, you need to be actively looking at network segmentation, robust firewall rules, and ideally, completely isolating them from internet access. Until a patch is available, it's about mitigating the risk through architectural controls. This is a blue teamer's nightmare: critical, unpatched vulnerabilities in systems that often can't be taken offline easily. Keep a close eye on your network traffic for any unusual activity targeting these devices.

## Retadup Worm Resurfaces 7 Years After Takedown to Spread CoffeeLoader Malware

Remember Retadup? It was a nasty worm that spread rapidly before a coordinated takedown. Well, it's back, seven years later, and now it's spreading a new payload: CoffeeLoader malware. Kaspersky's analysis shows it dropping a patched 7z.dll file into temporary directories and running it via rundll32.exe.

**My take:** This is a classic example of "what's old is new again" in malware. Attackers are constantly recycling and refining old code. The fact that Retadup, a worm thought to be neutralized, has resurfaced underscores the need for continuous vigilance. For sysadmins, this means ensuring your endpoint detection and response (EDR) solutions are up-to-date and configured to detect both known and novel malware behaviors. Pay attention to execution via `rundll32.exe` and unusual file drops, especially in temporary directories. User awareness training around suspicious attachments or links is also crucial, as worms often rely on initial user interaction.

## SANSAR Linux Cryptomining Malware Uses Modified NVIDIA Library to Hide GPU Activity

A financially motivated group, REF3364, is behind a new Linux cryptomining operation using a toolkit called SANSAR. What makes this interesting is its use of a modified NVIDIA library to tamper with GPU workload readings, making it harder to detect the mining activity. It's a Rust-based orchestrator, receiving commands over TOR.

**My take:** This is a clever tactic. Cryptominers are always trying to stay stealthy, and modifying library calls to spoof system telemetry is a sophisticated approach. For Linux administrators, this means you can't just rely on standard `nvidia-smi` output to detect unauthorized GPU usage. You need deeper monitoring – perhaps looking at power consumption changes, unexpected network connections (especially to TOR relays), or even anomaly detection on CPU/GPU utilization trends that bypass standard reporting. Inspecting dynamically loaded libraries and checking their integrity could also become a necessary, albeit complex, step.

## Amazon Uncovers AI Agent Campaign Targeting LiteLLM, Dify, and Other Apps for API Keys

This is a fascinating and somewhat unsettling development. Amazon's threat intelligence team used decoy servers to uncover an AI agent campaign that's hunting for weak spots in internet-exposed AI applications like LiteLLM, One API, and Dify. These attacker-controlled AI agents are essentially autonomously scanning for and stealing AI provider keys, then using those stolen keys to power their search for *more* keys. It's a self-propagating reconnaissance and exploitation loop.

**My take:** The rise of AI agents brings new attack vectors. This campaign highlights the critical importance of securing API keys for AI services. Treat them like any other sensitive credential. For developers and sysadmins managing AI applications, this means implementing robust secrets management, ensuring API keys are never hardcoded or exposed in public repositories, and reviewing access controls for AI services. Continuous monitoring of API key usage for anomalies and rate limiting is also vital. The idea of AI agents autonomously hunting for vulnerabilities feels like a page out of a sci-fi novel, but it's here, and we need to adapt our defenses.

## BO Team Exploits Log4Shell in VMware vCenter, Compromises Russian Firm's Code-Signing Server

Log4Shell just keeps giving, doesn't it? An investigation into a Russian software developer's network revealed a months-long compromise, attributed to "BO Team," leveraging Log4Shell in VMware vCenter to gain access to their development infrastructure and, crucially, their software code-signing server.

**My take:** This is a stark reminder of Log4Shell's enduring impact. Despite patches being available for ages, vulnerable instances persist, especially in complex enterprise environments. The compromise of a code-signing server is particularly dangerous, as it allows attackers to sign malicious software with legitimate certificates, making it much harder for security tools to detect. If you haven't already, run a comprehensive audit for Log4Shell vulnerabilities across ALL your infrastructure, especially critical components like vCenter. Patching is paramount, but also consider network segmentation for your code-signing infrastructure and robust monitoring for any unauthorized access or signing requests. Assume compromise if you found Log4Shell in such a critical system and do a thorough forensic analysis.

## Italy Fines Meta €805 Million Over Facebook's Android Gallery Access Without Explicit Consent

Meta just got hit with another massive fine, this time €805 million from Italy's data protection authority (Garante). The issue? Facebook for Android was accessing users' photos, videos, and related metadata from their phone galleries without explicit consent, via a feature suggesting photos to post that was enabled by default.

**My take:** This is a big win for user privacy and a clear message to tech giants. As sysadmins and cybersecurity professionals, even if we're not directly involved in app development or privacy policy, these kinds of rulings impact how we handle user data. It underscores the importance of data governance, clear consent mechanisms, and understanding exactly what data your systems are collecting and why. From a blue team perspective, this serves as a reminder that accidental or poorly handled data collection can lead to massive financial and reputational damage. It's not just about protecting data from external threats; it's also about ensuring internal processes comply with increasingly stringent privacy regulations.

That's a wrap for this week. Stay vigilant, patch your systems, and keep an eye on those emerging AI threats. The landscape is always shifting, and we need to adapt quickly.

Juan Rodriguez, CISSP, OSCP Candidate.