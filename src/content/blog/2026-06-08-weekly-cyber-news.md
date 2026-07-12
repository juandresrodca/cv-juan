---
title: "Weekly Rundown: Supply Chain Delays, Physical Intrusions, and Smart TV Proxies"
date: 2026-06-08
summary: "This week, we're looking at China-nexus espionage on Linux, UNC3753's blended vishing and physical intrusions, VS Code's extension update delay, ChatGPT's new Lockdown Mode, smart TVs turned into web-scraping proxies, and a SolarWinds Serv-U DoS flaw added to CISA's KEV catalog."
tags: ["weekly", "cyber-espionage", "linux", "supply-chain", "vishing", "physical-security", "ai", "privacy", "vulnerability", "cisa"]
draft: false
---

Alright team, let's dive into another week of cybersecurity updates. We've got a mixed bag today, from state-sponsored APTs hitting Linux to some rather creative, and concerning, methods of data exfiltration and proxy networks.

## VerdantBamboo Deploys BSD Variant of BRICKSTORM on Linux Appliances

First up, we're seeing reports from Volexity, backed by Microsoft and others, about the China-nexus cyber espionage group VerdantBamboo (aka Clay Typhoon) deploying a BSD variant of their BRICKSTORM backdoor on Linux systems. They're also using two other malware families, PLENET (GRIMBOLT) and AGENTPSD. This isn't just targeting standard Linux servers; they're specifically going after Linux appliances.

**My Take:** This is a clear reminder that Linux isn't immune. In fact, many organizations often overlook the security posture of their Linux-based appliances, assuming they're inherently more secure or less targeted than Windows. This is a dangerous assumption. As sysadmins, we need to ensure our patching cycles for Linux systems, including embedded and appliance-based ones, are as rigorous as for any other critical infrastructure. We also need to be looking at endpoint detection and response (EDR) solutions that support Linux. The shift to a BSD variant shows their adaptability; we need to be just as adaptable in our defense.

## UNC3753 Used Vishing and Physical Intrusions in U.S. Data Theft Extortion Campaign

Google Mandiant and GTIG have disclosed details on UNC3753, a financially motivated threat actor that has been targeting professional, legal, and financial services in the U.S. Their campaign, running from January to May 2026, involves a nasty blend of vishing and actual physical intrusions for data theft and extortion.

**My Take:** This is where things get really interesting and frankly, a bit chilling. We often focus heavily on digital defenses, firewalls, AV, MFA – all critical. But when threat actors blend vishing (social engineering over the phone) with physical intrusions, it highlights a gap many organizations have: physical security awareness and incident response. Training users to spot vishing attempts is crucial, but also ensuring our physical perimeters are robust, and that staff know how to report suspicious activity, both online and off, is paramount. This isn't just about patching software; it's about patching human and physical vulnerabilities.

## VS Code Adds 2-Hour Extension Auto-Update Delay to Limit Supply Chain Attacks

Microsoft announced that Visual Studio Code (VS Code) will now implement a two-hour delay before extensions automatically update to a new version. This is a direct response to software supply chain threats, giving a small window to catch potentially malicious updates.

**My Take:** As someone who uses VS Code daily, this is a sensible move. Supply chain attacks, especially through development tools and their ecosystems, are a growing concern. While two hours isn't a silver bullet, it provides a buffer. For blue teams, this means keeping an eye on public advisories and security feeds that might flag malicious extensions within that window. For developers, it reinforces the need to scrutinize what extensions they install and to understand the implications of automatic updates. It's a small step, but a positive one towards better supply chain security.

## New ChatGPT Lockdown Mode Limits Tools That Could Enable Data Exfiltration

OpenAI is rolling out a new "Lockdown Mode" for ChatGPT personal accounts. This feature aims to reduce the risk of data exfiltration, particularly from prompt injection attacks, by limiting tools that could enable such actions. It's designed for users and organizations handling sensitive data.

**My Take:** This is a welcome development. The increasing use of AI tools like ChatGPT for work, even personal accounts, means sensitive data can inadvertently (or maliciously) find its way into these models. Prompt injection is a real threat, and limiting capabilities that could be exploited for exfiltration is a good defensive measure. For organizations, it's another reason to establish clear policies around AI tool usage, especially with sensitive information. Even with "Lockdown Mode," the best defense is still user awareness and careful handling of data.

## Free Apps Are Quietly Turning Smart TVs Into Web-Scraping Proxies for AI

A researcher has exposed how free consumer apps are embedding Bright Data's SDK, effectively turning devices like always-on smart TVs into exit nodes for a massive residential proxy network. This network is heavily marketed to the AI industry for web scraping.

**My Take:** This is a stark reminder of the "free lunch" problem. If you're not paying for a product, *you* are the product. Smart TVs, often seen as benign entertainment devices, are now being weaponized as part of a distributed data collection network. For us in IT, it highlights the need for network segmentation, especially for IoT and consumer devices on enterprise networks (if they're allowed at all). For personal use, it’s a privacy nightmare. We need to be more scrutinizing of what "free" apps we install and understand their underlying business models. This isn't just about performance; it's about who controls your network traffic.

## CISA Adds Actively Exploited SolarWinds Serv-U DoS Flaw to KEV Catalog

CISA has added a high-severity denial-of-service (DoS) flaw in SolarWinds Serv-U (CVE-2026-28318, CVSS: 7.5) to its Known Exploited Vulnerabilities (KEV) catalog. This means the vulnerability is actively being exploited in the wild.

**My Take:** SolarWinds again. While not a supply chain compromise like their past mega-incident, any actively exploited vulnerability, especially one that can cause a DoS, is a critical concern. If you're running Serv-U, patch it immediately. For those of us on blue teams, CISA's KEV catalog should be a daily check. Any item added to that list demands immediate attention and a rapid response. Don't let your file transfer services be the weak link.

That wraps up this week's dive into the latest cybersecurity news. Stay vigilant, patch everything, and keep an eye on both your digital and physical perimeters.

Cheers,

Juan Rodriguez