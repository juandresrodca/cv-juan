---
title: "The Week of Forgotten Assumptions and Rogue AI"
date: 2026-09-28
summary: "This week's cybersecurity landscape was dominated by the exploitation of forgotten attack surfaces, critical Citrix flaws, and the emerging threat of ungoverned AI agents going rogue."
tags: ["weekly", "threat-intelligence", "vulnerabilities", "cloud-security", "ai-security", "botnet", "citrix", "zero-day"]
draft: false
heroImage: "images/blog/2026-09-28-weekly-cyber-news.svg"
---

Alright team, let's dive into another week of patching, monitoring, and adapting. This past week felt like a masterclass in how quickly forgotten assumptions can turn into active attack surfaces, coupled with a healthy dose of AI-related headaches.

## Weekly Recap: Forgotten Assumptions and Live Attack Surfaces

The general weekly recap from The Hacker News really hit home. The story of a harmless placeholder domain showing up in 1,700 repositories, only for someone to register it and start serving malicious lures, is a perfect illustration of how easily seemingly inert digital debris can become a live threat. It's a reminder that every piece of text, every forgotten config, every "will get to it later" item, is a potential attack vector if not properly managed or retired.

**My Take:** As sysadmins, we're constantly juggling old systems, legacy configurations, and the rapid pace of new deployments. This highlights the critical need for robust asset management and continuous auditing. What's that old test account nobody uses anymore? Is that dev environment really isolated? This kind of "passive" attack surface often flies under the radar because it's not a shiny new vulnerability. We need to be proactive about cleaning up and maintaining our digital real estate, not just patching the latest CVEs.

## CISA and Citrix: Critical NetScaler Flaws Under Global Exploitation

CISA adding two critical Citrix NetScaler ADC and Gateway flaws to its Known Exploited Vulnerabilities (KEV) catalog is a huge red flag. With a CVSS score of 9.5 for CVE-2026-88771, an improper input validation vulnerability allowing unauthenticated attackers, these aren't minor issues. Citrix has confirmed active exploitation and released fixes for these and six other flaws. One of the two critical vulnerabilities affects *every* deployment on an affected version, even default configurations.

**My Take:** If you're running Citrix NetScaler ADC or Gateway, you should have already been on this. This isn't just a "patch when you get a chance" situation; these are actively exploited zero-days. For blue teams, this means immediate patching and diligent log analysis for any signs of compromise. Check your ingress/egress logs, look for unusual activity, and make sure your Citrix instances are segmented appropriately. This also underscores the importance of staying current with vendor security advisories and having a robust emergency patching procedure in place.

## JADEPUFFER Leverages Compromised Service Principals in Azure

The threat actor JADEPUFFER (tracked by Microsoft as Storm-3168) has demonstrated an evolution in their tradecraft by using compromised service principals to orchestrate destructive actions within Microsoft Azure environments. The attack lasted about 18 hours in early June, allowing for significant damage.

**My Take:** This is a classic example of lateral movement and privilege escalation in cloud environments. Service principals are powerful, essentially non-human accounts that applications and services use to interact with Azure resources. If these are compromised, an attacker gains a highly privileged foothold. This incident screams for strict least-privilege principles, regular auditing of service principal permissions, and robust monitoring of activity originating from these accounts. MFA for service principals might sound complex, but alternative authentication methods and continuous access evaluation are becoming critical. Cloud security posture management (CSPM) tools are essential here to identify over-privileged or dormant service principals.

## Carbonato Botnet: Docker, Telegram, and AI Agents

Now for something a little different: the Carbonato botnet is targeting exposed Docker daemons to deploy an open-source AI agent framework called Hermes Agent. The botnet installs the framework and then overwrites its persona file with a 39-line prompt directing it to execute tasks received via Telegram.

**My Take:** This is a fascinating and concerning convergence of technologies. Firstly, exposed Docker daemons are still a problem, highlighting fundamental misconfigurations in many environments. Secondly, the use of an AI agent, specifically an open-source one that can be easily repurposed, to execute botnet commands is a glimpse into the future of sophisticated attacks. Imagine an AI agent not just following instructions but adapting and learning to evade detection. This necessitates securing our container environments meticulously and beginning to think about how we can detect and neutralize malicious AI activity on our networks. It also emphasizes the need to control outbound network access for services like Docker to prevent C2 communication.

## Governing AI Agents: The Looming Shadow AI Threat

This brings us neatly to the broader issue: AI agents in production environments. A webinar summary highlighted that AI agents are rapidly connecting to apps, handling data, calling APIs, and acting across business systems without the same controls applied to human users. Worryingly, Okta's report states only 47% of CISOs are confident they can identify every AI agent in their environment.

**My Take:** This is "shadow IT" on steroids, but with autonomous agents. The lack of visibility and governance around AI agents interacting with sensitive systems is a ticking time bomb. We need clear policies, robust discovery mechanisms, and audited access controls for every AI agent. They should be treated like highly privileged users, not just another piece of software. Implement identity and access management (IAM) principles for AI, monitor their activity for anomalous behavior, and ensure data privacy and compliance aren't being sidestepped by their rapid deployment. This is a new frontier for blue teams, requiring us to understand how these agents operate and what their normal behavior looks like.

This week's news underscores the fact that the fundamentals of cybersecurity—asset management, patching, least privilege, and robust monitoring—remain absolutely crucial, even as the attack surface evolves with new technologies like AI. Stay vigilant, stay curious, and keep those systems locked down.

Until next week,
Juan Rodriguez