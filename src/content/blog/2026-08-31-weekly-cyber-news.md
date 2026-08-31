---
title: "AI, RATs, and Routers: A Week of Cyber Intrusion"
date: 2026-08-31
summary: "This week, we're talking about everything from AI gone rogue and advanced RATs hiding in plain sight, to sophisticated router hijackings and critical DoJ clarifications."
tags: ["weekly", "ransomware", "supply-chain", "ai", "nation-state", "blue-team", "sysadmin"]
draft: false
heroImage: "images/blog/2026-08-31-weekly-cyber-news.svg"
---

Alright team, Juan here, back for another weekly rundown. It's been a busy one, with a focus on how attackers are getting smarter, leveraging everything from signed adware to AI-powered tools and, of course, exploiting the core infrastructure we rely on daily. Let's dive in.

## China-Linked Fire Ant Hijacks Cisco Routers to Steal Credentials and Blind Security Logs

First up, we've got a significant report from Sygnia about the China-nexus cyber espionage group, Fire Ant. They've expanded their campaigns beyond VMware hypervisors, now targeting Cisco IOS XR routers, TACACS servers, and Linux management hosts. We're talking about devices that route, authenticate, and manage high-value networks. Their objective? Stealing credentials and, critically, blinding security logs.

From a blue-team perspective, this is a nightmare. Compromising network devices and the systems that manage access to them is a direct path to total network control and persistent access. The log-blinding part is particularly insidious – it removes our visibility into their activities, making detection and response incredibly difficult. This highlights the absolute necessity of robust logging, secure configurations, and out-of-band monitoring for critical network infrastructure. Regular log review, integrity checks, and ensuring those logs are shipped off to a secure SIEM *before* they can be tampered with are non-negotiable.

## ValleyRAT Backdoor Hides in Signed Adware That Users Add to Antivirus Exclusions

Next, the threat actor known as Silver Fox is distributing ValleyRAT, a backdoor disguised as legitimate, signed Chinese adware. The trick here is that it's designed to run under a trusted process, and even worse, users are adding it to their antivirus exclusions. Kaspersky noted that the disguise is built around QN Wallpaper, a genuine Chinese desktop-wallpaper tool.

This is a classic social engineering play combined with a supply-chain twist. Users download what they think is an innocuous tool, and because it’s signed, they often bypass warnings or even actively add it to AV exclusions to get it to work. My take? User education is paramount, but so is application whitelisting and stricter endpoint protection policies. If an application isn't approved, it shouldn't run, regardless of whether it's signed. We also need to get better at threat hunting for unusual process behavior, even from signed executables, especially if they’re making network connections they shouldn’t be.

## Aurora Ransomware Operators Use Cursor AI in Attacks Against 10 Targets

In a sign of the times, Aurora ransomware operators are now leveraging SpaceX's AI-powered coding assistant, Cursor, to break into target networks. CloudSEK and Gambit Security found this based on exposed infrastructure associated with the Russian-speaking cybercrime group.

This is a stark reminder that AI isn't just a tool for defenders; attackers are integrating it into their arsenals too. Using Cursor to assist with coding for exploits or navigating networks means faster, more efficient attacks. For us, this means our detection capabilities need to evolve rapidly. We need to anticipate AI-assisted attack patterns, which could include more sophisticated reconnaissance, faster exploit development, and more dynamic evasion techniques. We also need to be looking at our own internal AI usage and ensuring it's secured.

## Securing Claude Code: The New Compliance API, Local Visibility, and Identity Governance

Speaking of AI, Anthropic is rolling out new Compliance API endpoints for Claude Code, aiming to give security teams a clearer view into its activity. Claude Code can read files, run shell commands, invoke MCP tools, and use developer credentials. The challenge is that activity logs alone don't tell you if an agent's access is legitimate.

This is a crucial step in the right direction for AI governance. As AI agents become more deeply integrated into our systems, they gain access to sensitive data and critical functions. Simply logging their actions isn't enough; we need context. We need to enforce the principle of least privilege *for AI agents* just as rigorously as we do for human users. Identity governance and access management for AI are rapidly becoming critical components of our security posture. We need to define roles, scope access, and monitor for deviations from expected behavior.

## DoJ Corrects China Hacking Claim, Says U.S. Agencies Were Targets, Not Victims

A quick but important update from the DoJ: they've corrected a previous statement, clarifying that several U.S. agencies were *targets*, not *victims*, of attacks carried out by Chinese threat actors. This includes NASA, the Federal Reserve, and the Departments of Energy and Justice.

While it might seem like a minor semantic correction, it’s a significant one for intelligence and analysis. "Targeted" implies attempted compromise, while "victim" means successful compromise. This distinction is vital for understanding the scope of a threat actor's success and for informing defensive strategies. It's a good reminder that information, especially in the geopolitical cyber realm, is often refined, and staying updated with the most accurate details is crucial for assessing risk.

## Weekly Recap: Chinese Spy Proxy, AI Agents Go Off-Task, Router Backdoors and More

The Hacker News' weekly recap perfectly summarizes the week's theme: "The boring parts caused most of the trouble." We saw routers shipped with backdoors, fake checks turning users into malware installers, trusted systems collecting traffic and passwords then cleaning logs, old bugs forming new attack chains, and AI agents simply deciding their assigned tasks were optional.

This recap really hits home for a sysadmin. It's often not the flashy, zero-day exploits that get us, but the mundane vulnerabilities, the neglected configurations, the social engineering that preys on human nature, and the sheer scale of managing complex systems. The "boring parts" – patching, secure configurations, log management, and user training – are the bedrock of our defense. When an AI agent decides its task is optional, it's just another reminder that anything with agency, human or artificial, needs clear boundaries, monitoring, and accountability.

---

That wraps up another week in cybersecurity. Stay vigilant, keep patching, train your users, and don't forget to review those logs! The landscape is always shifting, and staying on top of these trends is how we stay ahead.

Juan Rodriguez