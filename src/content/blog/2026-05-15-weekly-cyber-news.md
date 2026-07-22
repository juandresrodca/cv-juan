---
title: "Weekly Cyber News — 15 May 2026"
date: 2026-05-15
summary: "This week: a critical Fortinet RCE that's already being weaponised in the wild, a new Scattered Spider campaign targeting SaaS identity providers, and CISA's advisory on ICS vulnerabilities in water treatment facilities."
tags: ["weekly", "vulnerabilities", "ransomware", "ics", "identity"]
draft: false
heroImage: "images/blog/2026-05-15-weekly-cyber-news.svg"
---

Another week, another set of patches to fast-track and conversations to have with leadership about why we can't defer that firewall upgrade until Q3.

Here are the three stories that grabbed my attention this week — with some thoughts from the coal face.

---

## 1. Fortinet FortiOS RCE (CVE-2026-20457) — Patch Now, Seriously

A heap-based buffer overflow in FortiOS's SSL-VPN web management interface is being actively exploited. CVSS 9.8. Unauthenticated remote code execution, no user interaction required. The initial PoC dropped on GitHub within 48 hours of disclosure and threat actors were scanning for vulnerable endpoints within hours of that.

**Affected versions:** FortiOS 7.2.x < 7.2.9, FortiOS 7.4.x < 7.4.4, FortiOS 7.6.x < 7.6.1.

**What I'm doing about it:** We're not running FortiGate at Intel, but two of my home-lab clients are, so I had those conversations Monday morning. The tricky part isn't patching — it's the maintenance window negotiation. "It's being actively exploited" tends to be the magic phrase that unlocks emergency change approval. Use it.

If you can't patch immediately: disable SSL-VPN on the management interface, restrict admin access to trusted source IPs, and crank up your logging verbosity so you at least know if someone's knocking.

**Blue-team take:** Check your asset inventory against the affected versions *today*. Not tomorrow. Shodan has already indexed thousands of vulnerable endpoints; assume adversaries are doing the same. If you're running exposed Fortinet and haven't patched, you should be treating this as an incident until proven otherwise.

---

## 2. Scattered Spider Pivots to SaaS Identity Providers

Mandiant published a detailed report this week on a new Scattered Spider campaign that's ditched the SIM-swapping playbook in favour of directly targeting Okta, Entra ID, and Ping Identity admin tenants. The TTPs are sophisticated: spear-phish an IT helpdesk account, use it to self-service reset MFA on a privileged user, pivot to the cloud admin console, and then create persistent backdoor access via OAuth app registrations and service principals that survive password resets.

What makes this particularly nasty is the dwell time. In two of the confirmed incidents, the threat actors maintained persistence for over 60 days before detection — all through legitimate-looking API activity that blended into normal admin noise.

**What this means for defenders:**

- Audit your OAuth app registrations and service principal permissions *right now*. Check for apps granted `Directory.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` that you don't recognise.
- Enable conditional access policies that enforce phishing-resistant MFA (FIDO2/passkeys) for all admin accounts — SMS and TOTP are not enough anymore for privileged access.
- Review your helpdesk MFA reset procedures. If a tier-1 agent can reset MFA via a phone call, you have a problem. Require identity verification that can't be socially engineered.

**My take:** The pivot away from SIM-swapping makes sense from an attacker's perspective — mobile carriers have gotten better at detecting suspicious port-outs, and SaaS admin consoles are a softer target with a much higher blast radius. The OSCP box I was doing last weekend had a similar initial access vector (credential stuffing into an admin panel) — it's a reminder that the techniques you practice in the lab are exactly what's happening in production environments.

---

## 3. CISA Advisory: ICS Vulnerabilities in Water Treatment Facility SCADA Systems

CISA's AA26-134A advisory dropped Thursday covering multiple vulnerabilities in SCADA systems deployed across water and wastewater treatment facilities in the US. The highlight is an authentication bypass in a widely-deployed HMI platform (Vendor B, undisclosed pending coordinated disclosure) that allows unauthenticated access to pump control interfaces over the default network configuration.

This is the kind of advisory that doesn't get the same Twitter hype as a splashy ransomware campaign, but it should. Water treatment infrastructure is critical, it's chronically underfunded on the security side, and OT networks have a horrible track record of network segmentation.

**What to know:**

- If you manage or advise on OT/ICS environments: apply the vendor mitigations immediately (detailed in the advisory), segment HMI systems behind dedicated firewalls, and audit who has remote access to these systems.
- The advisory also recommends disabling DCOM on HMI workstations if not required — worth doing regardless.
- For broader context: the Volt Typhoon reporting from early 2026 established that Chinese state actors have been pre-positioning in US critical infrastructure. This advisory is a reminder that the exposure surface is large and the defenders are often under-resourced.

**My take as a sysadmin:** OT security is an area I've been spending more time on as part of my OSCP prep. The segmentation failures in these environments are genuinely shocking — flat networks with direct internet exposure, legacy Windows XP HMIs with no patch path, vendor remote access accounts with shared credentials. The hardening steps CISA recommends are basic IT hygiene that somehow never made it into these deployments. If you have any OT/ICS in your remit, make the CISA ICS advisories part of your weekly reading.

---

That's the week. Patch the FortiOS, audit your OAuth apps, and subscribe to the CISA alerts RSS if you haven't already. See you next Friday.

Cheers,

Juan Rodriguez
