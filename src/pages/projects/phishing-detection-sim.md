---
layout: ../../layouts/Layout.astro
title: Phishing Detection Simulator
description: A Python CLI tool that simulates SOC analyst workflows by analyzing suspicious emails, running detection modules, and generating risk assessments with structured reports.
tags: ["Python", "Cybersecurity", "SOC", "CLI Tool"]
emoji: "🎣"
gradient: "from-orange-500 to-red-600"
github: "https://github.com/juandresrodca/Phishing-Detection-Sim"
publishDate: 2025-01-01
---

<!-- Nav -->
<nav class="sticky top-0 z-40 bg-dark-900/80 backdrop-blur-md py-4 border-b border-gray-800">
  <div class="container mx-auto px-6 flex justify-between items-center">
    <a href="/cv-juan/#projects" class="text-primary-400 hover:text-primary-300 transition-colors flex items-center space-x-2">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M9.707 14.707a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414l4-4a1 1 0 001.414 1.414L7.414 9H15a1 1 0 110 2H7.414l2.293 2.293a1 1 0 010 1.414z" clip-rule="evenodd" />
      </svg>
      <span>Back to Projects</span>
    </a>
    <a href="https://github.com/juandresrodca/Phishing-Detection-Sim" target="_blank" rel="noopener noreferrer"
       class="flex items-center space-x-2 bg-primary-600/20 text-primary-400 border border-primary-600/40 px-4 py-2 rounded-lg hover:bg-primary-600/30 transition-colors text-sm">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
      </svg>
      <span>View on GitHub</span>
    </a>
  </div>
</nav>

<!-- Hero Banner -->
<div class="relative overflow-hidden bg-gradient-to-br from-orange-900/40 via-dark-900 to-red-900/40 border-b border-orange-800/30">
  <div class="absolute inset-0 opacity-10" style="background-image: repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(251,146,60,0.3) 39px, rgba(251,146,60,0.3) 40px), repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(251,146,60,0.3) 39px, rgba(251,146,60,0.3) 40px);"></div>
  <div class="container mx-auto px-6 py-20 relative z-10">
    <div class="max-w-4xl mx-auto text-center">
      <div class="inline-flex items-center space-x-2 bg-orange-500/20 border border-orange-500/40 text-orange-400 px-4 py-2 rounded-full text-sm font-medium mb-6">
        <span class="w-2 h-2 bg-orange-400 rounded-full animate-pulse"></span>
        <span>SOC Analyst Simulation Tool</span>
      </div>
      <h1 class="text-5xl md:text-7xl font-bold mb-6" style="background: linear-gradient(135deg, #fb923c, #ef4444, #f97316); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
        Phishing Detection<br/>Simulator
      </h1>
      <p class="text-xl text-gray-300 mb-8 max-w-2xl mx-auto leading-relaxed">
        A Python CLI tool that replicates the decision-making workflow of a real SOC analyst — scanning emails, scoring threats, and exporting structured incident reports.
      </p>
      <div class="flex flex-wrap justify-center gap-3 mb-10">
        <span class="bg-orange-600/20 text-orange-400 border border-orange-600/30 px-3 py-1 rounded-full text-sm">Python 3.12+</span>
        <span class="bg-red-600/20 text-red-400 border border-red-600/30 px-3 py-1 rounded-full text-sm">Cybersecurity</span>
        <span class="bg-blue-600/20 text-blue-400 border border-blue-600/30 px-3 py-1 rounded-full text-sm">SOC Workflows</span>
        <span class="bg-green-600/20 text-green-400 border border-green-600/30 px-3 py-1 rounded-full text-sm">CLI Tool</span>
        <span class="bg-purple-600/20 text-purple-400 border border-purple-600/30 px-3 py-1 rounded-full text-sm">MIT License</span>
      </div>
      <!-- Stats Row -->
      <div class="grid grid-cols-3 gap-6 max-w-xl mx-auto">
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <div class="text-3xl font-bold text-orange-400">4</div>
          <div class="text-xs text-gray-400 mt-1">Detection Modules</div>
        </div>
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <div class="text-3xl font-bold text-red-400">0–100</div>
          <div class="text-xs text-gray-400 mt-1">Risk Score Range</div>
        </div>
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <div class="text-3xl font-bold text-green-400">20+</div>
          <div class="text-xs text-gray-400 mt-1">Unit Tests</div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="container mx-auto px-6 py-16 max-w-5xl">

  <!-- What It Does -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">What It Does</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-8">
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6">
        <p class="text-gray-300 leading-relaxed">
          The <strong class="text-orange-400">Phishing Detection Simulator</strong> is a modular CLI application that walks through the same triage steps a SOC analyst performs when a suspicious email lands in a queue.
        </p>
        <p class="text-gray-300 leading-relaxed mt-4">
          It reads raw email content, passes it through four independent detection engines, aggregates weighted signals into a numeric risk score, classifies the threat level, and produces machine-readable reports — all without leaving the terminal.
        </p>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Built to simulate real SOC tasks:</h3>
        <ul class="space-y-3">
          <li class="flex items-start space-x-3">
            <span class="text-orange-400 mt-1">▶</span>
            <span class="text-gray-300">Parse and inspect raw email headers and body</span>
          </li>
          <li class="flex items-start space-x-3">
            <span class="text-orange-400 mt-1">▶</span>
            <span class="text-gray-300">Run multi-layer threat detection in seconds</span>
          </li>
          <li class="flex items-start space-x-3">
            <span class="text-orange-400 mt-1">▶</span>
            <span class="text-gray-300">Assign a structured risk rating for triage decisions</span>
          </li>
          <li class="flex items-start space-x-3">
            <span class="text-orange-400 mt-1">▶</span>
            <span class="text-gray-300">Export reports for SIEM integration or documentation</span>
          </li>
        </ul>
      </div>
    </div>
  </section>

  <!-- Terminal Demo -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Live Terminal Output</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="rounded-xl overflow-hidden border border-gray-700 shadow-2xl">
      <!-- Terminal chrome -->
      <div class="bg-gray-800 px-4 py-3 flex items-center space-x-2 border-b border-gray-700">
        <div class="w-3 h-3 rounded-full bg-red-500"></div>
        <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
        <div class="w-3 h-3 rounded-full bg-green-500"></div>
        <span class="ml-4 text-gray-400 text-sm font-mono">phishing-sim — bash</span>
      </div>
      <!-- Terminal body -->
      <div class="bg-gray-950 p-6 font-mono text-sm leading-relaxed overflow-x-auto">
        <div><span class="text-green-400">$</span> <span class="text-white">python main.py --email samples/phishing_sample.txt --report json</span></div>
        <div class="mt-3 text-gray-500">─────────────────────────────────────────────</div>
        <div class="text-cyan-400 font-bold">  🎣 PHISHING DETECTION SIMULATOR v1.0</div>
        <div class="text-gray-500">─────────────────────────────────────────────</div>
        <div class="mt-2"><span class="text-blue-400">[INFO]</span> <span class="text-gray-300">Loading email: samples/phishing_sample.txt</span></div>
        <div><span class="text-blue-400">[INFO]</span> <span class="text-gray-300">Starting analysis pipeline...</span></div>
        <div class="mt-3 text-yellow-400 font-semibold">► Running Detection Modules</div>
        <div class="mt-1 ml-2"><span class="text-green-400">✓</span> <span class="text-gray-300">Keyword Scanner ............ </span><span class="text-orange-400">+35 pts</span><span class="text-gray-500"> (urgency language, sensitive request phrases)</span></div>
        <div class="ml-2"><span class="text-green-400">✓</span> <span class="text-gray-300">Domain Analyzer ............ </span><span class="text-red-400">+40 pts</span><span class="text-gray-500"> (typosquatted domain: "paypa1.com")</span></div>
        <div class="ml-2"><span class="text-green-400">✓</span> <span class="text-gray-300">Attachment Scanner ......... </span><span class="text-orange-400">+20 pts</span><span class="text-gray-500"> (high-risk: invoice.exe)</span></div>
        <div class="ml-2"><span class="text-green-400">✓</span> <span class="text-gray-300">Header Inspector ........... </span><span class="text-yellow-400">+05 pts</span><span class="text-gray-500"> (sender spoofing mismatch)</span></div>
        <div class="mt-3 text-gray-500">─────────────────────────────────────────────</div>
        <div class="mt-1"><span class="text-white font-bold">RISK SCORE:  </span><span class="text-red-400 font-bold text-lg">82 / 100</span></div>
        <div><span class="text-white font-bold">VERDICT:     </span><span class="bg-red-600 text-white px-2 py-0.5 rounded text-xs font-bold">⚠ HIGH RISK — LIKELY PHISHING</span></div>
        <div class="mt-3 text-gray-500">─────────────────────────────────────────────</div>
        <div><span class="text-blue-400">[INFO]</span> <span class="text-gray-300">Report exported → </span><span class="text-green-400">reports/report_2025-01-15_14-32.json</span></div>
        <div><span class="text-blue-400">[INFO]</span> <span class="text-gray-300">Audit log updated → </span><span class="text-green-400">logs/phishing_sim.log</span></div>
        <div class="mt-2 text-green-400">✓ Analysis complete.</div>
      </div>
    </div>
  </section>

  <!-- Risk Score Visualizer -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Risk Classification</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-8">
      <p class="text-gray-400 mb-8 text-center">Every email receives a score from 0 to 100. The scoring engine maps this to one of three triage tiers:</p>
      <div class="grid md:grid-cols-3 gap-6 mb-8">
        <div class="bg-green-900/20 border border-green-700/40 rounded-xl p-6 text-center">
          <div class="text-5xl font-bold text-green-400 mb-2">0–39</div>
          <div class="text-green-300 font-semibold text-lg mb-2">LOW</div>
          <div class="text-gray-400 text-sm">Likely safe. No immediate action required. Logged for auditing.</div>
        </div>
        <div class="bg-yellow-900/20 border border-yellow-700/40 rounded-xl p-6 text-center">
          <div class="text-5xl font-bold text-yellow-400 mb-2">40–69</div>
          <div class="text-yellow-300 font-semibold text-lg mb-2">MEDIUM</div>
          <div class="text-gray-400 text-sm">Suspicious signals detected. Flagged for analyst review and monitoring.</div>
        </div>
        <div class="bg-red-900/20 border border-red-700/40 rounded-xl p-6 text-center">
          <div class="text-5xl font-bold text-red-400 mb-2">70–100</div>
          <div class="text-red-300 font-semibold text-lg mb-2">HIGH</div>
          <div class="text-gray-400 text-sm">Strong phishing indicators. Quarantine and incident response recommended.</div>
        </div>
      </div>
      <!-- Score bar -->
      <div class="relative h-6 rounded-full overflow-hidden" style="background: linear-gradient(to right, #16a34a 0%, #16a34a 39%, #ca8a04 39%, #ca8a04 69%, #dc2626 69%, #dc2626 100%);">
        <div class="absolute inset-0 flex items-center justify-around text-xs font-bold text-white px-4">
          <span>LOW</span>
          <span>|</span>
          <span>MEDIUM</span>
          <span>|</span>
          <span>HIGH</span>
        </div>
      </div>
    </div>
  </section>

  <!-- Detection Modules -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Detection Modules</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-6">

      <div class="bg-dark-800/60 border border-orange-700/30 rounded-xl p-6 hover:border-orange-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-orange-500/20 flex items-center justify-center text-xl">🔑</div>
          <h3 class="text-lg font-bold text-orange-400">Keyword Scanner</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Scans the email body for known phishing vocabulary — urgency phrases, credential-harvesting language, and social engineering cues that manipulate recipients into taking action.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">"Verify your account"</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">"Immediate action required"</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">"Click here to confirm"</span>
        </div>
      </div>

      <div class="bg-dark-800/60 border border-red-700/30 rounded-xl p-6 hover:border-red-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center text-xl">🌐</div>
          <h3 class="text-lg font-bold text-red-400">Domain Analyzer</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Inspects sender addresses and embedded URLs for typosquatting, suspicious TLDs, IP-based links, and sender/reply-to spoofing patterns that indicate fraudulent origin.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Typosquatting</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">IP-based URLs</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Sender spoofing</span>
        </div>
      </div>

      <div class="bg-dark-800/60 border border-yellow-700/30 rounded-xl p-6 hover:border-yellow-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-yellow-500/20 flex items-center justify-center text-xl">📎</div>
          <h3 class="text-lg font-bold text-yellow-400">Attachment Scanner</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Classifies all file attachments across four risk tiers — from critical (executables, macros) to low-risk (standard documents) — giving analysts a rapid surface-area assessment.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-red-900/40 text-red-400 border border-red-700/30 px-2 py-1 rounded text-xs">Critical: .exe .bat .ps1</span>
          <span class="bg-yellow-900/40 text-yellow-400 border border-yellow-700/30 px-2 py-1 rounded text-xs">High: .docm .xlsm</span>
          <span class="bg-green-900/40 text-green-400 border border-green-700/30 px-2 py-1 rounded text-xs">Low: .pdf .txt</span>
        </div>
      </div>

      <div class="bg-dark-800/60 border border-blue-700/30 rounded-xl p-6 hover:border-blue-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center text-xl">📋</div>
          <h3 class="text-lg font-bold text-blue-400">Risk Scoring Engine</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Aggregates weighted signals from all detection modules into a single 0–100 risk score. Each module contributes a calibrated point value based on indicator severity and confidence level.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Weighted aggregation</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Configurable thresholds</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">LOWs / MEDIUM / HIGH</span>
        </div>
      </div>

    </div>
  </section>

  <!-- Report Output -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Structured Report Export</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-8">
      <!-- JSON example -->
      <div>
        <div class="flex items-center space-x-2 mb-3">
          <span class="bg-blue-600/20 text-blue-400 border border-blue-600/30 px-3 py-1 rounded-full text-xs font-semibold">JSON OUTPUT</span>
          <span class="text-gray-500 text-xs">Machine-readable / SIEM-ready</span>
        </div>
        <div class="rounded-xl overflow-hidden border border-gray-700">
          <div class="bg-gray-800 px-4 py-2 flex items-center space-x-2 border-b border-gray-700">
            <div class="w-2 h-2 rounded-full bg-red-500"></div>
            <div class="w-2 h-2 rounded-full bg-yellow-500"></div>
            <div class="w-2 h-2 rounded-full bg-green-500"></div>
            <span class="ml-2 text-gray-400 text-xs">report_2025-01-15.json</span>
          </div>
          <pre class="bg-gray-950 p-4 text-xs font-mono overflow-x-auto text-gray-300"><code><span class="text-gray-500">{</span>
  <span class="text-blue-400">"email_id"</span>: <span class="text-green-400">"phish_0042"</span>,
  <span class="text-blue-400">"timestamp"</span>: <span class="text-green-400">"2025-01-15T14:32:00Z"</span>,
  <span class="text-blue-400">"risk_score"</span>: <span class="text-orange-400">82</span>,
  <span class="text-blue-400">"verdict"</span>: <span class="text-red-400">"HIGH"</span>,
  <span class="text-blue-400">"modules"</span>: <span class="text-gray-500">{</span>
    <span class="text-blue-400">"keyword_score"</span>: <span class="text-orange-400">35</span>,
    <span class="text-blue-400">"domain_score"</span>: <span class="text-orange-400">40</span>,
    <span class="text-blue-400">"attachment_score"</span>: <span class="text-orange-400">20</span>,
    <span class="text-blue-400">"header_score"</span>: <span class="text-orange-400">5</span>
  <span class="text-gray-500">}</span>,
  <span class="text-blue-400">"flags"</span>: <span class="text-gray-500">[</span>
    <span class="text-green-400">"typosquat_domain"</span>,
    <span class="text-green-400">"high_risk_attachment"</span>,
    <span class="text-green-400">"urgency_language"</span>
  <span class="text-gray-500">]</span>
<span class="text-gray-500">}</span></code></pre>
        </div>
      </div>
      <!-- CSV example -->
      <div>
        <div class="flex items-center space-x-2 mb-3">
          <span class="bg-green-600/20 text-green-400 border border-green-600/30 px-3 py-1 rounded-full text-xs font-semibold">CSV OUTPUT</span>
          <span class="text-gray-500 text-xs">Spreadsheet / audit trail</span>
        </div>
        <div class="rounded-xl overflow-hidden border border-gray-700">
          <div class="bg-gray-800 px-4 py-2 flex items-center space-x-2 border-b border-gray-700">
            <div class="w-2 h-2 rounded-full bg-red-500"></div>
            <div class="w-2 h-2 rounded-full bg-yellow-500"></div>
            <div class="w-2 h-2 rounded-full bg-green-500"></div>
            <span class="ml-2 text-gray-400 text-xs">report_2025-01-15.csv</span>
          </div>
          <pre class="bg-gray-950 p-4 text-xs font-mono overflow-x-auto text-gray-300"><code><span class="text-blue-400">email_id,timestamp,score,verdict,flags</span>
<span class="text-gray-300">phish_0042,2025-01-15T14:32:00Z,</span>
<span class="text-red-400">82,HIGH,</span>
<span class="text-gray-300">typosquat_domain|high_risk...</span>

<span class="text-blue-400">module,score,indicators</span>
<span class="text-gray-300">keyword,35,urgency_language|...</span>
<span class="text-gray-300">domain,40,typosquat_domain|...</span>
<span class="text-gray-300">attachment,20,invoice.exe</span>
<span class="text-gray-300">header,5,sender_spoof</span></code></pre>
        </div>
        <div class="mt-4 bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <h4 class="text-white font-semibold mb-2 text-sm">Report Features</h4>
          <ul class="space-y-2 text-sm text-gray-400">
            <li class="flex items-center space-x-2"><span class="text-green-400">✓</span><span>Timestamped entries for full audit trail</span></li>
            <li class="flex items-center space-x-2"><span class="text-green-400">✓</span><span>Per-module score breakdown</span></li>
            <li class="flex items-center space-x-2"><span class="text-green-400">✓</span><span>Named indicator flags for triage notes</span></li>
            <li class="flex items-center space-x-2"><span class="text-green-400">✓</span><span>Rotating log file for debugging</span></li>
          </ul>
        </div>
      </div>
    </div>
  </section>

  <!-- Tech Stack -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Tech Stack</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-orange-500/40 transition-colors">
        <div class="text-3xl mb-2">🐍</div>
        <div class="text-white font-semibold text-sm">Python 3.12+</div>
        <div class="text-gray-500 text-xs mt-1">Core language</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-orange-500/40 transition-colors">
        <div class="text-3xl mb-2">⚙️</div>
        <div class="text-white font-semibold text-sm">argparse</div>
        <div class="text-gray-500 text-xs mt-1">CLI framework</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-orange-500/40 transition-colors">
        <div class="text-3xl mb-2">🧪</div>
        <div class="text-white font-semibold text-sm">pytest</div>
        <div class="text-gray-500 text-xs mt-1">20+ tests</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-orange-500/40 transition-colors">
        <div class="text-3xl mb-2">📄</div>
        <div class="text-white font-semibold text-sm">JSON / CSV</div>
        <div class="text-gray-500 text-xs mt-1">Report formats</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-orange-500/40 transition-colors">
        <div class="text-3xl mb-2">📜</div>
        <div class="text-white font-semibold text-sm">Rotating Logs</div>
        <div class="text-gray-500 text-xs mt-1">Audit trail</div>
      </div>
    </div>
  </section>

  <!-- Architecture -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Architecture</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-8">
      <div class="flex flex-col items-center space-y-4">
        <!-- Input -->
        <div class="bg-gray-700/60 border border-gray-600 rounded-lg px-6 py-3 text-center">
          <div class="text-xs text-gray-400 mb-1">INPUT</div>
          <div class="text-white font-semibold">Raw Email File (.txt / .eml)</div>
        </div>
        <div class="text-orange-400 text-xl">↓</div>
        <!-- CLI Layer -->
        <div class="bg-orange-900/20 border border-orange-700/40 rounded-lg px-6 py-3 text-center">
          <div class="text-xs text-orange-400 mb-1">CLI LAYER</div>
          <div class="text-white font-semibold">main.py (argparse)</div>
        </div>
        <div class="text-orange-400 text-xl">↓</div>
        <!-- Detection modules row -->
        <div class="w-full">
          <div class="text-xs text-gray-400 text-center mb-3">DETECTION PIPELINE</div>
          <div class="grid grid-cols-4 gap-3">
            <div class="bg-orange-900/20 border border-orange-700/30 rounded-lg p-3 text-center">
              <div class="text-orange-400 text-lg mb-1">🔑</div>
              <div class="text-white text-xs font-semibold">keyword_scanner.py</div>
            </div>
            <div class="bg-red-900/20 border border-red-700/30 rounded-lg p-3 text-center">
              <div class="text-red-400 text-lg mb-1">🌐</div>
              <div class="text-white text-xs font-semibold">domain_analyzer.py</div>
            </div>
            <div class="bg-yellow-900/20 border border-yellow-700/30 rounded-lg p-3 text-center">
              <div class="text-yellow-400 text-lg mb-1">📎</div>
              <div class="text-white text-xs font-semibold">attachment_scanner.py</div>
            </div>
            <div class="bg-blue-900/20 border border-blue-700/30 rounded-lg p-3 text-center">
              <div class="text-blue-400 text-lg mb-1">📋</div>
              <div class="text-white text-xs font-semibold">header_inspector.py</div>
            </div>
          </div>
        </div>
        <div class="text-orange-400 text-xl">↓</div>
        <!-- Scoring -->
        <div class="bg-red-900/20 border border-red-700/40 rounded-lg px-6 py-3 text-center">
          <div class="text-xs text-red-400 mb-1">SCORING ENGINE</div>
          <div class="text-white font-semibold">scorer.py → 0–100 Risk Score + Verdict</div>
        </div>
        <div class="text-orange-400 text-xl">↓</div>
        <!-- Output row -->
        <div class="w-full">
          <div class="text-xs text-gray-400 text-center mb-3">OUTPUT</div>
          <div class="grid grid-cols-3 gap-3">
            <div class="bg-gray-700/60 border border-gray-600 rounded-lg p-3 text-center">
              <div class="text-green-400 text-sm mb-1">🖥</div>
              <div class="text-white text-xs font-semibold">ANSI Terminal</div>
              <div class="text-gray-400 text-xs">Colored output</div>
            </div>
            <div class="bg-gray-700/60 border border-gray-600 rounded-lg p-3 text-center">
              <div class="text-blue-400 text-sm mb-1">📄</div>
              <div class="text-white text-xs font-semibold">JSON Report</div>
              <div class="text-gray-400 text-xs">SIEM-ready</div>
            </div>
            <div class="bg-gray-700/60 border border-gray-600 rounded-lg p-3 text-center">
              <div class="text-orange-400 text-sm mb-1">📊</div>
              <div class="text-white text-xs font-semibold">CSV Report</div>
              <div class="text-gray-400 text-xs">Audit trail</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Getting Started -->
  <section class="mb-12">
    <h2 class="text-3xl font-bold mb-4 text-white">Getting Started</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded mb-8"></div>
    <div class="rounded-xl overflow-hidden border border-gray-700">
      <div class="bg-gray-800 px-4 py-3 flex items-center space-x-2 border-b border-gray-700">
        <div class="w-3 h-3 rounded-full bg-red-500"></div>
        <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
        <div class="w-3 h-3 rounded-full bg-green-500"></div>
        <span class="ml-4 text-gray-400 text-sm font-mono">terminal</span>
      </div>
      <div class="bg-gray-950 p-6 font-mono text-sm space-y-2">
        <div><span class="text-gray-500"># Clone the repository</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">git clone https://github.com/juandresrodca/Phishing-Detection-Sim.git</span></div>
        <div class="mt-2"><span class="text-gray-500"># Install dependencies</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">pip install -r requirements.txt</span></div>
        <div class="mt-2"><span class="text-gray-500"># Analyze an email sample</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">python main.py --email samples/phishing_sample.txt --report json</span></div>
        <div class="mt-2"><span class="text-gray-500"># Run the test suite</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">pytest tests/ -v</span></div>
      </div>
    </div>
  </section>

  <!-- CTA -->
  <div class="flex flex-col sm:flex-row gap-4 justify-center">
    <a href="https://github.com/juandresrodca/Phishing-Detection-Sim" target="_blank" rel="noopener noreferrer"
       class="flex items-center justify-center space-x-2 bg-orange-600 hover:bg-orange-500 text-white font-semibold px-8 py-4 rounded-xl transition-colors">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
      </svg>
      <span>View on GitHub</span>
    </a>
    <a href="/cv-juan/#projects"
       class="flex items-center justify-center space-x-2 bg-dark-800 border border-gray-600 hover:border-gray-400 text-white font-semibold px-8 py-4 rounded-xl transition-colors">
      <span>← Back to Projects</span>
    </a>
  </div>

</div>
