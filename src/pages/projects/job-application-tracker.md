---
layout: ../../layouts/Layout.astro
title: Job Application Tracker
description: A .NET 8 WPF desktop app built on Clean Architecture (MVVM, SQLite + Dapper) with a Kanban board, PDF job-posting extraction, Obsidian markdown sync, and an xUnit test suite.
tags: ["C#", ".NET 8", "WPF", "Clean Architecture", "SQLite", "xUnit"]
emoji: "📋"
gradient: "from-purple-500 to-pink-600"
github: "https://github.com/juandresrodca/job-application-tracker"
publishDate: 2024-01-01
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
    <a href="https://github.com/juandresrodca/job-application-tracker" target="_blank" rel="noopener noreferrer"
       class="flex items-center space-x-2 bg-primary-600/20 text-primary-400 border border-primary-600/40 px-4 py-2 rounded-lg hover:bg-primary-600/30 transition-colors text-sm">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
      </svg>
      <span>View on GitHub</span>
    </a>
  </div>
</nav>

<!-- Hero Banner -->
<div class="relative overflow-hidden bg-gradient-to-br from-purple-900/40 via-dark-900 to-pink-900/40 border-b border-purple-800/30">
  <div class="absolute inset-0 opacity-10" style="background-image: repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(192,132,252,0.3) 39px, rgba(192,132,252,0.3) 40px), repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(192,132,252,0.3) 39px, rgba(192,132,252,0.3) 40px);"></div>
  <div class="container mx-auto px-6 py-20 relative z-10">
    <div class="max-w-4xl mx-auto text-center">
      <div class="inline-flex items-center space-x-2 bg-purple-500/20 border border-purple-500/40 text-purple-400 px-4 py-2 rounded-full text-sm font-medium mb-6">
        <span class="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></span>
        <span>Windows Desktop App — Beta v0.1.0</span>
      </div>
      <h1 class="text-5xl md:text-7xl font-bold mb-6" style="background: linear-gradient(135deg, #c084fc, #ec4899, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
        Job Application<br/>Tracker
      </h1>
      <p class="text-xl text-gray-300 mb-8 max-w-2xl mx-auto leading-relaxed">
        A production-quality .NET 8 WPF desktop application for managing the full job-hunt lifecycle — Kanban workflow, PDF job-posting extraction, and automatic Obsidian vault sync.
      </p>
      <div class="flex flex-wrap justify-center gap-3 mb-10">
        <span class="bg-purple-600/20 text-purple-400 border border-purple-600/30 px-3 py-1 rounded-full text-sm">C# / .NET 8</span>
        <span class="bg-pink-600/20 text-pink-400 border border-pink-600/30 px-3 py-1 rounded-full text-sm">WPF + MVVM</span>
        <span class="bg-blue-600/20 text-blue-400 border border-blue-600/30 px-3 py-1 rounded-full text-sm">Clean Architecture</span>
        <span class="bg-green-600/20 text-green-400 border border-green-600/30 px-3 py-1 rounded-full text-sm">SQLite + Dapper</span>
        <span class="bg-orange-600/20 text-orange-400 border border-orange-600/30 px-3 py-1 rounded-full text-sm">xUnit</span>
        <span class="bg-gray-600/20 text-gray-400 border border-gray-600/30 px-3 py-1 rounded-full text-sm">MIT License</span>
      </div>
      <!-- Stats Row -->
      <div class="grid grid-cols-3 gap-6 max-w-xl mx-auto">
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <div class="text-3xl font-bold text-purple-400">4</div>
          <div class="text-xs text-gray-400 mt-1">Architecture Layers</div>
        </div>
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <div class="text-3xl font-bold text-pink-400">2</div>
          <div class="text-xs text-gray-400 mt-1">Dashboard Views</div>
        </div>
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <div class="text-3xl font-bold text-green-400">26</div>
          <div class="text-xs text-gray-400 mt-1">Pre-seeded IT Skills</div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="container mx-auto px-6 py-16 max-w-5xl">

  <!-- What It Does -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">What It Does</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-8">
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6">
        <p class="text-gray-300 leading-relaxed">
          The <strong class="text-purple-400">Job Application Tracker</strong> is a Windows desktop app that centralizes the entire job-search workflow — every application, company, contact, and skill in one local SQLite database, no cloud account required.
        </p>
        <p class="text-gray-300 leading-relaxed mt-4">
          Drop a job-posting PDF onto the form and it extracts the text and company name automatically. Every application syncs to your Obsidian vault as a structured markdown note, with your personal notes protected from being overwritten.
        </p>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Built for a real job hunt:</h3>
        <ul class="space-y-3">
          <li class="flex items-start space-x-3">
            <span class="text-purple-400 mt-1">▶</span>
            <span class="text-gray-300">Track applications from Applied through Offer or Rejected</span>
          </li>
          <li class="flex items-start space-x-3">
            <span class="text-purple-400 mt-1">▶</span>
            <span class="text-gray-300">Switch between sortable table and drag-and-drop Kanban board</span>
          </li>
          <li class="flex items-start space-x-3">
            <span class="text-purple-400 mt-1">▶</span>
            <span class="text-gray-300">See response rate and offer rate at a glance with stat cards</span>
          </li>
          <li class="flex items-start space-x-3">
            <span class="text-purple-400 mt-1">▶</span>
            <span class="text-gray-300">Keep long-form notes in Obsidian, auto-synced per application</span>
          </li>
        </ul>
      </div>
    </div>
  </section>

  <!-- Application Lifecycle -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Application Lifecycle</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-8">
      <p class="text-gray-400 mb-8 text-center">Every application moves through a status pipeline, visualized as columns on the Kanban board:</p>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-4 items-stretch">
        <div class="bg-blue-900/20 border border-blue-700/40 rounded-xl p-5 text-center">
          <div class="text-3xl mb-2">📨</div>
          <div class="text-blue-300 font-semibold mb-1">Applied</div>
          <div class="text-gray-400 text-xs">Submission logged with date, salary range, and posting URL</div>
        </div>
        <div class="bg-cyan-900/20 border border-cyan-700/40 rounded-xl p-5 text-center">
          <div class="text-3xl mb-2">📞</div>
          <div class="text-cyan-300 font-semibold mb-1">Screening</div>
          <div class="text-gray-400 text-xs">Recruiter call or HR screen in progress</div>
        </div>
        <div class="bg-yellow-900/20 border border-yellow-700/40 rounded-xl p-5 text-center">
          <div class="text-3xl mb-2">💬</div>
          <div class="text-yellow-300 font-semibold mb-1">Interview</div>
          <div class="text-gray-400 text-xs">Technical or panel interviews scheduled</div>
        </div>
        <div class="bg-green-900/20 border border-green-700/40 rounded-xl p-5 text-center">
          <div class="text-3xl mb-2">🎉</div>
          <div class="text-green-300 font-semibold mb-1">Offer</div>
          <div class="text-gray-400 text-xs">Offer received — celebrate and negotiate</div>
        </div>
        <div class="bg-red-900/20 border border-red-700/40 rounded-xl p-5 text-center">
          <div class="text-3xl mb-2">📕</div>
          <div class="text-red-300 font-semibold mb-1">Rejected</div>
          <div class="text-gray-400 text-xs">Closed out, kept for response-rate analytics</div>
        </div>
      </div>
      <!-- Pipeline bar -->
      <div class="relative h-6 rounded-full overflow-hidden mt-8" style="background: linear-gradient(to right, #2563eb 0%, #0891b2 25%, #ca8a04 50%, #16a34a 75%, #dc2626 100%);">
        <div class="absolute inset-0 flex items-center justify-around text-xs font-bold text-white px-2">
          <span>APPLIED</span>
          <span>→</span>
          <span>SCREENING</span>
          <span>→</span>
          <span>INTERVIEW</span>
          <span>→</span>
          <span>OFFER / REJECTED</span>
        </div>
      </div>
    </div>
  </section>

  <!-- Key Features -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Key Features</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-6">

      <div class="bg-dark-800/60 border border-purple-700/30 rounded-xl p-6 hover:border-purple-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center text-xl">📊</div>
          <h3 class="text-lg font-bold text-purple-400">Dashboard — Table & Kanban</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Toggle between a sortable table with real-time status updates and a drag-and-drop Kanban board organized by application status. Stat cards show application count, response rate, and offer rate.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Sortable columns</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Drag & drop</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Week stats</span>
        </div>
      </div>

      <div class="bg-dark-800/60 border border-pink-700/30 rounded-xl p-6 hover:border-pink-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-pink-500/20 flex items-center justify-center text-xl">🗒️</div>
          <h3 class="text-lg font-bold text-pink-400">Obsidian Vault Sync</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Every application auto-syncs to your Obsidian vault as a markdown note with YAML frontmatter, status, timeline, and skills. A protected User Notes section survives every re-sync — your notes are never overwritten.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">YAML frontmatter</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Section-aware merge</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Protected notes</span>
        </div>
      </div>

      <div class="bg-dark-800/60 border border-blue-700/30 rounded-xl p-6 hover:border-blue-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center text-xl">📄</div>
          <h3 class="text-lg font-bold text-blue-400">PDF Job-Posting Extraction</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Load a job posting PDF directly into the application form — the extraction service pulls the full text and detects the company name, so you never retype a job description again.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Text extraction</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Company detection</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Auto-fill form</span>
        </div>
      </div>

      <div class="bg-dark-800/60 border border-green-700/30 rounded-xl p-6 hover:border-green-500/50 transition-colors">
        <div class="flex items-center space-x-3 mb-4">
          <div class="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center text-xl">🗂️</div>
          <h3 class="text-lg font-bold text-green-400">Companies, Contacts & Skills</h3>
        </div>
        <p class="text-gray-300 text-sm mb-4">Full CRUD pages with inline edit panels for companies, recruiters, and skills. Tag each application with required vs. owned skills — 26 IT/security skills come pre-seeded on first run.</p>
        <div class="flex flex-wrap gap-2">
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Inline editing</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Skill matching</span>
          <span class="bg-gray-700 text-gray-300 px-2 py-1 rounded text-xs">Delete confirmations</span>
        </div>
      </div>

    </div>
  </section>

  <!-- Architecture -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Clean Architecture</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-8 mb-8">
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-3">Why MVVM + WPF?</h3>
        <ul class="space-y-3 text-sm text-gray-300">
          <li class="flex items-start space-x-2"><span class="text-purple-400 mt-0.5">✓</span><span>WPF's data binding engine is built for MVVM — <code class="text-pink-400 bg-gray-800 px-1 rounded">{Binding}</code> targets <code class="text-pink-400 bg-gray-800 px-1 rounded">INotifyPropertyChanged</code></span></li>
          <li class="flex items-start space-x-2"><span class="text-purple-400 mt-0.5">✓</span><span>ViewModels are fully testable without UI — no Window or Page references</span></li>
          <li class="flex items-start space-x-2"><span class="text-purple-400 mt-0.5">✓</span><span>Commands (<code class="text-pink-400 bg-gray-800 px-1 rounded">ICommand</code>) replace controller actions cleanly</span></li>
          <li class="flex items-start space-x-2"><span class="text-purple-400 mt-0.5">✓</span><span>Dependency injection container wires every layer at startup</span></li>
        </ul>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6">
        <h3 class="text-lg font-semibold text-white mb-3">Testing & Data</h3>
        <ul class="space-y-3 text-sm text-gray-300">
          <li class="flex items-start space-x-2"><span class="text-green-400 mt-0.5">✓</span><span><strong class="text-white">xUnit test suite</strong> — service, settings, and in-memory repository tests</span></li>
          <li class="flex items-start space-x-2"><span class="text-green-400 mt-0.5">✓</span><span><strong class="text-white">SQLite + Dapper</strong> with WAL mode and multi-map joins</span></li>
          <li class="flex items-start space-x-2"><span class="text-green-400 mt-0.5">✓</span><span>Indexes on the three most-filtered columns: AppliedDate, Status, CompanyId</span></li>
          <li class="flex items-start space-x-2"><span class="text-green-400 mt-0.5">✓</span><span>Settings persisted as JSON in <code class="text-pink-400 bg-gray-800 px-1 rounded">%APPDATA%\JobTracker</code></span></li>
        </ul>
      </div>
    </div>
    <!-- Layer diagram -->
    <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-8">
      <div class="flex flex-col items-center space-y-4">
        <div class="w-full max-w-lg bg-purple-900/20 border border-purple-700/40 rounded-lg px-6 py-3 text-center">
          <div class="text-xs text-purple-400 mb-1">PRESENTATION</div>
          <div class="text-white font-semibold">JobTracker.WPF</div>
          <div class="text-gray-400 text-xs mt-1">XAML Views · ViewModels · Converters · Dark Theme</div>
        </div>
        <div class="text-purple-400 text-xl">↓</div>
        <div class="w-full max-w-lg bg-pink-900/20 border border-pink-700/40 rounded-lg px-6 py-3 text-center">
          <div class="text-xs text-pink-400 mb-1">USE CASES</div>
          <div class="text-white font-semibold">JobTracker.Application</div>
          <div class="text-gray-400 text-xs mt-1">Services · DTOs · Interfaces · SettingsService</div>
        </div>
        <div class="text-purple-400 text-xl">↓</div>
        <div class="w-full max-w-lg bg-blue-900/20 border border-blue-700/40 rounded-lg px-6 py-3 text-center">
          <div class="text-xs text-blue-400 mb-1">DOMAIN</div>
          <div class="text-white font-semibold">JobTracker.Domain</div>
          <div class="text-gray-400 text-xs mt-1">Entities · Enums · Repository Contracts</div>
        </div>
        <div class="text-purple-400 text-xl">↓</div>
        <div class="w-full">
          <div class="text-xs text-gray-400 text-center mb-3">INFRASTRUCTURE — JobTracker.Infrastructure</div>
          <div class="grid grid-cols-3 gap-3 max-w-2xl mx-auto">
            <div class="bg-gray-700/60 border border-gray-600 rounded-lg p-3 text-center">
              <div class="text-green-400 text-lg mb-1">🗄️</div>
              <div class="text-white text-xs font-semibold">SQLite + Dapper</div>
              <div class="text-gray-400 text-xs">Repositories</div>
            </div>
            <div class="bg-gray-700/60 border border-gray-600 rounded-lg p-3 text-center">
              <div class="text-pink-400 text-lg mb-1">🗒️</div>
              <div class="text-white text-xs font-semibold">Markdown Sync</div>
              <div class="text-gray-400 text-xs">Obsidian vault</div>
            </div>
            <div class="bg-gray-700/60 border border-gray-600 rounded-lg p-3 text-center">
              <div class="text-blue-400 text-lg mb-1">📄</div>
              <div class="text-white text-xs font-semibold">PDF Extraction</div>
              <div class="text-gray-400 text-xs">Job postings</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Obsidian Sync Example -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Obsidian Markdown Sync</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-8">
      <!-- Markdown example -->
      <div>
        <div class="flex items-center space-x-2 mb-3">
          <span class="bg-purple-600/20 text-purple-400 border border-purple-600/30 px-3 py-1 rounded-full text-xs font-semibold">SYNCED NOTE</span>
          <span class="text-gray-500 text-xs">One .md file per application</span>
        </div>
        <div class="rounded-xl overflow-hidden border border-gray-700">
          <div class="bg-gray-800 px-4 py-2 flex items-center space-x-2 border-b border-gray-700">
            <div class="w-2 h-2 rounded-full bg-red-500"></div>
            <div class="w-2 h-2 rounded-full bg-yellow-500"></div>
            <div class="w-2 h-2 rounded-full bg-green-500"></div>
            <span class="ml-2 text-gray-400 text-xs">2025-04-02_KPMG_IT-Infrastructure.md</span>
          </div>
          <pre class="bg-gray-950 p-4 text-xs font-mono overflow-x-auto text-gray-300"><code><span class="text-gray-500">---</span>
<span class="text-blue-400">tags:</span> <span class="text-green-400">[job-application, applied, 2025]</span>
<span class="text-blue-400">status:</span> <span class="text-green-400">Applied</span>
<span class="text-blue-400">company:</span> <span class="text-green-400">"KPMG Ireland"</span>
<span class="text-blue-400">role:</span> <span class="text-green-400">"IT Infrastructure Specialist"</span>
<span class="text-blue-400">applied_date:</span> <span class="text-orange-400">2025-04-02</span>
<span class="text-gray-500">---</span>

<span class="text-purple-400"># Job Application — IT Infrastructure</span>

<span class="text-purple-400">## Skills Required</span>
<span class="text-gray-300">- Azure ✅</span>
<span class="text-gray-300">- PowerShell ✅</span>
<span class="text-gray-300">- SIEM</span>
<span class="text-gray-300">- Defender XDR</span>

<span class="text-purple-400">## User Notes</span>
<span class="text-gray-500">&lt;!-- USER_NOTES_START --&gt;</span>
<span class="text-yellow-400">My notes survive every re-sync</span>
<span class="text-gray-500">&lt;!-- USER_NOTES_END --&gt;</span></code></pre>
        </div>
      </div>
      <!-- Sync features -->
      <div>
        <div class="flex items-center space-x-2 mb-3">
          <span class="bg-pink-600/20 text-pink-400 border border-pink-600/30 px-3 py-1 rounded-full text-xs font-semibold">HOW SYNC WORKS</span>
        </div>
        <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-6 space-y-4">
          <div class="flex items-start space-x-3">
            <div class="w-8 h-8 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold text-sm flex-shrink-0">1</div>
            <div>
              <div class="text-white font-semibold text-sm">Point at your vault</div>
              <div class="text-gray-400 text-sm">Settings → Browse → select your Obsidian vault root folder.</div>
            </div>
          </div>
          <div class="flex items-start space-x-3">
            <div class="w-8 h-8 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold text-sm flex-shrink-0">2</div>
            <div>
              <div class="text-white font-semibold text-sm">Auto-generated filenames</div>
              <div class="text-gray-400 text-sm">Notes are written as <code class="text-pink-400 bg-gray-800 px-1 rounded text-xs">YYYY-MM-DD_company_role.md</code> with structured YAML frontmatter.</div>
            </div>
          </div>
          <div class="flex items-start space-x-3">
            <div class="w-8 h-8 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold text-sm flex-shrink-0">3</div>
            <div>
              <div class="text-white font-semibold text-sm">Section-aware merge</div>
              <div class="text-gray-400 text-sm">The sync service rewrites status, timeline, and skills on every change — but the <code class="text-pink-400 bg-gray-800 px-1 rounded text-xs">USER_NOTES</code> markers protect anything you wrote by hand.</div>
            </div>
          </div>
        </div>
        <div class="mt-4 bg-dark-800/60 border border-gray-700 rounded-xl p-4">
          <h4 class="text-white font-semibold mb-2 text-sm">Database Schema</h4>
          <pre class="text-xs font-mono text-gray-400 overflow-x-auto"><code><span class="text-purple-400">Companies</span>        (Id, Name, Website, Industry...)
<span class="text-purple-400">Contacts</span>         (Id, Name, Email, LinkedInUrl...)
<span class="text-purple-400">Skills</span>           (Id, Name, Category)
<span class="text-purple-400">JobApplications</span>  (Id, RoleName, Status, AppliedDate,
                  SalaryRange, IsRemote, CompanyId FK...)
<span class="text-purple-400">ApplicationSkills</span> (JobAppId FK, SkillId FK,
                  IsOwned, IsRequired)</code></pre>
        </div>
      </div>
    </div>
  </section>

  <!-- Tech Stack -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Tech Stack</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-purple-500/40 transition-colors">
        <div class="text-3xl mb-2">💜</div>
        <div class="text-white font-semibold text-sm">C# / .NET 8</div>
        <div class="text-gray-500 text-xs mt-1">Core language</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-purple-500/40 transition-colors">
        <div class="text-3xl mb-2">🖥️</div>
        <div class="text-white font-semibold text-sm">WPF + MVVM</div>
        <div class="text-gray-500 text-xs mt-1">UI framework</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-purple-500/40 transition-colors">
        <div class="text-3xl mb-2">🗄️</div>
        <div class="text-white font-semibold text-sm">SQLite + Dapper</div>
        <div class="text-gray-500 text-xs mt-1">Local database</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-purple-500/40 transition-colors">
        <div class="text-3xl mb-2">🧪</div>
        <div class="text-white font-semibold text-sm">xUnit</div>
        <div class="text-gray-500 text-xs mt-1">Test suite</div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 text-center hover:border-purple-500/40 transition-colors">
        <div class="text-3xl mb-2">🗒️</div>
        <div class="text-white font-semibold text-sm">Obsidian</div>
        <div class="text-gray-500 text-xs mt-1">Markdown sync</div>
      </div>
    </div>
  </section>

  <!-- Roadmap -->
  <section class="mb-20">
    <h2 class="text-3xl font-bold mb-4 text-white">Roadmap</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="grid md:grid-cols-2 gap-4">
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 flex items-start space-x-3">
        <span class="text-xl">📤</span>
        <div>
          <div class="text-white font-semibold text-sm">CSV / Excel Export</div>
          <div class="text-gray-400 text-xs mt-1">Export the full application history for analysis in spreadsheets.</div>
        </div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 flex items-start space-x-3">
        <span class="text-xl">📅</span>
        <div>
          <div class="text-white font-semibold text-sm">Interview Calendar View</div>
          <div class="text-gray-400 text-xs mt-1">Timeline view with urgency indicators for upcoming interviews.</div>
        </div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 flex items-start space-x-3">
        <span class="text-xl">📧</span>
        <div>
          <div class="text-white font-semibold text-sm">Email Parsing</div>
          <div class="text-gray-400 text-xs mt-1">Poll the inbox with MailKit to auto-create draft applications.</div>
        </div>
      </div>
      <div class="bg-dark-800/60 border border-gray-700 rounded-xl p-5 flex items-start space-x-3">
        <span class="text-xl">🤖</span>
        <div>
          <div class="text-white font-semibold text-sm">AI CV Analysis</div>
          <div class="text-gray-400 text-xs mt-1">Match CV text against job descriptions with DPAPI-encrypted API keys.</div>
        </div>
      </div>
    </div>
  </section>

  <!-- Getting Started -->
  <section class="mb-12">
    <h2 class="text-3xl font-bold mb-4 text-white">Getting Started</h2>
    <div class="w-16 h-1 bg-gradient-to-r from-purple-500 to-pink-500 rounded mb-8"></div>
    <div class="rounded-xl overflow-hidden border border-gray-700">
      <div class="bg-gray-800 px-4 py-3 flex items-center space-x-2 border-b border-gray-700">
        <div class="w-3 h-3 rounded-full bg-red-500"></div>
        <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
        <div class="w-3 h-3 rounded-full bg-green-500"></div>
        <span class="ml-4 text-gray-400 text-sm font-mono">terminal</span>
      </div>
      <div class="bg-gray-950 p-6 font-mono text-sm space-y-2">
        <div><span class="text-gray-500"># Clone the repository</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">git clone https://github.com/juandresrodca/job-application-tracker.git</span></div>
        <div class="mt-2"><span class="text-gray-500"># Run the app (requires .NET 8 SDK on Windows 10/11)</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">cd src/JobTracker.WPF</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">dotnet run</span></div>
        <div class="mt-2"><span class="text-gray-500"># First run auto-creates the SQLite DB, settings, and 26 IT skills</span></div>
        <div><span class="text-gray-500"># %APPDATA%\JobTracker\jobtracker.db · settings.json</span></div>
        <div class="mt-2"><span class="text-gray-500"># Run the test suite</span></div>
        <div><span class="text-green-400">$</span> <span class="text-white">dotnet test</span></div>
      </div>
    </div>
  </section>

  <!-- CTA -->
  <div class="flex flex-col sm:flex-row gap-4 justify-center">
    <a href="https://github.com/juandresrodca/job-application-tracker" target="_blank" rel="noopener noreferrer"
       class="flex items-center justify-center space-x-2 bg-purple-600 hover:bg-purple-500 text-white font-semibold px-8 py-4 rounded-xl transition-colors">
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
