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

# Phishing Detection Simulator

## Project Overview

A lightweight Python command-line tool that replicates the core decision-making process of a SOC analyst reviewing suspicious emails. The tool reads raw email text, runs it through a suite of detection modules, assigns a risk score from 0–100, and exports machine-readable reports — all from the terminal.

## Key Features

### Keyword Detection
Scans email body for phishing vocabulary, urgency language, and social engineering phrases commonly used to manipulate recipients.

### Domain Analysis
Flags suspicious Top-Level Domains (TLDs), typosquatted domains, IP-based URLs, and sender spoofing patterns that indicate fraudulent origins.

### Attachment Scanning
Classifies file attachments across four risk tiers — from high-risk executables to low-risk documents — giving analysts a quick surface-area view.

### Risk Scoring Engine
Each detection module contributes a weighted score, aggregated into a final **0–100 risk rating** with a clear **LOW / MEDIUM / HIGH** classification for rapid triage.

### Structured Report Export
Generates both **JSON** (machine-readable, API-ready) and **CSV** (spreadsheet-friendly) reports for integration with SIEM tools or incident documentation.

### Terminal UI
ANSI-colored output provides fast, human-readable review directly in the terminal — no GUI required.

## Tech Stack

| Technology | Usage |
|---|---|
| Python 3.12+ | Core language |
| argparse | CLI framework |
| pytest | 20+ unit & integration tests |
| JSON / CSV | Report export formats |
| Rotating file logs | Audit trail & debugging |

## Architecture

The project follows a clean modular design with separate components for keyword analysis, domain inspection, attachment classification, and scoring — keeping each detection layer independently testable and extensible.

## Getting Started

Visit the [GitHub repository](https://github.com/juandresrodca/Phishing-Detection-Sim) to clone the project, review the documentation, and run the simulator against sample phishing emails.

---

**Language**: Python 3.12+  
**License**: MIT  
**Status**: Active Development
