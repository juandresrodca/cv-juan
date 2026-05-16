---
layout: ../../layouts/Layout.astro
title: DorkCraft
description: Generate advanced Google search operators from plain English — built for OSINT, academic research, and public information discovery.
---

# DorkCraft

## Project Overview
DorkCraft transforms natural language queries into precise Google dork operators. Instead of memorising complex syntax like `filetype:pdf intitle:"linux malware"`, you simply describe what you're looking for and DorkCraft builds the query for you.

**Live site:** https://juandresrodca.github.io/DorkCraft/
**GitHub:** https://github.com/juandresrodca/DorkCraft

## Stack
- **Frontend:** Astro + TypeScript, deployed on GitHub Pages
- **Backend:** FastAPI (Python 3.9+), with a rule-based dork engine
- **CI/CD:** GitHub Actions for automatic deployment

## Key Features
- Plain-English to Google dork conversion
- Support for OSINT, academic, and security research queries
- Backend safety blocklist that rejects harmful query patterns
- Clean extension point for swapping in an LLM (Claude, OpenAI, Gemini)
