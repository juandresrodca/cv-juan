# Personal Portfolio Website

[![Astro](https://img.shields.io/badge/Astro-333333.svg?style=for-the-badge&logo=astro&logoColor=white)](https://astro.build/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

This repository contains the source code for my personal portfolio website, designed to showcase my skills and experience in IT support and cybersecurity. The live version can be accessed at: **[juandresrodca.github.io/cv-juan/](https://juandresrodca.github.io/cv-juan/)**

<!--
**Add a screenshot of your portfolio's homepage here!**
![Portfolio Screenshot](path/to/your/screenshot.png)
-->

## Features

- **Responsive Design:** Fully responsive layout that works on all devices, from mobile to desktop.
- **Project Showcase:** Detailed project pages with write-ups and links to live demos and source code.
- **Interactive Components:** Engaging user experience with animations and interactive elements.
- **Blog/Write-ups:** A dedicated section for cybersecurity write-ups and articles.
- **Contact Form:** A contact section with links to email, LinkedIn, and a downloadable CV.

## Technologies Used

This portfolio is built with a modern tech stack:

- **[Astro](https://docs.astro.build/):** The primary framework for building this fast, content-focused website.
- **[React](https://react.dev/learn):** Used for creating interactive UI components within the Astro ecosystem.
- **[Tailwind CSS](https://tailwindcss.com/docs):** A utility-first CSS framework for rapid and responsive styling.
- **[JavaScript (Vanilla JS)](https://developer.mozilla.org/en-US/docs/Web/JavaScript):** Powers dynamic interactions and animations.
- **[GitHub Pages](https://docs.github.com/en/pages):** Hosts the live version of the portfolio.
- **[GitHub Actions](https://docs.github.com/en/actions):** Automates the build and deployment process.

## Setup and Local Development

To run this project locally, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/juandresrodca/cv-juan.git
    cd cv-juan
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Start the development server:**
    ```bash
    npm run dev
    ```

    The site will be accessible at `http://localhost:4321`.

## Deployment

This project is automatically deployed to GitHub Pages using a GitHub Actions workflow. Any push to the `main` branch will trigger a new build and deployment.

## Weekly Post Automation

`weekly_post.py` fetches the latest cybersecurity news from three RSS feeds
(The Hacker News, Krebs on Security, CISA Alerts), calls the Claude API to
draft a blog post in your voice, writes the Markdown file to
`src/content/blog/`, and pushes to git automatically.

### Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Create your .env file
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 3. Test with a dry run (no files written, no git ops)
python weekly_post.py --dry-run

# 4. Run for real
python weekly_post.py
```

### Scheduling — Linux / macOS (cron)

Open your crontab:

```bash
crontab -e
```

Add a line to run every Friday at 08:00 local time (adjust path as needed):

```cron
0 8 * * 5 cd /path/to/cv-juan && /usr/bin/python3 weekly_post.py >> /tmp/weekly_post.log 2>&1
```

Verify your Python path with `which python3`. To use a virtual environment:

```cron
0 8 * * 5 cd /path/to/cv-juan && /path/to/cv-juan/venv/bin/python weekly_post.py >> /tmp/weekly_post.log 2>&1
```

### Scheduling — Windows (Task Scheduler)

1. Open **Task Scheduler** → **Create Basic Task**.
2. **Name:** `Weekly Cyber Post`
3. **Trigger:** Weekly → Friday → 08:00
4. **Action:** Start a program
   - **Program:** `C:\Path\To\Python\python.exe`
   - **Arguments:** `weekly_post.py`
   - **Start in:** `C:\path\to\cv-juan`
5. On the **Conditions** tab, tick *Start only if the following network
   connection is available* → Any connection.
6. Click Finish.

Alternatively, create the task from PowerShell (run as Administrator):

```powershell
$action = New-ScheduledTaskAction `
    -Execute "python.exe" `
    -Argument "weekly_post.py" `
    -WorkingDirectory "C:\path\to\cv-juan"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At "08:00"

Register-ScheduledTask `
    -TaskName "WeeklyCyberPost" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest
```

### Notes

- The generated post is saved to
  `src/content/blog/YYYY-MM-DD-weekly-cyber-news.md`.
- If a post for today's date already exists, `git add` will simply update it.
- Keep `.env` out of git — it is already listed in `.gitignore`
  (add it if not present).

---

## Contact

If you have any questions or would like to get in touch, you can reach me on [LinkedIn](https://www.linkedin.com/in/juan-andres-rodriguez-itil).

**Author:** Juan Rodriguez
