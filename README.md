# Weekly Vulnerability Report

Automated weekly HTML report covering CVEs and security advisories for:
- 🐧 **Linux** (kernel, RHEL, CoreOS)
- ☸️ **Kubernetes**
- 🔴 **OpenShift**

## Sources

| Source | What it covers |
|--------|----------------|
| [NVD](https://nvd.nist.gov) | All CVEs, CVSS scores |
| [Kubernetes CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/) | Official k8s CVEs |
| [Red Hat RHSA](https://access.redhat.com/security/security-updates) | RHEL & OpenShift advisories |

## Setup (< 5 minutes)

### 1. Create the repository

```bash
git init vuln-report
cd vuln-report
# Copy all files from this project into the folder
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/vuln-report.git
git push -u origin main
```

### 2. Enable GitHub Pages

1. Go to your repo → **Settings → Pages**
2. Set **Source** to `Deploy from a branch`
3. Set **Branch** to `gh-pages` / `/ (root)`
4. Save

Your report will be live at:
`https://YOUR_USERNAME.github.io/vuln-report/`

### 3. Run it manually (first time)

Go to **Actions → Weekly Vulnerability Report → Run workflow**

The workflow will:
1. Fetch CVEs from NVD, Kubernetes, and Red Hat
2. Generate `reports/index.html`
3. Push to `gh-pages` branch (your live dashboard)
4. Archive a downloadable ZIP artifact

### 4. Automatic schedule

The workflow runs **every Monday at 07:00 UTC** automatically.
To change the schedule, edit `.github/workflows/vuln-report.yml`:

```yaml
- cron: "0 7 * * 1"   # Mon 07:00 UTC
```

## Project structure

```
.
├── .github/
│   └── workflows/
│       └── vuln-report.yml    # GitHub Actions workflow
├── scripts/
│   ├── fetch_vulns.py         # Fetches CVEs → reports/vulns.json
│   └── generate_report.py     # Renders HTML → reports/index.html
├── reports/                   # Auto-created, gitignored locally
└── README.md
```

## Customisation

**Change the lookback window** (default: 7 days):
Edit `DAYS_BACK` in `scripts/fetch_vulns.py`.

**Add more keywords**:
Edit the `KEYWORDS` dict in `fetch_vulns.py`.

**Filter by severity**:
The HTML report has built-in interactive filters — click any severity badge or category icon.

## Local development

```bash
python scripts/fetch_vulns.py     # writes reports/vulns.json
python scripts/generate_report.py # writes reports/index.html
open reports/index.html
```

No external dependencies — uses Python stdlib only.
