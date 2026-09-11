# repo-exposure-check

A zero-dependency shell script that walks the public file tree of any GitHub repository and flags paths whose names match patterns commonly associated with leaked credentials, secrets, keys, database dumps, and sensitive configuration files.

**It reads file paths only — never file contents.** It makes no determination about whether any file actually contains a secret.

## How to run

```bash
curl -O https://raw.githubusercontent.com/harvst-online/repo-exposure-check/main/check.sh && chmod +x check.sh
./check.sh owner/repository
```

Replace `owner/repository` with the GitHub user and repo name, e.g. `./check.sh torvalds/linux`.

No packages, no npm, no pip, no gems. Requires only `bash` and `curl`, which ship with macOS and every major Linux distribution.

## What it does

- Calls the GitHub Trees API (`/git/trees/{sha}?recursive=1`) to retrieve the full file path list for the default branch
- Matches each path against a set of pattern groups:
  - Environment files: `.env`, `.env.local`, `.env.production`, etc.
  - Key and certificate files: `*.pem`, `id_rsa*`, `*.p12`, `*.jks`, `*.key`
  - Credential-shaped names: `credentials.json`, `serviceAccount*.json`, `secrets.*`, `*.secret`
  - Database dumps and backups: `*.sql`, `*.dump`, `*.bak`
  - Config files that commonly carry tokens: `.npmrc`, `.pypirc`, `.netrc`, `wp-config.php`
  - CI and deploy files that expose pipeline secrets: `.travis.yml`, `Jenkinsfile`, `*.github/workflows/*.yml`, `Dockerfile`, `docker-compose*.yml`
- Prints each matching path with one plain-English line explaining why that file pattern is a risk
- Exits with code `0` (no matches) or `1` (matches found) so it can be used in CI

## What it does NOT do

- It **never downloads or reads file contents** — it works on the path list only
- It does **not** confirm that any file contains an actual secret
- It does **not** access private repositories (no auth token is used)
- It does **not** submit, store, or transmit findings anywhere
- It does **not** fix anything

## Want a full report with fixes?

**Public Repo Exposure Check — $49**
A human-reviewed report of every flagged path, what the exposure means, and the exact steps to remove it from history and rotate affected credentials.

https://harvst.online/mind-breached-check-audit-20260911-2118

