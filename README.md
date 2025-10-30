# GitHub SBOM Fetcher

Fetches Dependency Graph SBOMs for all repositories accessible by one or more GitHub accounts and saves them locally.

## Features
- Multi-account support via a single `key.json` (or single-account format).
- Lists all accessible repos using `/user/repos` with affiliation.
- Saves SBOM JSON as `owner-repo-sbom.json`.
- Handles rate limits and common SBOM response cases (200 saved, 202/403/404 skipped).
- Optional archived repos inclusion.
- VS Code run/debug and testing integration (pytest).

## Requirements
- Python 3.9+
- A GitHub Personal Access Token (PAT) for each account you want to use.
  - Classic PAT: include `repo` for private repos.
  - Fine-grained PAT: Repository permissions — Contents (Read) and Dependency graph (Read); grant access to target repos.

## Install
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# (optional for tests)
pip install -r requirements-dev.txt
```

## Configure credentials (DO NOT COMMIT SECRETS)
Two supported formats for `key.json`:

Single-account:
```json
{ "username": "your-user", "token": "ghp_..." }
```

Multi-account:
```json
{
  "accounts": [
    { "username": "acct1", "token": "ghp_..." },
    { "username": "acct2", "token": "ghp_..." }
  ]
}
```

Use `key.sample.json` in this repo as a template. Ensure `key.json` is in `.gitignore`.

## Usage
Save SBOMs for all accounts in `key.json`:
```bash
python fetch_sbom.py --key-file key.json --output-dir sboms
```

Only for a specific account (by username/login):
```bash
python fetch_sbom.py --key-file key.json --account acct2 --output-dir sboms
```

Include archived repos:
```bash
python fetch_sbom.py --key-file key.json --include-archived --output-dir sboms
```

Output files: `owner-repo-sbom.json` inside the chosen output dir.

## VS Code
- Run/Debug: use the provided `.vscode/launch.json` ("Run fetch_sbom.py").
- Testing panel: pytest is enabled via `.vscode/settings.json` and `pytest.ini`.

## Testing
```bash
# optional dev deps
pip install -r requirements-dev.txt
# run tests
pytest -q
# with coverage
pytest --cov=fetch_sbom --cov-report=term-missing
```

The tests stub network calls; no real GitHub traffic is generated.

## Troubleshooting
- 401/403 on token validation: token scope or repo access missing.
- 422 listing error: we avoid incompatible `type` with `affiliation` (fixed). If you still see 422, check inputs.
- Skipped repos: SBOM 202 (not ready) or Dependency Graph disabled.
- Rate limits: script sleeps until reset when needed.

## Security
- `key.json` contains secrets. Do not commit it. Use `key.sample.json` as a template.
- Consider using a secrets manager for long-term storage and rotating tokens regularly.

## Repository setup (publishing under tedg-dev)
1) Initialize git and create first commit (do NOT add `key.json`):
```bash
git init
python -m venv venv  # optional if not created yet
echo ""  # no-op placeholder
# Add everything, then unstage secrets just in case
git add .
# ensure key.json and sboms are ignored; see .gitignore
git reset key.json || true

git commit -m "Initial commit: GitHub SBOM fetcher"
```

2) Create public GitHub repo under the tedg-dev account (choose one):
- Using GitHub CLI (recommended):
```bash
# requires https://cli.github.com/ and gh auth login
# ensure you are authenticated as tedg-dev (gh auth status)
gh repo create tedg-dev/fetch-sbom \
  --public \
  --source=. \
  --remote=origin \
  --push
```
- Or create a public repo owned by tedg-dev at https://github.com/new named `fetch-sbom`, then:
```bash
git branch -M main
git remote add origin git@github.com:tedg-dev/fetch-sbom.git  # or https URL
git push -u origin main
```

## License
MIT
