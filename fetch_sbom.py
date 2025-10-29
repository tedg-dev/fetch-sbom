import argparse
import os
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple

import requests
import json

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"


def _headers(token: Optional[str]) -> Dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "sbom-fetcher",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _handle_rate_limit(resp: requests.Response) -> None:
    if resp.status_code != 403:
        return
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset is not None:
        try:
            reset_ts = int(reset)
            sleep_s = max(0, reset_ts - int(time.time()) + 1)
            time.sleep(sleep_s)
        except ValueError:
            pass


def _get(session: requests.Session, url: str, params: Optional[Dict[str, str]] = None) -> requests.Response:
    while True:
        resp = session.get(url, params=params, timeout=60)
        if resp.status_code == 403:
            _handle_rate_limit(resp)
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                continue
        return resp


def _list_accessible_repos(session: requests.Session, include_archived: bool) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    page = 1
    # affiliation covers repos the user can access: owner, collaborator, org member
    while True:
        url = f"{GITHUB_API}/user/repos"
        # When using 'affiliation', the GitHub API forbids also specifying 'type'.
        params = {
            "per_page": "100",
            "page": str(page),
            "sort": "full_name",
            "direction": "asc",
            "affiliation": "owner,collaborator,organization_member",
        }
        resp = _get(session, url, params=params)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to list accessible repos: {resp.status_code} {resp.text}")
        items = resp.json()
        for r in items:
            if not include_archived and r.get("archived"):
                continue
            owner = r.get("owner", {}).get("login")
            repo = r.get("name")
            if owner and repo:
                results.append((owner, repo))
        link = resp.headers.get("Link", "")
        has_next = 'rel="next"' in link
        if not items or not has_next:
            break
        page += 1
    return results


def _list_repos(session: requests.Session, kind: str, name: str, include_archived: bool) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    page = 1
    while True:
        if kind == "user":
            url = f"{GITHUB_API}/users/{name}/repos"
        else:
            url = f"{GITHUB_API}/orgs/{name}/repos"
        params = {"per_page": "100", "page": str(page), "type": "all", "sort": "full_name", "direction": "asc"}
        resp = _get(session, url, params=params)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to list repos for {kind} '{name}': {resp.status_code} {resp.text}")
        items = resp.json()
        if not items:
            break
        for r in items:
            if not include_archived and r.get("archived"):
                continue
            owner = r.get("owner", {}).get("login")
            repo = r.get("name")
            if owner and repo:
                results.append((owner, repo))
        page += 1
    return results


def _get_sbom(session: requests.Session, owner: str, repo: str) -> Optional[Dict]:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/dependency-graph/sbom"
    resp = _get(session, url)
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code in (202,):
        return None
    if resp.status_code in (403, 404):
        return None
    raise RuntimeError(f"Failed to fetch SBOM for {owner}/{repo}: {resp.status_code} {resp.text}")


def _save(owner: str, repo: str, data: Dict, outdir: str) -> str:
    filename = f"{owner}-{repo}-sbom.json"
    path = os.path.join(outdir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def _parse_repo_strings(values: Iterable[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for v in values:
        v = v.strip().strip("/")
        if not v:
            continue
        if "/" not in v:
            raise ValueError(f"Repo must be in 'owner/repo' form: {v}")
        owner, repo = v.split("/", 1)
        if not owner or not repo:
            raise ValueError(f"Repo must be in 'owner/repo' form: {v}")
        out.append((owner, repo))
    return out


def _load_accounts(path: str) -> List[Tuple[Optional[str], str]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Credentials file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    accounts: List[Tuple[Optional[str], str]] = []
    if isinstance(data, dict) and "accounts" in data and isinstance(data["accounts"], list):
        for entry in data["accounts"]:
            if not isinstance(entry, dict):
                continue
            username = entry.get("username") or entry.get("login")
            token = entry.get("token") or entry.get("password")
            if not token:
                raise ValueError("Each account must include 'token' (recommended) or 'password' with a GitHub PAT")
            accounts.append((username, str(token)))
    else:
        username = data.get("username") or data.get("login")
        token = data.get("token") or data.get("password")
        if not token:
            raise ValueError("key.json must include 'token' (recommended) or 'password' containing a GitHub Personal Access Token")
        accounts.append((username, str(token)))
    return accounts


def _load_credentials(path: str) -> Tuple[Optional[str], str]:
    # Backward-compatible helper returning the first account
    accounts = _load_accounts(path)
    return accounts[0]


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="fetch_sbom", description="Fetch GitHub Dependency Graph SBOMs and save to files.")
    p.add_argument("--include-archived", action="store_true", help="Include archived repositories")
    p.add_argument("--output-dir", default=".", help="Directory to write files (default: current directory)")
    p.add_argument("--key-file", default="key.json", help="Path to JSON file with either {username, token} or {accounts: [{username, token}, ...]}")
    p.add_argument("--account", default=None, help="Optional username/login to restrict to a single account from key file")
    args = p.parse_args(argv)

    # Load one or more accounts from key.json
    try:
        accounts = _load_accounts(args.key_file)
    except Exception as e:
        print(f"Failed to load credentials: {e}", file=sys.stderr)
        return 2

    # Optional filter to a single account
    if args.account:
        accounts = [(u, t) for (u, t) in accounts if (u or "").lower() == args.account.lower()]
        if not accounts:
            print(f"No account named '{args.account}' found in key file.", file=sys.stderr)
            return 2

    # Iterate each account, validate token, and collect union of repos
    saved_targets: set = set()
    fetch_plan: List[Tuple[requests.Session, Tuple[str, str]]] = []
    any_valid = False
    any_token_error = False

    for username, token in accounts:
        session = requests.Session()
        session.headers.update(_headers(token))
        me = session.get(f"{GITHUB_API}/user", timeout=60)
        if me.status_code != 200:
            print(
                f"Token validation failed for account {username or '<unknown>'}: {me.status_code} {me.text}",
                file=sys.stderr,
            )
            any_token_error = True
            continue
        user_login = (username or me.json().get("login") or "<unknown>")
        print(f"Authenticated as: {user_login}")
        print("Listing accessible repositories...")
        any_valid = True
        try:
            repos = _list_accessible_repos(session, args.include_archived)
        except Exception as e:
            print(f"Failed to list repos for account {user_login}: {e}", file=sys.stderr)
            continue
        for owner, repo in repos:
            key = (owner, repo)
            if key in saved_targets:
                continue
            saved_targets.add(key)
            fetch_plan.append((session, key))

    if not fetch_plan:
        print("No accessible repositories found.", file=sys.stderr)
        # If all failures were due to token validation, treat as credential error
        if any_token_error and not any_valid:
            return 2
        return 1

    os.makedirs(args.output_dir, exist_ok=True)

    ok = 0
    skipped = 0
    failed = 0
    for session, (owner, repo) in fetch_plan:
        try:
            data = _get_sbom(session, owner, repo)
            if not data:
                skipped += 1
                continue
            _save(owner, repo, data, args.output_dir)
            ok += 1
        except Exception as e:
            failed += 1
            print(f"Error processing {owner}/{repo}: {e}", file=sys.stderr)
    print(f"Completed. Saved: {ok}, skipped (not available): {skipped}, failed: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
