import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

import fetch_sbom as mod


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        json_data: Any = None,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
    ):
        self.status_code = status_code
        self._json = json_data
        self.text = text or (json.dumps(json_data) if json_data is not None else "")
        self.headers = headers or {}

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.headers: Dict[str, str] = {}

    def get(self, url: str, params: Optional[Dict[str, str]] = None, timeout: int = 60):
        return self.handler(url, params or {})


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_: None)


def write_key(tmp_path, token: str = "tkn", username: Optional[str] = "user") -> str:
    path = tmp_path / "key.json"
    data = {"token": token}
    if username:
        data["username"] = username
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def write_multi_key(tmp_path, accounts: List[Tuple[str, str]]) -> str:
    path = tmp_path / "key.json"
    data = {"accounts": [{"username": u, "token": t} for u, t in accounts]}
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_load_credentials_ok(tmp_path):
    key_path = write_key(tmp_path, token="abc", username="me")
    username, token = mod._load_credentials(key_path)
    assert username == "me"
    assert token == "abc"


def test_load_credentials_missing_file():
    with pytest.raises(FileNotFoundError):
        mod._load_credentials("does_not_exist.json")


def test_load_credentials_missing_token(tmp_path):
    p = tmp_path / "key.json"
    p.write_text(json.dumps({"username": "me"}), encoding="utf-8")
    with pytest.raises(ValueError):
        mod._load_credentials(str(p))


def test_token_validation_failure(monkeypatch, tmp_path, capsys):
    key_path = write_key(tmp_path, token="bad")

    def handler(url, params):
        if url.endswith("/user"):
            return FakeResponse(401, {"message": "Bad token"})
        raise AssertionError("Unexpected URL")

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handler))
    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "Token validation failed" in captured.err


def test_list_accessible_repos_pagination_and_filter(monkeypatch):
    calls: List[Tuple[str, Dict[str, str]]] = []

    def handler(url, params):
        calls.append((url, params))
        if url.endswith("/user"):
            return FakeResponse(200, {"login": "me"})
        if url.endswith("/user/repos"):
            page = int(params.get("page", 1))
            if page == 1:
                return FakeResponse(
                    200,
                    [
                        {"name": "r1", "owner": {"login": "o1"}, "archived": False},
                        {"name": "r2", "owner": {"login": "o1"}, "archived": True},
                    ],
                )
            else:
                return FakeResponse(200, [])
        return FakeResponse(404)

    s = FakeSession(handler)
    repos = mod._list_accessible_repos(s, include_archived=False)
    assert repos == [("o1", "r1")]
    # Ensure no 'type' param was sent when using affiliation
    for url, params in calls:
        if url.endswith("/user/repos"):
            assert "affiliation" in params
            assert "type" not in params

    # When include_archived=True, both appear
    s2 = FakeSession(handler)
    repos_all = mod._list_accessible_repos(s2, include_archived=True)
    assert ("o1", "r1") in repos_all and ("o1", "r2") in repos_all


def test_list_accessible_repos_422_raises(monkeypatch):
    def handler(url, params):
        if url.endswith("/user/repos"):
            return FakeResponse(
                422,
                {"message": "bad combo"},
                text='{"message":"bad combo"}',
            )
        return FakeResponse(404)

    s = FakeSession(handler)
    with pytest.raises(RuntimeError):
        mod._list_accessible_repos(s, include_archived=False)


def test_get_sbom_variants(monkeypatch):
    def make_session(resp: FakeResponse):
        return FakeSession(lambda url, params: resp)

    # 200
    s = make_session(FakeResponse(200, {"sbom": 1}))
    assert mod._get_sbom(s, "o", "r") == {"sbom": 1}
    # 202
    s = make_session(FakeResponse(202))
    assert mod._get_sbom(s, "o", "r") is None
    # 403
    s = make_session(FakeResponse(403))
    assert mod._get_sbom(s, "o", "r") is None
    # 404
    s = make_session(FakeResponse(404))
    assert mod._get_sbom(s, "o", "r") is None
    # other
    s = make_session(FakeResponse(500, text="err"))
    with pytest.raises(RuntimeError):
        mod._get_sbom(s, "o", "r")


def test_save_writes_file(tmp_path):
    p = mod._save("own", "repo", {"a": 1}, str(tmp_path))
    assert os.path.exists(p)
    assert p.endswith("own-repo-sbom.json")
    data = json.loads(open(p, "r", encoding="utf-8").read())
    assert data == {"a": 1}


def test_load_accounts_single_and_multi(tmp_path):
    # single
    single_path = write_key(tmp_path, token="one", username="u1")
    accounts = mod._load_accounts(single_path)
    assert accounts == [("u1", "one")]
    # multi
    multi_path = write_multi_key(tmp_path, [("u1", "t1"), ("u2", "t2")])
    accounts = mod._load_accounts(multi_path)
    assert ("u1", "t1") in accounts and ("u2", "t2") in accounts


def test_get_rate_limit_handling(monkeypatch):
    calls = {"count": 0}

    def handler(url, params):
        if url.endswith("/something"):
            calls["count"] += 1
            if calls["count"] == 1:
                headers = {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time())),
                }
                return FakeResponse(403, {"message": "rate"}, headers=headers)
            return FakeResponse(200, {"ok": True})
        return FakeResponse(404)

    s = FakeSession(handler)
    resp = mod._get(s, f"{mod.GITHUB_API}/something")
    assert resp.status_code == 200
    assert calls["count"] == 2


def test_main_end_to_end_success(monkeypatch, tmp_path):
    key_path = write_key(tmp_path, token="good", username="me")

    def handler(url, params):
        if url.endswith("/user"):
            return FakeResponse(200, {"login": "me"})
        if url.endswith("/user/repos"):
            return FakeResponse(
                200,
                [{"name": "r1", "owner": {"login": "o1"}, "archived": False}],
            )
        if "/repos/o1/r1/dependency-graph/sbom" in url:
            return FakeResponse(200, {"sbom": 1})
        return FakeResponse(404)

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handler))

    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    assert rc == 0
    files = os.listdir(tmp_path)
    assert any(f.endswith("o1-r1-sbom.json") for f in files)


def test_main_account_filter(monkeypatch, tmp_path):
    key_path = write_multi_key(tmp_path, [("meA", "tokA"), ("meB", "tokB")])

    # Create two sessions sequentially with different behaviors
    def make_handler_user(login_value, repos):
        def handler(url, params):
            if url.endswith("/user"):
                return FakeResponse(200, {"login": login_value})
            if url.endswith("/user/repos"):
                return FakeResponse(200, repos)
            if "/dependency-graph/sbom" in url:
                return FakeResponse(200, {"ok": True})
            return FakeResponse(404)
        return handler

    # Ensure the first created Session corresponds to the filtered account (meB)
    handlers = [
        make_handler_user("meB", [{"name": "rB", "owner": {"login": "oB"}, "archived": False}]),
        make_handler_user("meA", [{"name": "rA", "owner": {"login": "oA"}, "archived": False}]),
    ]

    def session_factory():
        return FakeSession(handlers.pop(0))

    monkeypatch.setattr(mod.requests, "Session", session_factory)
    rc = mod.main(["--key-file", key_path, "--account", "meB", "--output-dir", str(tmp_path)])
    assert rc == 0
    files = os.listdir(tmp_path)
    # Only meB's repo should be saved
    assert any(f.endswith("oB-rB-sbom.json") for f in files)
    assert not any(f.endswith("oA-rA-sbom.json") for f in files)


def test_main_multi_accounts_union_and_dedup(monkeypatch, tmp_path):
    key_path = write_multi_key(tmp_path, [("meA", "tokA"), ("meB", "tokB")])

    sbom_calls = {"count": 0}

    def make_handler(login_value, repos):
        def handler(url, params):
            if url.endswith("/user"):
                return FakeResponse(200, {"login": login_value})
            if url.endswith("/user/repos"):
                return FakeResponse(200, repos)
            if "/dependency-graph/sbom" in url:
                sbom_calls["count"] += 1
                return FakeResponse(200, {"ok": True})
            return FakeResponse(404)
        return handler

    # Both accounts list the same repo; dedup means one SBOM call for it.
    handlers = [
        make_handler("meA", [{"name": "r1", "owner": {"login": "o1"}, "archived": False}]),
        make_handler("meB", [
            {"name": "r1", "owner": {"login": "o1"}, "archived": False},
            {"name": "r2", "owner": {"login": "o2"}, "archived": False},
        ]),
    ]

    def session_factory():
        return FakeSession(handlers.pop(0))

    monkeypatch.setattr(mod.requests, "Session", session_factory)
    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    assert rc == 0
    files = os.listdir(tmp_path)
    # Expect two files: o1-r1 and o2-r2, and SBOM called twice total
    assert any(f.endswith("o1-r1-sbom.json") for f in files)
    assert any(f.endswith("o2-r2-sbom.json") for f in files)
    assert sbom_calls["count"] == 2


def test_main_token_validation_per_account(monkeypatch, tmp_path):
    key_path = write_multi_key(tmp_path, [("bad", "badTok"), ("good", "goodTok")])

    def make_handler(login_value, ok_user):
        def handler(url, params):
            if url.endswith("/user"):
                if ok_user:
                    return FakeResponse(200, {"login": login_value})
                return FakeResponse(401, {"message": "bad token"})
            if url.endswith("/user/repos"):
                return FakeResponse(200, [{"name": "r", "owner": {"login": "o"}, "archived": False}])
            if "/dependency-graph/sbom" in url:
                return FakeResponse(200, {"ok": True})
            return FakeResponse(404)
        return handler

    handlers = [
        make_handler("bad", ok_user=False),
        make_handler("good", ok_user=True),
    ]

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handlers.pop(0)))
    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    assert rc == 0
    files = os.listdir(tmp_path)
    assert any(f.endswith("o-r-sbom.json") for f in files)


def test_main_account_filter_not_found(monkeypatch, tmp_path, capsys):
    key_path = write_multi_key(tmp_path, [("meA", "tokA")])

    def handler(url, params):
        if url.endswith("/user"):
            return FakeResponse(200, {"login": "meA"})
        if url.endswith("/user/repos"):
            return FakeResponse(200, [])
        return FakeResponse(404)

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handler))
    rc = mod.main(["--key-file", key_path, "--account", "nope", "--output-dir", str(tmp_path)])
    assert rc == 2
    assert "No account named 'nope'" in capsys.readouterr().err


def test_main_all_accounts_invalid_tokens(monkeypatch, tmp_path, capsys):
    key_path = write_multi_key(tmp_path, [("u1", "t1"), ("u2", "t2")])

    def handler(url, params):
        if url.endswith("/user"):
            return FakeResponse(401, {"message": "bad"})
        return FakeResponse(404)

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handler))
    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    # All accounts failed token validation; treat as credential error (exit 2)
    assert rc == 2
    assert "No accessible repositories found" in capsys.readouterr().err


def test_main_list_failure_one_account(monkeypatch, tmp_path):
    key_path = write_multi_key(tmp_path, [("a1", "t1"), ("a2", "t2")])

    def make_handler(login_value, ok_list):
        def handler(url, params):
            if url.endswith("/user"):
                return FakeResponse(200, {"login": login_value})
            if url.endswith("/user/repos"):
                if ok_list:
                    return FakeResponse(200, [{"name": "r", "owner": {"login": "o"}, "archived": False}])
                return FakeResponse(422, {"message": "bad"}, text='{"message":"bad"}')
            if "/dependency-graph/sbom" in url:
                return FakeResponse(200, {"ok": True})
            return FakeResponse(404)
        return handler

    handlers = [
        make_handler("a1", ok_list=False),
        make_handler("a2", ok_list=True),
    ]

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handlers.pop(0)))
    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    assert rc == 0
    files = os.listdir(tmp_path)
    assert any(f.endswith("o-r-sbom.json") for f in files)


def test_main_no_repos(monkeypatch, tmp_path, capsys):
    key_path = write_key(tmp_path, token="good", username="me")

    def handler(url, params):
        if url.endswith("/user"):
            return FakeResponse(200, {"login": "me"})
        if url.endswith("/user/repos"):
            return FakeResponse(200, [])
        return FakeResponse(404)

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handler))

    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    assert rc == 1
    assert "No accessible repositories found" in capsys.readouterr().err


def test_main_counts_failures(monkeypatch, tmp_path):
    key_path = write_key(tmp_path, token="good", username="me")

    def handler(url, params):
        if url.endswith("/user"):
            return FakeResponse(200, {"login": "me"})
        if url.endswith("/user/repos"):
            return FakeResponse(
                200,
                [{"name": "r1", "owner": {"login": "o1"}, "archived": False}],
            )
        if "/repos/o1/r1/dependency-graph/sbom" in url:
            return FakeResponse(500, text="boom")
        return FakeResponse(404)

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession(handler))
    rc = mod.main(["--key-file", key_path, "--output-dir", str(tmp_path)])
    assert rc == 1
