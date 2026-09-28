#!/bin/zsh
# Build coagent-phoned from THIS checkout, reproducibly, and optionally deploy it.
#
#   scripts/coagent/build-phoned.sh            build + verify only (prints the path)
#   scripts/coagent/build-phoned.sh --deploy   build, verify, back up the live binary,
#                                              swap it in, restart the bridge, check /status
#
# Why this exists (2026-09-28): the live ~/Projects/coagent-phone-control/coagent-phoned
# had been built by hand from an uncommitted tree (`go version -m` said
# vcs.modified=true on a commit that did not contain the fix it was running), so
# nobody could say which source it came from or rebuild it. This script refuses a
# dirty tree and an unpushed commit, and the binary carries its own proof: Go
# embeds vcs.revision / vcs.modified, which are checked after the build, and a
# coagent-phoned.build.json record is written next to the deployed binary.
#
# Env: COAGENT_PHONE_DIR (default ~/Projects/coagent-phone-control), GO (default: go on PATH,
# else /opt/homebrew/bin/go), COAGENT_PHONED_REMOTE (default fork), ALLOW_UNPUSHED=1 to skip
# the pushed-commit check (never for a deploy that should be reproducible by others).
set -euo pipefail
DEPLOY=0
[[ "${1:-}" == "--deploy" ]] && DEPLOY=1
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DEST_DIR="${COAGENT_PHONE_DIR:-$HOME/Projects/coagent-phone-control}"
REMOTE="${COAGENT_PHONED_REMOTE:-fork}"
GO="${GO:-$(command -v go 2>/dev/null || echo /opt/homebrew/bin/go)}"
cd "$REPO"

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "refusing: the tree has uncommitted changes; commit them first so the binary names its source" >&2
  exit 2
fi
COMMIT="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${ALLOW_UNPUSHED:-0}" != 1 ]]; then
  git fetch -q "$REMOTE" "$BRANCH" 2>/dev/null || true
  if ! git merge-base --is-ancestor "$COMMIT" "$REMOTE/$BRANCH" 2>/dev/null; then
    echo "refusing: $COMMIT is not on $REMOTE/$BRANCH; push it first (or ALLOW_UNPUSHED=1)" >&2
    exit 3
  fi
fi

OUT_DIR="$(mktemp -d)"
OUT="$OUT_DIR/coagent-phoned"
# Same settings as every earlier build (go version -m of the old binary): cgo on, default flags.
CGO_ENABLED=1 "$GO" build -trimpath -o "$OUT" ./cmd/coagent-phoned
"$GO" test ./cmd/coagent-phoned >/dev/null

INFO="$("$GO" version -m "$OUT")"
REV="$(print -r -- "$INFO" | awk '$2=="vcs.revision"{print $3}' | cut -d= -f2)"
[[ -z "$REV" ]] && REV="$(print -r -- "$INFO" | awk -F= '/vcs.revision=/{print $2}')"
MOD="$(print -r -- "$INFO" | awk -F= '/vcs.modified=/{print $2}')"
if [[ "$REV" != "$COMMIT" || "$MOD" != "false" ]]; then
  echo "refusing: built binary says revision=$REV modified=$MOD, expected $COMMIT / false" >&2
  exit 4
fi
SHA="$(shasum -a 256 "$OUT" | awk '{print $1}')"
GOVER="$("$GO" env GOVERSION)"
echo "built $OUT"
echo "  commit $COMMIT ($BRANCH), $GOVER, sha256 $SHA"
[[ $DEPLOY == 1 ]] || exit 0

LIVE="$DEST_DIR/coagent-phoned"
STAMP="$(date +%Y%m%d-%H%M%S)"
if [[ -f "$LIVE" ]]; then
  cp -p "$LIVE" "$LIVE.bak-$STAMP"
  [[ -f "$DEST_DIR/coagent-phoned.build.json" ]] && cp -p "$DEST_DIR/coagent-phoned.build.json" "$DEST_DIR/coagent-phoned.build.json.bak-$STAMP"
  echo "backup $LIVE.bak-$STAMP"
fi
cp "$OUT" "$LIVE.new.$$"
chmod 755 "$LIVE.new.$$"
mv -f "$LIVE.new.$$" "$LIVE"
cat > "$DEST_DIR/coagent-phoned.build.json" <<JSON
{
  "binary": "coagent-phoned",
  "repo": "$(git remote get-url "$REMOTE" 2>/dev/null || echo unknown)",
  "branch": "$BRANCH",
  "commit": "$COMMIT",
  "go": "$GOVER",
  "sha256": "$SHA",
  "builtAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rollback": "$LIVE.bak-$STAMP",
  "builtBy": "scripts/coagent/build-phoned.sh"
}
JSON
echo "deployed $LIVE (record: $DEST_DIR/coagent-phoned.build.json)"

# Restart on whichever road is live: the bridge script owns the process and finds it by command line.
cd "$DEST_DIR"
ROAD="$(./phone-bridge.sh transport 2>/dev/null || true)"
case "$ROAD" in
  usb) START=start-usb ;;
  lan) START=start-lan ;;
  tunnel) START=start-tunnel ;;
  wireless) START=start-wireless ;;
  *) START=start-auto ;;
esac
./phone-bridge.sh stop >/dev/null 2>&1 || true
./phone-bridge.sh "$START" || { echo "bridge did not come back on $START; roll back with: cp -p $LIVE.bak-$STAMP $LIVE && ./phone-bridge.sh $START" >&2; exit 5; }
echo "bridge restarted ($START)"
