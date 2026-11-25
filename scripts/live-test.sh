#!/usr/bin/env bash
# Runs examples/live_keepassxc against a throwaway KeePassXC (this flake's
# patched build) and database inside a headless sway, answering KeePassXC's
# dialogs with keystrokes. Run from the repository root in `nix develop`.
#
# Screenshots of each dialog land in $KEEP (default: a temporary directory)
# for inspection.
set -euo pipefail

repo=$(pwd)
cargo build --quiet --example live_keepassxc
example="$repo/target/debug/examples/live_keepassxc"
# KEEPASSXC=<dir with keepassxc and keepassxc-cli> tests another build, e.g. an
# unpatched one, against which registration works and sign-in is refused.
keepassxc=${KEEPASSXC:-$(nix build --no-link --print-out-paths "$repo#keepassxc^out")/bin}

work=$(mktemp -d)
shots=${KEEP:-$work/shots}
mkdir -p "$shots"
pids=()
cleanup() {
  [[ -n ${KEEP:-} && -n ${WAYLAND_DISPLAY:-} ]] && grim "$shots/final.png" 2>/dev/null
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n ${KEEP:-} ]] || rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# Nothing below touches the real session, KeePassXC or configuration.
export HOME=$work/home XDG_CONFIG_HOME=$work/config XDG_DATA_HOME=$work/data \
  XDG_CACHE_HOME=$work/cache XDG_RUNTIME_DIR=$work/run TMPDIR=$work/tmp
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$TMPDIR"
mkdir -m 700 "$XDG_RUNTIME_DIR"
unset WAYLAND_DISPLAY DISPLAY SWAYSOCK DBUS_SESSION_BUS_ADDRESS

password=live-test
printf '%s\n%s\n' "$password" "$password" |
  "$keepassxc/keepassxc-cli" db-create --set-password "$work/test.kdbx" >/dev/null 2>&1

cat >"$work/keepassxc.ini" <<EOF
[General]
ConfigVersion=2
SingleInstance=false

[Browser]
Enabled=true
EOF

cat >"$work/sway.conf" <<EOF
output HEADLESS-1 resolution 1280x800
EOF

WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman \
  sway -c "$work/sway.conf" >"$work/sway.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do
  WAYLAND_DISPLAY=$(cd "$XDG_RUNTIME_DIR" && ls wayland-? 2>/dev/null | head -1) || true
  SWAYSOCK=$(ls "$XDG_RUNTIME_DIR"/sway-ipc.*.sock 2>/dev/null | head -1) || true
  [[ -n $WAYLAND_DISPLAY && -n $SWAYSOCK ]] && break
  sleep 0.1
done
export WAYLAND_DISPLAY SWAYSOCK QT_QPA_PLATFORM=wayland

echo "$password" | dbus-run-session -- "$keepassxc/keepassxc" \
  --config "$work/keepassxc.ini" --localconfig "$work/keepassxc-local.ini" \
  --pw-stdin "$work/test.kdbx" >"$work/keepassxc.log" 2>&1 &
pids+=($!)
focused() {
  swaymsg -t get_tree | jq -r '.. | objects | select(.focused == true) | "\(.id) \(.name // "")"'
}
focused_title() { focused | cut -d' ' -f2-; }

# The browser socket opens before --pw-stdin has unlocked the database; a
# request in between would make KeePassXC pop up its own unlock dialog.
unlocked() { [[ -S $socket && $(focused_title) == "test.kdbx - KeePassXC" ]]; }
socket=$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer
for _ in $(seq 100); do unlocked && break; sleep 0.1; done
unlocked || { cat "$work/keepassxc.log"; echo "KeePassXC did not unlock the database and open its browser socket" >&2; exit 1; }

# Answer each KeePassXC dialog once, after it has had time to take keyboard
# focus (keys sent earlier land on another widget), with a single wtype call
# (Qt deactivates the window when a call's virtual keyboard goes away). The
# example asks for an association, a registration, then an authentication.
# Registration takes "Add to existing entry" (two Tabs from Cancel), then
# Register in the entry picker (four Tabs from its Group box), which creates
# a new entry; authentication takes Authenticate (three Tabs from the
# credentials table).
answer_dialogs() {
  local passkey_dialogs=0 seen=" " id title
  while sleep 0.5; do
    read -r id title < <(focused)
    [[ $seen == *" $id "* ]] && continue
    case $title in
      *"New key association request"*)
        sleep 1.5
        grim "$shots/associate.png"
        wtype keepassxc-hybrid-live-test -k Return ;;
      *"Passkey"*)
        sleep 1.5
        passkey_dialogs=$((passkey_dialogs + 1))
        grim "$shots/passkey-$passkey_dialogs.png"
        case $passkey_dialogs in
          1) wtype -k Tab -k Tab -k Return ;;
          2) wtype -k Tab -k Tab -k Tab -k Tab -k Return ;;
          *) wtype -k Tab -k Tab -k Tab -k Space ;;
        esac ;;
      *) continue ;;
    esac
    seen+="$id "
    echo "answered: $title" >&2
  done
}
answer_dialogs &
pids+=($!)

timeout 60 "$example" "$work/associations.json"
