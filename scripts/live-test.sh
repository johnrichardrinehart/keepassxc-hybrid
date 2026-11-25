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
# The entry the registration adds its passkey to.
entry="Example account"
echo "$password" | "$keepassxc/keepassxc-cli" add -q -u alice --url https://example.com \
  "$work/test.kdbx" "$entry"

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
# Registration selects the entry in the main window (search, then Down to the
# first result) and takes "Add to selected entry" (Alt+S); authentication
# takes Authenticate (three Tabs from the credentials table).
answer_dialogs() {
  local passkey_dialogs=0 seen=" " id title main
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
        if ((passkey_dialogs == 1)); then
          main=$(swaymsg -t get_tree | jq -r '.. | objects | select(.name == "test.kdbx - KeePassXC") | .id')
          swaymsg -q "[con_id=$main] focus"
          sleep 0.5
          wtype -M ctrl -k f -m ctrl alice -k Down
          sleep 0.5
          swaymsg -q "[con_id=$id] focus"
          sleep 1
          grim "$shots/passkey-$passkey_dialogs.png"
          wtype -M alt -k s -m alt
        else
          # The main window had focus last; give it back to the dialog.
          swaymsg -q "[con_id=$id] focus"
          sleep 1
          grim "$shots/passkey-$passkey_dialogs.png"
          wtype -k Tab -k Tab -k Tab -k Space
        fi ;;
      *) continue ;;
    esac
    # Keys sometimes reach the dialog while it is inactive and do nothing;
    # answer it again if it is still open.
    sleep 2
    if swaymsg -t get_tree | jq -e ".. | objects | select(.id == $id)" >/dev/null; then
      [[ $title == *Passkey* ]] && passkey_dialogs=$((passkey_dialogs - 1))
      echo "retrying: $title" >&2
      continue
    fi
    seen+="$id "
    echo "answered: $title" >&2
  done
}
answer_dialogs &
pids+=($!)

timeout 60 "$example" "$work/associations.json"

# The passkey went into the selected entry (KeePassXC saves after each change).
relying_party=$(echo "$password" | "$keepassxc/keepassxc-cli" show -q -a KPEX_PASSKEY_RELYING_PARTY \
  "$work/test.kdbx" "$entry")
[[ $relying_party == example.com ]] || { echo "the passkey is not in \"$entry\"" >&2; exit 1; }
echo "passkey stored in \"$entry\""
