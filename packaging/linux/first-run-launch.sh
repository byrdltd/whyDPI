#!/bin/sh
# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT
#
# Called from package post-install hooks (AUR .install, deb postinst,
# rpm %post, install.sh).
#
#   (no args)       Open the tray only in sessions that have not yet
#                   accepted the first-run disclaimer.
#   --restart       Replace the tray in live graphical sessions after
#                   an upgrade (consent already on disk must not skip).
#   --stop-trays    Kill leftover tray processes (pre_remove / pre_upgrade).
#
# Always exits 0 — a missing display or missing tray extras must not
# fail the package transaction.  Login autostart is unchanged (opt-in).

TRAY=/usr/bin/whydpi-tray
CONSENT_REL=".config/whydpi/.disclaimer_accepted_v1"
RESTART=0

stop_trays() {
    pkill -f '/usr/bin/whydpi-tray' >/dev/null 2>&1 || true
    pkill -f 'python.*-m whydpi.ui.tray' >/dev/null 2>&1 || true
}

case "${1:-}" in
    --stop-trays)
        stop_trays
        exit 0
        ;;
    --restart)
        RESTART=1
        ;;
esac

already_running() {
    pgrep -u "$1" -f '/usr/bin/whydpi-tray' >/dev/null 2>&1
}

try_launch() {
    user=$1
    [ -n "$user" ] && [ "$user" != root ] || return 1
    uid=$(id -u "$user" 2>/dev/null) || return 1
    home=$(getent passwd "$user" | cut -d: -f6)
    [ -n "$home" ] || return 1
    if [ "$RESTART" -eq 1 ]; then
        pkill -u "$uid" -f '/usr/bin/whydpi-tray' >/dev/null 2>&1 || true
        pkill -u "$uid" -f 'python.*-m whydpi.ui.tray' >/dev/null 2>&1 || true
    else
        [ -f "$home/$CONSENT_REL" ] && return 1
        already_running "$uid" && return 1
    fi

    runtime=/run/user/$uid
    [ -d "$runtime" ] || return 1

    if command -v systemd-run >/dev/null 2>&1; then
        if systemd-run --quiet --collect --machine="${user}@" --user -- \
            "$TRAY" 2>/dev/null; then
            return 0
        fi
        if systemd-run --quiet --collect --machine="${user}@.host" --user -- \
            "$TRAY" 2>/dev/null; then
            return 0
        fi
        if [ -S "$runtime/bus" ] && command -v runuser >/dev/null 2>&1; then
            if runuser -u "$user" -- env \
                XDG_RUNTIME_DIR="$runtime" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
                systemd-run --user --quiet --collect -- "$TRAY" 2>/dev/null; then
                return 0
            fi
        fi
    fi

    wayland=
    if [ -S "$runtime/wayland-1" ]; then
        wayland=wayland-1
    elif [ -S "$runtime/wayland-0" ]; then
        wayland=wayland-0
    fi

    set_env="XDG_RUNTIME_DIR=$runtime"
    [ -S "$runtime/bus" ] && set_env="$set_env DBUS_SESSION_BUS_ADDRESS=unix:path=$runtime/bus"
    if [ -n "$wayland" ]; then
        set_env="$set_env WAYLAND_DISPLAY=$wayland XDG_SESSION_TYPE=wayland"
    else
        set_env="$set_env DISPLAY=${DISPLAY:-:0}"
    fi

    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- env $set_env "$TRAY" >/dev/null 2>&1 &
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        sudo -u "$user" env $set_env "$TRAY" >/dev/null 2>&1 &
        return 0
    fi
    return 1
}

[ -x "$TRAY" ] || exit 0

users=""
add_user() {
    u=$1
    [ -n "$u" ] && [ "$u" != root ] || return 0
    case " $users " in
        *" $u "*) return 0 ;;
    esac
    users="$users $u"
}

add_user "${SUDO_USER-}"
if [ -n "${PKEXEC_UID-}" ]; then
    add_user "$(id -nu "$PKEXEC_UID" 2>/dev/null || true)"
fi

if command -v loginctl >/dev/null 2>&1; then
    sids=$(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
    for sid in $sids; do
        [ -n "$sid" ] || continue
        suser=$(loginctl show-session "$sid" -p Name --value 2>/dev/null || true)
        stype=$(loginctl show-session "$sid" -p Type --value 2>/dev/null || true)
        sstate=$(loginctl show-session "$sid" -p State --value 2>/dev/null || true)
        case "$sstate" in
            active|online) ;;
            *) continue ;;
        esac
        case "$stype" in
            wayland|x11|mir|unspecified) ;;
            *) continue ;;
        esac
        add_user "$suser"
    done
fi

launched=0
for user in $users; do
    if try_launch "$user"; then
        launched=1
        if [ "$RESTART" -eq 1 ]; then
            echo "whyDPI: restarted tray for $user"
        else
            echo "whyDPI: opened first-run dialog for $user"
        fi
    fi
done

[ "$launched" -eq 1 ] || true
exit 0
