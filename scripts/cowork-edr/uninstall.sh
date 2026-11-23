#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Uninstall must run as root' >&2; exit 1; }
LIB=/usr/local/lib/kontext-cowork
RUN=/run/kontext-cowork
if [ -d /run/systemd/system ]; then
    systemctl disable --now kontext-cowork.service 2>/dev/null || true
elif [ -f /etc/kontext-cowork/sensor.pid ]; then
    pid=$(cat /etc/kontext-cowork/sensor.pid)
    case "$pid" in ''|*[!0-9]*) ;; *)
        if [ -r "/proc/$pid/cmdline" ] && tr '\000' ' ' < "/proc/$pid/cmdline" | grep -Fq "$LIB/kontext cowork-sensor run"; then
            kill -TERM "$pid" 2>/dev/null || true
            n=0; while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 15 ]; do sleep 1; n=$((n+1)); done
            kill -0 "$pid" 2>/dev/null && { echo 'Sensor is still running; refusing to remove its files' >&2; exit 1; }
        fi;;
    esac
fi
rm -f /etc/claude-code/managed-settings.d/95-kontext-cowork.json /etc/systemd/system/kontext-cowork.service
[ ! -d /run/systemd/system ] || systemctl daemon-reload
rm -rf /etc/kontext-cowork /var/lib/kontext-cowork /run/kontext-cowork /usr/local/lib/kontext-cowork
echo 'Removed the internal Kontext Cowork sensor; revoke its test credential in Kontext'
