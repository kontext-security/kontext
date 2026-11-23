#!/bin/sh
set -eu

LIB=/usr/local/lib/kontext-cowork
ETC=/etc/kontext-cowork
STATE=/var/lib/kontext-cowork
RUN=/run/kontext-cowork
SENSOR_USER=kontext-cowork
HOOKS=/etc/claude-code/managed-settings.d/95-kontext-cowork.json
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

[ "$(id -u)" = 0 ] || { echo 'Cowork sensor installer must run as root' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Run this package inside the Cowork Linux VM' >&2; exit 1; }
case "$(uname -m)" in aarch64|arm64) ;; *) echo 'This internal package is Linux ARM64 only' >&2; exit 1;; esac
for file in kontext config.json test-token hooks.json uninstall.sh kontext-cowork.service; do
    [ -f "$HERE/$file" ] || { echo "Missing package file: $file" >&2; exit 1; }
done

# Replace only our own service and drop-in. Other Claude hooks are preserved.
if [ -d /run/systemd/system ]; then
    systemctl stop kontext-cowork.service 2>/dev/null || true
elif [ -f "$ETC/sensor.pid" ]; then
    pid=$(cat "$ETC/sensor.pid")
    case "$pid" in ''|*[!0-9]*) ;; *)
        if [ -r "/proc/$pid/cmdline" ] && tr '\000' ' ' < "/proc/$pid/cmdline" | grep -Fq "$LIB/kontext cowork-sensor run"; then
            kill -TERM "$pid" 2>/dev/null || true
            n=0; while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 15 ]; do sleep 1; n=$((n+1)); done
            kill -0 "$pid" 2>/dev/null && { echo 'Previous sensor did not stop' >&2; exit 1; }
        fi;;
    esac
fi
if ! id "$SENSOR_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$SENSOR_USER"
fi
install -d -m 0755 "$LIB" /etc/claude-code/managed-settings.d
install -d -m 0750 -o root -g "$SENSOR_USER" "$ETC"
install -d -m 0700 -o "$SENSOR_USER" -g "$SENSOR_USER" "$STATE"
install -d -m 0755 -o "$SENSOR_USER" -g "$SENSOR_USER" "$RUN"
install -m 0755 "$HERE/kontext" "$LIB/kontext"
install -m 0755 "$HERE/uninstall.sh" "$LIB/uninstall.sh"
install -m 0600 -o "$SENSOR_USER" -g "$SENSOR_USER" "$HERE/config.json" "$ETC/config.json"
install -m 0600 -o "$SENSOR_USER" -g "$SENSOR_USER" "$HERE/test-token" "$ETC/test-token"
install -m 0644 "$HERE/hooks.json" "$HOOKS"
rm -f "$RUN/ready.json" "$ETC/sensor.pid"

launcher_pid=
cleanup_failed_install() {
    status=$?
    if [ "$status" -ne 0 ]; then
        if [ -d /run/systemd/system ]; then
            systemctl stop kontext-cowork.service 2>/dev/null || true
        elif [ -n "$launcher_pid" ]; then
            kill -TERM "$launcher_pid" 2>/dev/null || true
        fi
        rm -f "$HOOKS"
    fi
}
trap cleanup_failed_install EXIT

if [ -d /run/systemd/system ]; then
    install -m 0644 "$HERE/kontext-cowork.service" /etc/systemd/system/kontext-cowork.service
    systemctl daemon-reload
    systemctl enable --now kontext-cowork.service
else
    # Cowork images without systemd need a detached process. No shell or SSH
    # access to the VM is needed by the person deploying this package.
    nohup setpriv --reuid "$SENSOR_USER" --regid "$SENSOR_USER" --init-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- env HOME="$STATE" "$LIB/kontext" cowork-sensor run --config "$ETC/config.json" > "$STATE/sensor.log" 2>&1 < /dev/null &
    launcher_pid=$!
fi

n=0
while [ "$n" -lt 30 ]; do
    if [ -f "$RUN/ready.json" ] && "$LIB/kontext" cowork-sensor check >/dev/null 2>&1; then
        sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p' "$RUN/ready.json" > "$ETC/sensor.pid"
        [ -s "$ETC/sensor.pid" ] || { echo 'Sensor did not record its PID' >&2; exit 1; }
        chmod 0644 "$ETC/sensor.pid"
        echo 'Kontext Cowork sensor installed: observe-only; test workspace accepted startup'
        exit 0
    fi
    sleep 1
    n=$((n+1))
done
echo 'Sensor did not start and authenticate within 30 seconds. Installation failed.' >&2
exit 1
