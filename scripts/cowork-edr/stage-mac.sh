#!/bin/sh
# Stage an already verified internal test package; run with sudo on the host.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'Run on the Mac host' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Run with sudo to protect the package path' >&2; exit 1; }
[ "$#" = 1 ] || { echo 'Usage: stage-mac.sh /absolute/path/package.tar.gz' >&2; exit 1; }
archive=$1
case "$archive" in /*) ;; *) echo 'Archive path must be absolute' >&2; exit 1;; esac
[ -f "$archive" ] && [ -f "$archive.sig" ] || { echo 'Archive and signature are required' >&2; exit 1; }
destination='/Library/Application Support/KontextCoworkEDR'
for path in / /Library '/Library/Application Support' "$destination"; do
    [ ! -L "$path" ] || { echo "Refusing symlink: $path" >&2; exit 1; }
    [ ! -e "$path" ] && continue
    [ "$(stat -f %u "$path")" = 0 ] || { echo "Path must be root-owned: $path" >&2; exit 1; }
    mode=$(stat -f %Lp "$path")
    [ "$((0$mode & 0022))" = 0 ] || { echo "Path is writable by non-root: $path" >&2; exit 1; }
done
install -d -o root -g admin -m 0750 "$destination"
for file in kontext-cowork-internal.tar.gz kontext-cowork-internal.tar.gz.sig; do
    [ ! -L "$destination/$file" ] || { echo 'Refusing package symlink' >&2; exit 1; }
done
# Admin-only readability permits Claude to copy the internal credential-bearing
# archive while ordinary non-admin users cannot inspect its test credential.
install -o root -g admin -m 0640 "$archive" "$destination/kontext-cowork-internal.tar.gz"
install -o root -g admin -m 0640 "$archive.sig" "$destination/kontext-cowork-internal.tar.gz.sig"
echo 'Staged the internal package. Install the system profile, restart Claude, and start a local Cowork session.'
