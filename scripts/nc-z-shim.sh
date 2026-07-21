#!/usr/bin/env bash
set -euo pipefail

# Fiber's devnet scripts only use `nc -z HOST PORT` as a local readiness
# probe. Keep this fallback deliberately narrower than a general netcat clone.
if [ "$#" -ne 3 ] || [ "$1" != "-z" ]; then
  printf 'usage: nc -z {127.0.0.1|localhost|::1} PORT\n' >&2
  exit 2
fi

host="$2"
port="$3"
case "$host" in
  127.0.0.1 | localhost | ::1) ;;
  *)
    printf 'nc -z shim only permits loopback hosts\n' >&2
    exit 2
    ;;
esac
case "$port" in
  '' | *[!0-9]*)
    printf 'nc -z shim requires a numeric TCP port\n' >&2
    exit 2
    ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  printf 'nc -z shim TCP port is out of range\n' >&2
  exit 2
fi

(exec 3<>"/dev/tcp/$host/$port") 2>/dev/null
