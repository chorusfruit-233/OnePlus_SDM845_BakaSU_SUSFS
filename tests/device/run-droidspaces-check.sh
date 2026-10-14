#!/system/bin/sh
# Run the selected backend directly instead of forwarding to an older daemon.
set -eu

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [path-to-droidspaces-v7-backend]" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo 'Droidspaces runtime checks require root on the target device.' >&2
    exit 2
fi
binary=${1:-/data/local/Droidspaces/bin/droidspaces}
if [ ! -x "$binary" ]; then
    echo "Droidspaces backend is not executable: $binary" >&2
    exit 2
fi
export DS_NO_PROXY=1
exec "$binary" --format check
