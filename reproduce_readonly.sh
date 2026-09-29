#!/bin/zsh
set -eu
set -o pipefail
export LC_ALL=C
export LANG=C

REPORT_DIR="${0:A:h}"
TOOLS_DIR="$REPORT_DIR/tools"
OUT_DIR="${1:-$REPORT_DIR/reproduction-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/session.log"

run() {
    print -r -- "$ $*" | tee -a "$LOG"
    "$@" 2>&1 | tee -a "$LOG"
    print -r -- "" | tee -a "$LOG"
}

print -r -- "CyberSafe read-only reproduction" | tee "$LOG"
print -r -- "UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOG"
print -r -- "PIN was not entered. Flash writes: none." | tee -a "$LOG"
print -r -- "ZIP contents are not opened or extracted." | tee -a "$LOG"
print -r -- "" | tee -a "$LOG"

run system_profiler SPUSBDataType
if [[ -f /Volumes/RPI-RP2/INFO_UF2.TXT ]]; then
    run cat /Volumes/RPI-RP2/INFO_UF2.TXT
fi

run python3 "$TOOLS_DIR/read_picoboot.py" "$OUT_DIR/flash.bin" --size 0x200000 --verify
run python3 "$TOOLS_DIR/read_picoboot.py" "$OUT_DIR/pin.bin" --address 0x10005500 --size 4 --verify
run xxd -g 1 "$OUT_DIR/pin.bin"
run python3 "$TOOLS_DIR/read_picoboot.py" "$OUT_DIR/disk-region.bin" --address 0x10100000 --size 0x100000 --verify
run python3 "$TOOLS_DIR/decode_disk_region.py" "$OUT_DIR/disk-region.bin" "$OUT_DIR/disk.img"
run python3 "$TOOLS_DIR/inspect_fat_root.py" "$OUT_DIR/disk.img" --json "$OUT_DIR/fat-root.json"
run fsck_msdos -n "$OUT_DIR/disk.img"
run python3 "$TOOLS_DIR/analyze_firmware.py" "$OUT_DIR/flash.bin" --json "$OUT_DIR/firmware-analysis.json"
run shasum -a 256 "$OUT_DIR/flash.bin" "$OUT_DIR/pin.bin" "$OUT_DIR/disk-region.bin" "$OUT_DIR/disk.img"

print -r -- "Result directory: $OUT_DIR" | tee -a "$LOG"
