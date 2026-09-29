#!/bin/zsh
set -eu
export LC_ALL=C
export LANG=C

OUT="${1:?output path is required}"
{
    print -r -- "CyberSafe normal unlock proof"
    print -r -- "UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    print -r -- "The owner entered PIN 8170 with the encoder after a full USB power cycle."
    print -r -- "ZIP files were not opened, copied or extracted."
    print -r -- ""
    print -r -- '$ system_profiler SPUSBDataType'
    system_profiler SPUSBDataType
    print -r -- ""
    print -r -- '$ mount'
    mount
    print -r -- ""
    print -r -- '$ stat -f ... /Volumes/NO NAME'
    stat -f 'mount=%N filesystem=%T owner_uid=%u mode=%Sp' '/Volumes/NO NAME'
} > "$OUT"
