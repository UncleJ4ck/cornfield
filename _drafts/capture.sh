#!/usr/bin/env bash
# capture.sh — produce the shedskin blog assets.
# Linux-side components run now. Windows-side components run only when the
# win11 guest has an unlocked desktop session; detected and skipped with a
# clear message otherwise.
#
# Outputs:
#   assets/img/posts/shedskin-measure.png     (Windows terminal, needs unlock)
#   assets/img/posts/shedskin-il-scancontent.png   (Linux-rendered)
#   assets/img/posts/shedskin-amsi-re.png     (Linux-rendered r2)
#   assets/img/posts/shedskin-mimikatz.mp4    (Windows, needs unlock)

set -euo pipefail

BLOG_ROOT="/home/j4kuuu/Desktop/Now/free-time/dev/my-blog"
OUT_DIR="$BLOG_ROOT/assets/img/posts"
WORK="/tmp/shedskin-capture"
mkdir -p "$OUT_DIR" "$WORK"

VIRSH="virsh -c qemu:///system"
GUEST="win11"
LAB="/home/j4kuuu/Desktop/Now/free-time/mws/lab"

say() { printf '[capture] %s\n' "$*"; }

# -----------------------------------------------------------------------------
# 1. Linux-rendered: IL dump of AmsiUtils.ScanContent + Uninitialize
# -----------------------------------------------------------------------------
render_il_png() {
    local title="$1" body_file="$2" out="$3"
    local html="$WORK/${title}.html"
    python3 - "$body_file" "$title" > "$html" <<'PY'
import sys, html, pathlib
body = pathlib.Path(sys.argv[1]).read_text()
title = sys.argv[2]
print(f'''<!doctype html>
<html><head><meta charset="utf-8"><style>
body {{ margin: 0; background: #0d1117; font-family: "JetBrains Mono", "Fira Code", monospace;
        color: #c9d1d9; padding: 40px; }}
.title {{ color: #58a6ff; font-size: 14px; margin-bottom: 16px;
          border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
pre {{ margin: 0; font-size: 13px; line-height: 1.5; white-space: pre; }}
.hl-op {{ color: #ff7b72; }}
.hl-tok {{ color: #a5d6ff; }}
.hl-cmt {{ color: #8b949e; }}
.hl-off {{ color: #d2a8ff; }}
</style></head><body>
<div class="title">{html.escape(title)}</div>
<pre>''')
import re
for ln in body.splitlines():
    ln = html.escape(ln)
    ln = re.sub(r'(IL_[A-F0-9]+:)', r'<span class="hl-off">\\1</span>', ln)
    ln = re.sub(r'(ldsfld|stsfld|brtrue|brfalse|brtrue\\.s|brfalse\\.s|call|callvirt|ret|ldc\\.i4|ldc\\.i4\\.0|ldc\\.i4\\.1|ldarg|starg|stloc|ldloc|box|leave|leave\\.s|pop|dup|newobj|ldnull|ldftn|ldstr|conv\\.i|blt\\.s|endfinally)\\b', r'<span class="hl-op">\\1</span>', ln)
    ln = re.sub(r'(token\\(0x[0-9A-Fa-f]+\\))', r'<span class="hl-tok">\\1</span>', ln)
    ln = re.sub(r'(//.*)$', r'<span class="hl-cmt">\\1</span>', ln)
    print(ln)
print('</pre></body></html>')
PY
    chromium --headless --disable-gpu --no-sandbox \
        --window-size=1600,1200 --hide-scrollbars \
        --screenshot="$WORK/raw-${title}.png" "file://$html" >/dev/null 2>&1
    # Trim whitespace around the content
    if command -v magick >/dev/null; then
        magick "$WORK/raw-${title}.png" -trim +repage -bordercolor '#0d1117' -border 40 "$out" 2>/dev/null
    else
        convert "$WORK/raw-${title}.png" -trim +repage -bordercolor '#0d1117' -border 40 "$out"
    fi
    say "rendered $out"
}

say "1/4 rendering IL dump of ScanContent + Uninitialize"
# produce the body file from the real IL dump captured earlier
cp /tmp/shedskin-re/amsiutils-il-dump.txt "$WORK/scancontent.txt"
render_il_png "AmsiUtils-ScanContent-and-Uninitialize-IL" "$WORK/scancontent.txt" "$OUT_DIR/shedskin-il-scancontent.png"

# -----------------------------------------------------------------------------
# 2. Linux-rendered: radare2 output on amsi.dll
# -----------------------------------------------------------------------------
say "2/4 rendering radare2 analysis of amsi.dll AMSI exports"
AMSI_DLL=/tmp/amsi-win11.dll
if [ ! -f "$AMSI_DLL" ]; then
    "$LAB/winpull.sh" -d $GUEST 'C:\Windows\System32\amsi.dll' "$AMSI_DLL" >/dev/null 2>&1 || true
fi
if [ -f "$AMSI_DLL" ]; then
    {
        echo "\$ r2 -q -c 'iE~Amsi' /tmp/amsi-win11.dll"
        r2 -q -c 'iE~AmsiInit;iE~AmsiScan;iE~AmsiUninit' "$AMSI_DLL" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g'
        echo ""
        echo "\$ r2 -q -A -c 's 0x180001840; pdc' /tmp/amsi-win11.dll"
        echo "// AmsiUninitialize (export)"
        r2 -q -A -c 's 0x180001840; pdc' "$AMSI_DLL" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | awk '/^INFO|^$/{next} 1' | head -30
    } > "$WORK/r2-amsi.txt"
    render_il_png "radare2 pseudo-decompile of amsi.dll AmsiUninitialize" "$WORK/r2-amsi.txt" "$OUT_DIR/shedskin-amsi-re.png"
else
    say "  (amsi.dll not available; skipping)"
fi

# -----------------------------------------------------------------------------
# 3. Windows terminal screenshot (needs unlocked guest)
# -----------------------------------------------------------------------------
say "3/4 attempting Windows terminal capture (requires unlocked guest)"
# detect the current framebuffer and look for a desktop (not lock-screen)
$VIRSH screenshot $GUEST "$WORK/current-fb.ppm" >/dev/null 2>&1 || true
if [ -f "$WORK/current-fb.ppm" ]; then
    # Lock screen on Win11 shows a dark blue wallpaper with a huge white clock;
    # a logged-in desktop has a taskbar and distinct chrome. A fast heuristic:
    # mean brightness and standard deviation. Lock screen is uniform; desktop is varied.
    STATS=$(magick "$WORK/current-fb.ppm" -colorspace Gray -format '%[fx:mean] %[fx:standard_deviation]' info: 2>/dev/null || echo "0 0")
    say "  framebuffer stats (mean stddev): $STATS"
    # On Win11 lock screen stddev stays low (uniform wallpaper + clock). Desktop stddev higher.
    STDDEV=$(echo "$STATS" | awk '{print $2}')
    STDDEV_OK=$(awk -v s="$STDDEV" 'BEGIN{print (s>0.12) ? "1" : "0"}')
    if [ "$STDDEV_OK" = "1" ]; then
        say "  desktop detected, running measurement + capturing terminal"
        "$LAB/winrun.sh" -d $GUEST "start powershell.exe -NoProfile -NoExit -Command \"cls; cd C:\\lab\\amb-iter20\\amp; .\\measure.ps1\"" >/dev/null 2>&1 || true
        sleep 45  # P1 + attack + P2 + P3 + P4 need the full sleep budget
        $VIRSH screenshot $GUEST "$WORK/win-measure.ppm" >/dev/null
        magick "$WORK/win-measure.ppm" "$OUT_DIR/shedskin-measure.png"
        say "  wrote $OUT_DIR/shedskin-measure.png"
    else
        say "  guest appears locked (stddev=$STDDEV < 0.12 threshold)."
        say "  LOG IN TO THE WIN11 GUEST and re-run this script to produce shedskin-measure.png."
    fi
fi

# -----------------------------------------------------------------------------
# 4. mp4 screencast (needs unlocked guest)
# -----------------------------------------------------------------------------
say "4/4 mp4 screencast (requires unlocked guest, otherwise skipped)"
if [ "${STDDEV_OK:-0}" = "1" ]; then
    FRAMES="$WORK/frames"
    rm -rf "$FRAMES" && mkdir -p "$FRAMES"
    say "  recording 60 frames at 1 fps (60-second clip)"
    for i in $(seq -w 1 60); do
        $VIRSH screenshot $GUEST "$FRAMES/f${i}.ppm" >/dev/null 2>&1 || true
        sleep 1
    done
    # Convert to mp4 at 1 fps real-time (60s clip) or 10 fps for a faster read
    ffmpeg -y -framerate 1 -pattern_type glob -i "$FRAMES/f*.ppm" \
        -c:v libx264 -pix_fmt yuv420p -movflags +faststart \
        "$OUT_DIR/shedskin-mimikatz.mp4" >/dev/null 2>&1
    say "  wrote $OUT_DIR/shedskin-mimikatz.mp4"
else
    say "  (locked guest; skipping)"
fi

say "done. outputs in $OUT_DIR"
ls -la "$OUT_DIR" | grep -E 'shedskin' || true
