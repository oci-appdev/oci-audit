#!/usr/bin/env bash
#
# sysmon.sh — a live, colourful Linux resource monitor.
#
#   * Bash + Linux /proc and /sys, coreutils (df, date), procps-ng (ps),
#     and optionally tput from ncurses. No python, no external monitors.
#   * Gradient block bars for CPU (aggregate + per core), memory, swap, disks.
#   * Live network throughput, load average, temperature, top processes.
#   * Rolling history charts from 1 minute to 6 hours, in constant memory.
#   * Flicker-free: each frame is assembled in memory and painted in one write.
#
# Usage:  ./sysmon.sh [-i SEC] [-w WINDOW] [-R ROWS] [-c FRAMES] [-anCrh]
# Keys:   1-5 pick history window, , / . cycle it, q quit
#
set -uo pipefail

# ----------------------------------------------------------------- options ---
INTERVAL=1
MAXFRAMES=0        # 0 = run forever
WANT_COLOR=1
FORCE_COLOR=0
ASCII=0
INCLUDE_REMOTE=0   # NFS/CIFS are off by default: a stale mount blocks df
CHART_ROWS=3       # height of the CPU/memory history charts
WINDOW_ARG=15m

# History windows. Each keeps NBUCK averaged buckets, so a 6-hour view costs
# exactly as much memory as a 1-minute view; only the bucket span changes.
NBUCK=60
TIER_SECS=(60 300 900 3600 21600)
TIER_NAME=(1m 5m 15m 1h 6h)
NTIER=5
WINDOW=2

usage() {
  cat <<'EOF'
sysmon.sh — real-time Linux resource monitor

  -i, --interval SEC   refresh interval, decimals allowed (default: 1)
  -c, --count N        render N frames then exit (default: unlimited)
  -w, --window WIN     initial history window: 1m, 5m, 15m, 1h or 6h (default: 15m)
  -R, --chart-rows N   height of the history charts, 1-10 (default: 3)
  -a, --ascii          use ASCII bar characters instead of Unicode blocks
  -n, --no-color       disable colour output
  -C, --color          keep colour even when stdout is not a terminal
  -r, --remote         also report NFS/CIFS mounts (a stale mount can block df)
  -h, --help           show this help

Keys while running:
  1 2 3 4 5            switch the history window
  , .                  cycle the history window
  q                    quit

History is collected only while the script runs, so a 6h chart needs 6h
of uptime to fill. Buckets already gathered are kept when you switch windows.
EOF
}

need_value() {   # $1 = flag as written, $2 = number of args still on the line
  (( $2 >= 2 )) && return 0
  printf 'sysmon: %s requires a value\n' "$1" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    -i|--interval)  need_value "$1" $#; INTERVAL="$2";  shift 2 ;;
    -c|--count)     need_value "$1" $#; MAXFRAMES="$2"; shift 2 ;;
    -w|--window)    need_value "$1" $#; WINDOW_ARG="$2";  shift 2 ;;
    -R|--chart-rows) need_value "$1" $#; CHART_ROWS="$2";  shift 2 ;;
    -a|--ascii)     ASCII=1; shift ;;
    -n|--no-color)  WANT_COLOR=0; shift ;;
    -C|--color)     FORCE_COLOR=1; shift ;;
    -r|--remote)    INCLUDE_REMOTE=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) printf 'sysmon: unknown option %q\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$INTERVAL"  =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "sysmon: bad interval" >&2; exit 2; }
[[ "$MAXFRAMES" =~ ^[0-9]+$ ]]            || { echo "sysmon: bad count" >&2; exit 2; }
# A zero interval would spin the loop at 100% of a core: reject it. Stripping
# dots and zeros leaves nothing behind only when every digit is a zero.
[[ -n "${INTERVAL//[.0]/}" ]] || { echo "sysmon: interval must be greater than zero" >&2; exit 2; }
[[ "$CHART_ROWS" =~ ^[0-9]+$ ]] && (( CHART_ROWS >= 1 && CHART_ROWS <= 10 )) \
  || { echo "sysmon: chart rows must be 1-10" >&2; exit 2; }

resolve_window() {
  local t
  for (( t = 0; t < NTIER; t++ )); do
    [[ "$WINDOW_ARG" == "${TIER_NAME[t]}" ]] && { WINDOW=$t; return 0; }
  done
  printf 'sysmon: unknown window %q (choose %s)\n' "$WINDOW_ARG" "${TIER_NAME[*]}" >&2
  exit 2
}
resolve_window

# ------------------------------------------------------------------ styling ---
ESC=$'\e'
INTERACTIVE=0
[[ -t 1 ]] && INTERACTIVE=1

NCOLORS=8
command -v tput >/dev/null 2>&1 && NCOLORS=$(tput colors 2>/dev/null || echo 8)
[[ "$NCOLORS" =~ ^[0-9]+$ ]] || NCOLORS=8

# Piped or redirected output gets plain text unless colour is forced (--color,
# for the benefit of `less -R`).
(( INTERACTIVE || FORCE_COLOR )) || WANT_COLOR=0

if (( WANT_COLOR && NCOLORS >= 256 )); then
  RESET="${ESC}[0m"; BOLD="${ESC}[1m"; DIM="${ESC}[2m"
  TITLE="${ESC}[1;38;5;39m"; LABEL="${ESC}[38;5;110m"
  VALUE="${ESC}[1;38;5;253m"; MUTED="${ESC}[38;5;240m"
  ACCENT="${ESC}[38;5;208m"
  PALETTE=(46 82 118 154 190 226 220 214 208 202 196)
elif (( WANT_COLOR && NCOLORS >= 8 )); then
  RESET="${ESC}[0m"; BOLD="${ESC}[1m"; DIM="${ESC}[2m"
  TITLE="${ESC}[1;36m"; LABEL="${ESC}[36m"
  VALUE="${ESC}[1;37m"; MUTED="${ESC}[90m"
  ACCENT="${ESC}[33m"
  PALETTE=(32 32 32 32 33 33 33 31 31 31 31)   # green / yellow / red
else
  RESET=""; BOLD=""; DIM=""; TITLE=""; LABEL=""; VALUE=""; MUTED=""; ACCENT=""
  PALETTE=()
fi

PAL_CODE=()
PAL_N=${#PALETTE[@]}
for (( pi = 0; pi < PAL_N; pi++ )); do
  if (( NCOLORS >= 256 )); then PAL_CODE[pi]="${ESC}[38;5;${PALETTE[pi]}m"
  else PAL_CODE[pi]="${ESC}[${PALETTE[pi]}m"; fi
done

# Erase-to-end-of-line only makes sense when repainting a live terminal.
if (( INTERACTIVE )); then CLR="${ESC}[K"; else CLR=""; fi

if (( ASCII )); then
  FULL='#'; EMPTY='.'; RULE='-'; DOT='*'; MID='|'; GAP='.'
else
  FULL='█'; EMPTY='░'; RULE='─'; DOT='⬤'; MID='·'; GAP='·'
fi

# Chart glyphs. A braille cell carries a 2-wide by 4-tall dot grid, so one
# text row is worth four plot rows and the line can actually slope. BITS is
# indexed (column * SUBH) + row; the odd numbering is the braille standard.
declare -a BITS CHART_CHARS
if (( ASCII )); then
  SUBW=1; SUBH=1; BITS=(1); CHART_CHARS=(' ' '#')
else
  SUBW=2; SUBH=4; BITS=(1 2 4 64 8 16 32 128)
  # U+2800+n encoded by hand: \u depends on the locale charmap, \x does not.
  for (( bn = 0; bn < 256; bn++ )); do
    printf -v bfmt '\\x%02x\\x%02x\\x%02x' 226 $(( 0xA0 | bn >> 6 )) $(( 0x80 | bn & 63 ))
    printf -v "CHART_CHARS[$bn]" "$bfmt"
  done
fi

# Fixed hues for the two network series so they stay distinguishable where the
# value gradient would render them identically.
if (( WANT_COLOR && NCOLORS >= 256 )); then
  RX_COLOR="${ESC}[38;5;45m"; TX_COLOR="${ESC}[38;5;208m"
elif (( WANT_COLOR && NCOLORS >= 8 )); then
  RX_COLOR="${ESC}[36m"; TX_COLOR="${ESC}[33m"
else
  RX_COLOR=""; TX_COLOR=""
fi

# Draw a gradient bar. $1 = percent 0..100, $2 = width. Emits a colour code
# only when it actually changes, so a 60-cell bar costs a handful of escapes.
bar() {
  local pct=$1 w=$2 i filled out="" last=-1 idx
  (( pct < 0 )) && pct=0
  (( pct > 100 )) && pct=100
  filled=$(( pct * w / 100 ))
  for (( i = 0; i < filled; i++ )); do
    (( idx = PAL_N ? i * PAL_N / w : 0 ))
    if (( idx != last )); then out+="${PAL_CODE[idx]:-}"; last=$idx; fi
    out+="$FULL"
  done
  if (( filled < w )); then
    out+="${MUTED}"
    for (( i = filled; i < w; i++ )); do out+="$EMPTY"; done
  fi
  printf '%s%s' "$out" "$RESET"
}

human() {       # bytes -> 12.3M
  local b=$1 u=0 frac=0
  local -a suf=(B K M G T P)
  while (( b >= 1024 && u < 5 )); do
    frac=$(( (b % 1024) * 10 / 1024 )); b=$(( b / 1024 )); (( u++ ))
  done
  if (( u == 0 )); then printf '%d%s' "$b" "${suf[u]}"
  else printf '%d.%d%s' "$b" "$frac" "${suf[u]}"; fi
}

pct_of() {      # used total -> integer percent, 0 when total is 0
  local used=$1 total=$2
  (( total > 0 )) || { printf 0; return; }
  printf '%d' $(( used * 100 / total ))
}

now_ms() {     # wall clock in milliseconds
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local t="${EPOCHREALTIME/,/.}" sec frac
    sec="${t%.*}"; frac="${t#*.}"; frac="${frac:0:3}"
    printf '%d' $(( 10#$sec * 1000 + 10#${frac:-0} ))
  else
    date +%s%3N
  fi
}

short_path() { # keep the meaningful tail of a long mount point
  local m="$1" ell='…'
  (( ASCII )) && ell='~'
  if (( ${#m} > 9 )); then printf '%s%s' "$ell" "${m: -8}"; else printf '%s' "$m"; fi
}

# --------------------------------------------------------------- collectors ---
declare -a PREV_TOTAL=() PREV_IDLE=() CUR_TOTAL=() CUR_IDLE=() CPU_PCT=()
NCPU=0

sample_cpu() {
  local i=0 label user nice system idle iowait irq softirq steal rest
  CUR_TOTAL=(); CUR_IDLE=()
  while read -r label user nice system idle iowait irq softirq steal rest; do
    case "$label" in cpu|cpu[0-9]*) ;; *) continue ;; esac
    CUR_IDLE[i]=$(( idle + iowait ))
    CUR_TOTAL[i]=$(( user + nice + system + idle + iowait + irq + softirq + steal ))
    (( i++ ))
  done < /proc/stat
  NCPU=$i

  CPU_PCT=()
  for (( i = 0; i < NCPU; i++ )); do
    local pt=${PREV_TOTAL[i]:-0} pi=${PREV_IDLE[i]:-0}
    local dt=$(( CUR_TOTAL[i] - pt )) di=$(( CUR_IDLE[i] - pi ))
    if (( dt > 0 )); then CPU_PCT[i]=$(( (dt - di) * 100 / dt )); else CPU_PCT[i]=0; fi
    (( CPU_PCT[i] < 0 )) && CPU_PCT[i]=0
  done
  PREV_TOTAL=("${CUR_TOTAL[@]}"); PREV_IDLE=("${CUR_IDLE[@]}")
}

MEM_TOTAL=0 MEM_USED=0 MEM_CACHE=0 SWAP_TOTAL=0 SWAP_USED=0
sample_mem() {
  local key val unit avail=0 free=0 buffers=0 cached=0 sreclaim=0 swfree=0
  MEM_TOTAL=0; SWAP_TOTAL=0
  while read -r key val unit; do
    case "$key" in
      MemTotal:)     MEM_TOTAL=$(( val * 1024 )) ;;
      MemFree:)      free=$(( val * 1024 )) ;;
      MemAvailable:) avail=$(( val * 1024 )) ;;
      Buffers:)      buffers=$(( val * 1024 )) ;;
      Cached:)       cached=$(( val * 1024 )) ;;
      SReclaimable:) sreclaim=$(( val * 1024 )) ;;
      SwapTotal:)    SWAP_TOTAL=$(( val * 1024 )) ;;
      SwapFree:)     swfree=$(( val * 1024 )) ;;
    esac
  done < /proc/meminfo
  if (( avail > 0 )); then MEM_USED=$(( MEM_TOTAL - avail ))
  else MEM_USED=$(( MEM_TOTAL - free - buffers - cached - sreclaim )); fi
  (( MEM_USED < 0 )) && MEM_USED=0
  MEM_CACHE=$(( buffers + cached + sreclaim ))
  SWAP_USED=$(( SWAP_TOTAL - swfree ))
  (( SWAP_USED < 0 )) && SWAP_USED=0
}

PREV_RX=-1 PREV_TX=-1 PREV_MS=0 RX_RATE=0 TX_RATE=0 RX_TOTAL=0 TX_TOTAL=0 NET_IFACES=0
sample_net() {
  local line glob_was_on=0 rx=0 tx=0
  NET_IFACES=0
  # Splitting "eth0:12345 ..." needs word splitting but must not glob, so
  # pathname expansion is disabled for the duration of the parse.
  [[ $- == *f* ]] || glob_was_on=1
  set -f
  while IFS= read -r line; do
    line="${line//:/ }"
    # shellcheck disable=SC2086
    set -- $line
    # iface + 8 receive counters + 8 transmit counters
    (( $# >= 17 )) || continue
    [[ "$2" =~ ^[0-9]+$ && "${10}" =~ ^[0-9]+$ ]] || continue
    case "$1" in lo|veth*|docker*|br-*|virbr*|tap*|tun*) continue ;; esac
    rx=$(( rx + $2 )); tx=$(( tx + ${10} )); (( NET_IFACES++ ))
  done < /proc/net/dev
  (( glob_was_on )) && set +f
  RX_TOTAL=$rx; TX_TOTAL=$tx
  local now elapsed
  now=$(now_ms)
  if (( PREV_RX >= 0 && PREV_MS > 0 )); then
    elapsed=$(( now - PREV_MS )); (( elapsed < 1 )) && elapsed=1
    RX_RATE=$(( (rx - PREV_RX) * 1000 / elapsed ))
    TX_RATE=$(( (tx - PREV_TX) * 1000 / elapsed ))
    (( RX_RATE < 0 )) && RX_RATE=0
    (( TX_RATE < 0 )) && TX_RATE=0
  fi
  PREV_RX=$rx; PREV_TX=$tx; PREV_MS=$now
}

read_temp() {   # highest reported thermal zone, in whole degrees C; empty if none
  local f v best=""
  for f in /sys/class/thermal/thermal_zone*/temp; do
    [[ -r "$f" ]] || continue
    read -r v < "$f" 2>/dev/null || continue
    [[ "$v" =~ ^[0-9]+$ ]] || continue
    (( v > 1000 )) && v=$(( v / 1000 ))
    if [[ -z "$best" ]] || (( v > best )); then best=$v; fi
  done
  printf '%s' "$best"
}

fmt_uptime() {
  local secs=${1%%.*} d h m
  d=$(( secs / 86400 )); h=$(( secs % 86400 / 3600 )); m=$(( secs % 3600 / 60 ))
  if   (( d > 0 )); then printf '%dd %dh %dm' "$d" "$h" "$m"
  elif (( h > 0 )); then printf '%dh %dm' "$h" "$m"
  else printf '%dm' "$m"; fi
}


# --------------------------------------------------------------- history ---
# Four metrics x five windows x NBUCK buckets, flattened into one integer
# array indexed ((metric * NTIER) + tier) * NBUCK + slot. Every window keeps a
# fixed 60 buckets, so a 6-hour view costs exactly what a 1-minute view costs;
# only the seconds-per-bucket differs. Nothing grows without bound.
M_CPU=0; M_MEM=1; M_RX=2; M_TX=3; NMET=4
declare -a HIST=() ACC=() ACC_N=() TIER_SLOT=() TIER_FILL=() TIER_EDGE=()

hist_init() {
  local m t i
  for (( m = 0; m < NMET; m++ )); do
    for (( t = 0; t < NTIER; t++ )); do
      ACC[m*NTIER+t]=0
      for (( i = 0; i < NBUCK; i++ )); do HIST[(m*NTIER+t)*NBUCK+i]=0; done
    done
  done
  for (( t = 0; t < NTIER; t++ )); do
    ACC_N[t]=0; TIER_SLOT[t]=0; TIER_FILL[t]=0; TIER_EDGE[t]=0
  done
}

# Seal the in-progress bucket of one tier. $2..$5 are the readings from the
# sample now arriving; they are used only to backfill buckets that elapsed
# without any sample landing in them, which is the best estimate available.
hist_close() {
  local t=$1 slot=${TIER_SLOT[$1]} n=${ACC_N[$1]} m
  local -a cur=("$2" "$3" "$4" "$5")
  for (( m = 0; m < NMET; m++ )); do
    if (( n > 0 )); then
      HIST[(m*NTIER+t)*NBUCK+slot]=$(( ACC[m*NTIER+t] / n ))
    else
      HIST[(m*NTIER+t)*NBUCK+slot]=${cur[m]}
    fi
    ACC[m*NTIER+t]=0
  done
  ACC_N[t]=0
  TIER_SLOT[t]=$(( (slot + 1) % NBUCK ))
  (( TIER_FILL[t] < NBUCK )) && TIER_FILL[t]=$(( TIER_FILL[t] + 1 ))
}

hist_push() {   # cpu% mem% rx-bytes/s tx-bytes/s
  local cpu=$1 mem=$2 rx=$3 tx=$4 now t span guard
  now=$(now_ms)
  for (( t = 0; t < NTIER; t++ )); do
    span=$(( TIER_SECS[t] * 1000 / NBUCK ))
    (( span < 1 )) && span=1
    (( TIER_EDGE[t] == 0 )) && TIER_EDGE[t]=$(( now + span ))
    # Seal elapsed buckets BEFORE this sample is accumulated: a reading taken
    # at or after the edge belongs to the new bucket, not the one it closes.
    guard=0
    while (( now >= TIER_EDGE[t] && guard < NBUCK )); do
      hist_close "$t" "$cpu" "$mem" "$rx" "$tx"
      TIER_EDGE[t]=$(( TIER_EDGE[t] + span ))
      (( guard++ ))
    done
    # After a suspend or SIGSTOP the edge can be hours behind. Once a whole
    # ring has been rotated there is nothing left to backfill, so resynchronise
    # instead of spinning through the missed spans.
    (( guard >= NBUCK )) && TIER_EDGE[t]=$(( now + span ))
    ACC[M_CPU*NTIER+t]=$(( ACC[M_CPU*NTIER+t] + cpu ))
    ACC[M_MEM*NTIER+t]=$(( ACC[M_MEM*NTIER+t] + mem ))
    ACC[M_RX*NTIER+t]=$((  ACC[M_RX*NTIER+t]  + rx  ))
    ACC[M_TX*NTIER+t]=$((  ACC[M_TX*NTIER+t]  + tx  ))
    ACC_N[t]=$(( ACC_N[t] + 1 ))
  done
}

HSER=()
hist_series() {  # $1 metric, $2 tier -> HSER oldest first, partial bucket last
  local m=$1 t=$2 fill=${TIER_FILL[$2]} base=$(( ($1 * NTIER + $2) * NBUCK )) i slot
  HSER=()
  for (( i = 0; i < fill; i++ )); do
    slot=$(( (TIER_SLOT[t] - fill + i + NBUCK) % NBUCK ))
    HSER+=( "${HIST[base+slot]}" )
  done
  (( ACC_N[t] > 0 )) && HSER+=( $(( ACC[m*NTIER+t] / ACC_N[t] )) )
}

fmt_dur() {
  local sec=$1 h m
  h=$(( sec / 3600 )); m=$(( sec % 3600 / 60 )); sec=$(( sec % 60 ))
  if   (( h > 0 )); then printf '%dh%02dm' "$h" "$m"
  elif (( m > 0 )); then if (( sec > 0 )); then printf '%dm%02ds' "$m" "$sec"; else printf '%dm' "$m"; fi
  else printf '%ds' "$sec"; fi
}

# ------------------------------------------------------------------ display ---
declare -a REAL_MOUNTS=()
scan_mounts() {   # only physically-backed filesystems; skips tmpfs, cgroup, fuse, ...
  local -A seen=()
  local dev mp fstype rest
  REAL_MOUNTS=()
  while read -r dev mp fstype rest; do
    case "$fstype" in
      ext2|ext3|ext4|xfs|btrfs|zfs|f2fs|jfs|reiserfs|bcachefs|\
      vfat|exfat|ntfs|ntfs3|hfsplus|apfs|ufs) ;;
      nfs|nfs4|cifs|smbfs|sshfs)
        # A hung server makes df block forever, which would freeze the display.
        (( INCLUDE_REMOTE )) || continue ;;
      *) continue ;;
    esac
    mp="${mp//\\040/ }"
    [[ -n "${seen[$mp]:-}" ]] && continue
    seen[$mp]=1
    REAL_MOUNTS+=("$mp")
  done < /proc/self/mounts
  (( ${#REAL_MOUNTS[@]} )) || REAL_MOUNTS=(/)
}

COLS=80
RESIZED=1
ROWS=24
measure() {
  COLS=$( { tput cols;  } 2>/dev/null || echo 80 )
  ROWS=$( { tput lines; } 2>/dev/null || echo 24 )
  [[ "$COLS" =~ ^[0-9]+$ ]] || COLS=80
  [[ "$ROWS" =~ ^[0-9]+$ ]] || ROWS=24
  (( COLS < 46 )) && COLS=46
  (( ROWS < 8 ))  && ROWS=8
  RESIZED=0
}
trap 'RESIZED=1' WINCH

FRAME=""
line() { FRAME+="${1-}${CLR}"$'\n'; }

rule() {
  local title="${1-}" w=$(( COLS - 2 )) i txt=""
  if [[ -n "$title" ]]; then
    txt="${TITLE}${title}${RESET}${MUTED}"
    local pad=$(( w - ${#title} - 3 ))
    (( pad < 0 )) && pad=0
    local dashes=""; for (( i = 0; i < pad; i++ )); do dashes+="$RULE"; done
    line "${MUTED}${RULE}${RULE}${RESET} ${txt} ${dashes}${RESET}"
  else
    local dashes=""; for (( i = 0; i < w; i++ )); do dashes+="$RULE"; done
    line "${MUTED}${dashes}${RESET}"
  fi
}

# label | bar | "used / total" — the bar flexes with the terminal width.
meter() {
  local label=$1 pct=$2 right=${3-} w
  w=$(( COLS - 12 - ${#right} - 8 ))
  (( w > 58 )) && w=58
  (( w < 10 )) && w=10
  line "$(printf '%s%-9s%s ' "$LABEL" "$label" "$RESET")$(bar "$pct" "$w") $(printf '%s%3d%%%s' "$VALUE" "$pct" "$RESET")  ${DIM}${right}${RESET}"
}

# Sections are rendered into separate buffers so the frame can be fitted to the
# terminal height, dropping the least important panels rather than overflowing.
sec_begin() { FRAME=""; }
sec_end() {   # $1 = buffer variable, $2 = line-count variable
  local nl="${FRAME//[!$'\n']/}"
  printf -v "$1" '%s' "$FRAME"
  printf -v "$2" '%d' "${#nl}"
}

HIST_SHOWN=0
declare -a G=() GC=() CTAB=() SER=()

# Plot one series into the dot grid. Consecutive samples are joined by filling
# the rows between them, so the result is a connected line rather than columns.
# $1 = fixed colour index, or -1 to colour each cell by its own value.
chart_draw() {
  local fixed=$1 kind=$2 h=$3 start=$4 shown=$5 maxv=$6
  local dw=$(( shown * SUBW )) dh=$(( h * SUBH ))
  local x i a b v y ylo yhi row cell bit idx yprev=-1
  for (( x = 0; x < dw; x++ )); do
    i=$(( start + x / SUBW ))
    if (( SUBW > 1 && x % SUBW )); then
      a=${SER[i]}; b=${SER[i+1]:-$a}; v=$(( (a + b) / 2 ))   # midpoint of the step
    else
      v=${SER[i]}
    fi
    y=$(( dh - 1 - v * (dh - 1) / maxv ))
    (( y < 0 )) && y=0
    (( y >= dh )) && y=$(( dh - 1 ))
    if   (( yprev < 0 ));    then ylo=$y;     yhi=$y
    elif (( yprev < y ));    then ylo=$yprev; yhi=$y
    else                          ylo=$y;     yhi=$yprev
    fi
    if (( fixed >= 0 )); then
      idx=$fixed
    else
      if [[ $kind == pct ]]; then (( idx = PAL_N ? v * PAL_N / 100 : 0 ))
      else                        (( idx = PAL_N ? v * PAL_N / maxv : 0 )); fi
      (( PAL_N && idx >= PAL_N )) && idx=$(( PAL_N - 1 ))
    fi
    for (( row = ylo; row <= yhi; row++ )); do
      cell=$(( (row / SUBH) * shown + x / SUBW ))
      bit=${BITS[(x % SUBW) * SUBH + row % SUBH]}
      G[cell]=$(( ${G[cell]:-0} | bit ))
      GC[cell]=$idx
    done
    yprev=$y
  done
}

# $1 label, $2 kind (pct|rate), $3 rows, $4.. metric ids (one or two)
hist_chart() {
  local label=$1 kind=$2 h=$3; shift 3
  local t=$WINDOW w n start shown i v maxv peak=0 cur=0 cur2=0
  local -a SA=() SB=() ANN=()
  local r c cell bits idx last out pre

  hist_series "$1" "$t"
  (( ${#HSER[@]} )) && SA=("${HSER[@]}")
  if (( $# > 1 )); then
    hist_series "$2" "$t"
    (( ${#HSER[@]} )) && SB=("${HSER[@]}")
  fi

  w=$(( COLS - 9 - 16 ))
  # NBUCK sealed buckets exactly span the window; the extra in-progress bucket
  # would otherwise make the chart claim more time than it covers.
  (( w > NBUCK )) && w=$NBUCK
  (( w < 16 )) && w=16
  n=${#SA[@]}
  start=0
  (( n > w )) && start=$(( n - w ))
  shown=$(( n - start ))
  HIST_SHOWN=$shown

  for (( i = start; i < n; i++ )); do
    v=${SA[i]};              (( v > peak )) && peak=$v
    v=${SB[i]:-0};           (( v > peak )) && peak=$v
  done
  (( n > 0 )) && cur=${SA[n-1]}
  (( ${#SB[@]} )) && cur2=${SB[${#SB[@]}-1]}
  # Autoscaled y-axis, floored so an idle machine does not look saturated.
  maxv=$peak
  if [[ $kind == pct ]]; then (( maxv < 10 )) && maxv=10
  else                        (( maxv < 1 )) && maxv=1; fi

  G=(); GC=(); CTAB=()
  if (( $# > 1 )); then
    CTAB=("$RX_COLOR" "$TX_COLOR")
    SER=("${SB[@]}"); chart_draw 1 "$kind" "$h" "$start" "$shown" "$maxv"
    SER=("${SA[@]}"); chart_draw 0 "$kind" "$h" "$start" "$shown" "$maxv"
    ANN=("${DIM}max $(human "$maxv")/s${RESET}"
         "${RX_COLOR}rx${RESET} ${DIM}$(human "$cur")/s${RESET}"
         "${TX_COLOR}tx${RESET} ${DIM}$(human "$cur2")/s${RESET}")
  else
    (( PAL_N )) && CTAB=("${PAL_CODE[@]}")
    SER=("${SA[@]}"); chart_draw -1 "$kind" "$h" "$start" "$shown" "$maxv"
    printf -v v '%s' "$(printf 'max %3d%%' "$maxv")"
    ANN=("${DIM}${v}${RESET}" "${DIM}$(printf 'now %3d%%' "$cur")${RESET}")
  fi

  for (( r = 0; r < h; r++ )); do          # row 0 is the top of the chart
    out=""; last=-1
    if (( shown < w )); then               # time not yet collected
      out+="${MUTED}"
      for (( i = shown; i < w; i++ )); do
        if (( r == h - 1 )); then out+="$GAP"; else out+=" "; fi
      done
      last=-2
    fi
    for (( c = 0; c < shown; c++ )); do
      cell=$(( r * shown + c ))
      bits=${G[cell]:-0}
      if (( bits == 0 )); then
        out+=" "                            # blank ink needs no colour change
      else
        idx=${GC[cell]}
        if (( idx != last )); then out+="${CTAB[idx]:-}"; last=$idx; fi
        out+="${CHART_CHARS[bits]}"
      fi
    done
    if (( r == 0 )); then printf -v pre '%s%-9s%s' "$LABEL" "$label" "$RESET"
    else                  printf -v pre '%9s' ""; fi
    line "${pre}${out}${RESET}  ${ANN[r]:-}"
  done
}

hist_panel() {   # $1 rows, $2 charts: costs 2 + $1 * $2 lines
  local h=$1 n=$2 span keys="" i
  rule "HISTORY"
                 hist_chart "cpu" pct  "$h" "$M_CPU"
  (( n >= 2 )) && hist_chart "mem" pct  "$h" "$M_MEM"
  (( n >= 3 )) && hist_chart "net" rate "$h" "$M_RX" "$M_TX"
  span=$(( TIER_SECS[WINDOW] / NBUCK ))
  (( span < 1 )) && span=1
  for (( i = 0; i < NTIER; i++ )); do
    if (( i == WINDOW )); then keys+="${VALUE}$(( i + 1 )):${TIER_NAME[i]}${RESET} "
    else keys+="${MUTED}$(( i + 1 )):${TIER_NAME[i]}${RESET} "; fi
  done
  line "  ${keys}${DIM} ${MID} $(fmt_dur "$span")/col ${MID} $(fmt_dur $(( HIST_SHOWN * span ))) shown ${MID} ${TIER_FILL[WINDOW]}/${NBUCK} buckets${RESET}"
}

proc_panel() {   # costs 2 + $1 lines
  local rows=$1 pid pcpu pmem comm
  rule "TOP PROCESSES"
  line "$(printf '%s  %-7s %-24s %8s %8s%s' "$MUTED" "PID" "COMMAND" "CPU%" "MEM%" "$RESET")"
  while read -r pid pcpu pmem comm; do
    [[ -n "${comm:-}" ]] || continue
    line "$(printf '  %s%-7s%s %-24s %s%8s%s %8s' "$VALUE" "$pid" "$RESET" "${comm:0:24}" "$ACCENT" "$pcpu" "$RESET" "$pmem")"
  done < <(ps -eo pid=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | head -n "$rows")
}

render() {
  local host kernel up load1 load5 load15 procs temp clock
  host=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo linux)
  read -r kernel < /proc/sys/kernel/osrelease
  read -r up _ < /proc/uptime
  read -r load1 load5 load15 procs _ < /proc/loadavg
  temp=$(read_temp)
  clock=$(date '+%H:%M:%S')

  local S_HEAD S_CPU S_CORE S_HIST S_MEM S_DISK S_NET S_PROC S_FOOT
  local N_HEAD N_CPU N_CORE N_HIST N_MEM N_DISK N_NET N_PROC N_FOOT

  # ---- header
  sec_begin
  line "${BOLD}${TITLE} ${DOT} ${host}${RESET}  ${DIM}${kernel}${RESET}   ${LABEL}up${RESET} ${VALUE}$(fmt_uptime "$up")${RESET}   ${LABEL}load${RESET} ${VALUE}${load1} ${load5} ${load15}${RESET}   ${LABEL}tasks${RESET} ${VALUE}${procs}${RESET}$( [[ -n $temp ]] && printf '   %stemp%s %s%s°C%s' "$LABEL" "$RESET" "$ACCENT" "$temp" "$RESET" )   ${DIM}${clock}${RESET}"
  sec_end S_HEAD N_HEAD

  # ---- CPU
  local cores=$(( NCPU - 1 ))
  sec_begin
  rule "CPU"
  meter "total" "${CPU_PCT[0]:-0}" "$cores core$( (( cores == 1 )) || printf s )"
  sec_end S_CPU N_CPU

  sec_begin
  if (( cores > 0 )); then
    local percol=24 ncol row rows c idx out
    ncol=$(( COLS / percol )); (( ncol < 1 )) && ncol=1; (( ncol > 4 )) && ncol=4
    rows=$(( (cores + ncol - 1) / ncol ))
    for (( row = 0; row < rows; row++ )); do
      out=""
      for (( c = 0; c < ncol; c++ )); do
        idx=$(( c * rows + row + 1 ))
        (( idx <= cores )) || continue
        out+="$(printf '%s%3s%s ' "$MUTED" "c$(( idx - 1 ))" "$RESET")"
        out+="$(bar "${CPU_PCT[idx]:-0}" 12)"
        out+="$(printf ' %s%3d%%%s  ' "$DIM" "${CPU_PCT[idx]:-0}" "$RESET")"
      done
      line "$out"
    done
  fi
  sec_end S_CORE N_CORE

  # ---- memory
  sec_begin
  rule "MEMORY"
  meter "ram" "$(pct_of "$MEM_USED" "$MEM_TOTAL")" "$(human "$MEM_USED") / $(human "$MEM_TOTAL")"
  if (( SWAP_TOTAL > 0 )); then
    meter "swap" "$(pct_of "$SWAP_USED" "$SWAP_TOTAL")" "$(human "$SWAP_USED") / $(human "$SWAP_TOTAL")"
  else
    line "$(printf '%s%-9s%s %s' "$LABEL" "swap" "$RESET" "${DIM}not configured${RESET}")"
  fi
  line "$(printf '%s%-9s%s %s%s%s   %sbuffers + reclaimable page cache%s' "$LABEL" "cache" "$RESET" "$VALUE" "$(human "$MEM_CACHE")" "$RESET" "$DIM" "$RESET")"
  sec_end S_MEM N_MEM

  # ---- disks
  sec_begin
  rule "DISK"
  local shown=0 fs size used avail cap mnt
  while read -r fs size used avail cap mnt; do
    [[ "$fs" == "Filesystem" || -z "${mnt:-}" ]] && continue
    [[ "$size" =~ ^[0-9]+$ ]] || continue
    (( size > 0 )) || continue
    meter "$(short_path "$mnt")" "$(pct_of "$used" "$size")" "$(human "$used") / $(human "$size")"
    (( ++shown >= 5 )) && break
  done < <(df -P -B1 "${REAL_MOUNTS[@]}" 2>/dev/null)
  (( shown == 0 )) && line "${DIM}  no filesystems reported${RESET}"
  sec_end S_DISK N_DISK

  # ---- network
  sec_begin
  rule "NETWORK"
  if (( NET_IFACES == 0 )); then
    line "${DIM}  no physical interfaces found (loopback and virtual devices are excluded)${RESET}"
  else
    local nw=$(( COLS / 3 )); (( nw > 30 )) && nw=30; (( nw < 10 )) && nw=10
    # Scale the live bar against 12 MiB/s so ordinary traffic stays legible.
    local rxp=$(( RX_RATE / 125829 )) txp=$(( TX_RATE / 125829 ))
    line "$(printf '%s%-9s%s ' "$LABEL" "down" "$RESET")$(bar "$rxp" "$nw") $(printf '%s%9s/s%s  %stotal %s%s' "$VALUE" "$(human "$RX_RATE")" "$RESET" "$DIM" "$(human "$RX_TOTAL")" "$RESET")"
    line "$(printf '%s%-9s%s ' "$LABEL" "up" "$RESET")$(bar "$txp" "$nw") $(printf '%s%9s/s%s  %stotal %s%s' "$VALUE" "$(human "$TX_RATE")" "$RESET" "$DIM" "$(human "$TX_TOTAL")" "$RESET")"
  fi
  sec_end S_NET N_NET

  # ---- footer
  sec_begin
  line "${MUTED}  q quit${RESET}${DIM} ${MID} 1-5 or , . change history window ${MID} refresh ${INTERVAL}s${RESET}"
  sec_end S_FOOT N_FOOT

  # ---- fit to the terminal. The history charts and the process table are the
  # point of the panel, so both keep a reserved minimum and the surplus is
  # spent widening them. Blank separators are the first thing sacrificed.
  local budget=$(( ROWS - 1 ))
  (( INTERACTIVE )) || budget=9999        # redirected output is not height-limited
  local avail=$(( budget - N_HEAD - N_CPU - N_CORE - N_MEM - N_FOOT ))
  local hrows=0 hcharts=0 prows=0 show_net=0 show_disk=0 show_core=1
  if (( avail < 8 )); then                # no room for per-core bars
    show_core=0; avail=$(( avail + N_CORE ))
  fi
  (( avail >= 3 )) && { hrows=1; hcharts=1; avail=$(( avail - 3 )); }   # rule+keys+cpu
  (( avail >= 5 )) && { prows=3;            avail=$(( avail - 5 )); }   # rule+header+3
  while (( hcharts && hcharts < 3 && avail >= hrows )); do (( hcharts++ )); avail=$(( avail - hrows )); done
  (( hrows == 1 && CHART_ROWS >= 2 && avail >= hcharts )) && { hrows=2; avail=$(( avail - hcharts )); }
  while (( prows > 0 && prows < 6 && avail >= 1 )); do (( prows++, avail-- )); done
  (( avail >= N_NET  )) && { show_net=1;  avail=$(( avail - N_NET  )); }
  (( avail >= N_DISK )) && { show_disk=1; avail=$(( avail - N_DISK )); }
  while (( hrows > 0 && hrows < CHART_ROWS && avail >= hcharts )); do (( hrows++ )); avail=$(( avail - hcharts )); done

  sec_begin; (( hcharts )) && hist_panel "$hrows" "$hcharts"; sec_end S_HIST N_HIST
  sec_begin; (( prows ))   && proc_panel "$prows";            sec_end S_PROC N_PROC

  # NB: never assemble panels through $(...) -- it strips the trailing newline
  # and welds the next panel onto the last line.
  local cpu_part="$S_CPU"
  (( show_core )) && cpu_part+="$S_CORE"
  local -a parts=("$S_HEAD" "$cpu_part")
  (( hcharts ))   && parts+=("$S_HIST")
  parts+=("$S_MEM")
  (( show_disk )) && parts+=("$S_DISK")
  (( show_net ))  && parts+=("$S_NET")
  (( prows ))     && parts+=("$S_PROC")
  parts+=("$S_FOOT")

  local sep="" i
  (( avail >= ${#parts[@]} - 1 )) && sep="${CLR}"$'\n'
  FRAME="${parts[0]}"
  for (( i = 1; i < ${#parts[@]}; i++ )); do FRAME+="${sep}${parts[i]}"; done
  trim_frame "$budget"
}

trim_frame() {   # last resort on a very short terminal
  local max=$1 out="" n=0 rest="$FRAME" ln
  while (( n < max )) && [[ -n "$rest" ]]; do
    if [[ "$rest" != *$'\n'* ]]; then out+="$rest"; break; fi
    ln="${rest%%$'\n'*}"; rest="${rest#*$'\n'}"
    out+="$ln"$'\n'; (( n++ ))
  done
  FRAME="$out"
}

# --------------------------------------------------------------------- main ---
cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  if (( INTERACTIVE )); then printf '%s[?25h%s[?1049l' "$ESC" "$ESC"; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT      # 128 + SIGINT
trap 'exit 143' TERM     # 128 + SIGTERM
trap 'exit 129' HUP      # 128 + SIGHUP

if (( INTERACTIVE )); then printf '%s[?1049h%s[?25l' "$ESC" "$ESC"; fi

# Prime the counters so the first painted frame shows real deltas, not a spike.
hist_init
scan_mounts
sample_cpu; sample_net
sleep "$INTERVAL"

frames=0
painted=0
redraw=0        # set when a keypress only changes the view, not the data
while :; do
  (( RESIZED )) && measure
  if (( redraw )); then
    redraw=0
  else
    (( frames % 10 == 0 )) && scan_mounts
    sample_cpu; sample_mem; sample_net
    hist_push "${CPU_PCT[0]:-0}" "$(pct_of "$MEM_USED" "$MEM_TOTAL")" "$RX_RATE" "$TX_RATE"
    (( ++frames ))
  fi

  render
  if (( INTERACTIVE )); then
    printf '%s[H%s%s[J' "$ESC" "$FRAME" "$ESC"
  else
    (( painted > 0 )) && printf '\n'
    printf '%s' "$FRAME"
  fi
  (( ++painted ))

  if (( MAXFRAMES > 0 && frames >= MAXFRAMES )); then break; fi

  if (( INTERACTIVE )) && [[ -t 0 ]]; then
    if read -rsn1 -t "$INTERVAL" key 2>/dev/null; then
      case "$key" in
        q|Q)          break ;;
        [1-5])        WINDOW=$(( key - 1 )); redraw=1 ;;
        ','|'<')      WINDOW=$(( (WINDOW - 1 + NTIER) % NTIER )); redraw=1 ;;
        '.'|'>')      WINDOW=$(( (WINDOW + 1) % NTIER )); redraw=1 ;;
      esac
    fi
  else
    sleep "$INTERVAL"
  fi
done
