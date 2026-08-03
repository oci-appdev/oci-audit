#!/usr/bin/env bash
#
# sysmon.sh — a live, colourful Linux resource monitor.
#
#   * Pure bash + /proc + coreutils. No python, no external monitors.
#   * Gradient block bars for CPU (aggregate + per core), memory, swap, disks.
#   * Live network throughput, load average, temperature, top processes.
#   * Flicker-free: each frame is assembled in memory and painted in one write.
#
# Usage:  ./sysmon.sh [-i SECONDS] [-c FRAMES] [-a] [-n] [-h]
# Quit:   q  or  Ctrl-C
#
set -uo pipefail

# ----------------------------------------------------------------- options ---
INTERVAL=1
MAXFRAMES=0        # 0 = run forever
WANT_COLOR=1
ASCII=0

usage() {
  cat <<'EOF'
sysmon.sh — real-time Linux resource monitor

  -i, --interval SEC   refresh interval, decimals allowed (default: 1)
  -c, --count N        render N frames then exit (default: unlimited)
  -a, --ascii          use ASCII bar characters instead of Unicode blocks
  -n, --no-color       disable colour output
  -h, --help           show this help

Press q at any time to quit.
EOF
}

while (($#)); do
  case "$1" in
    -i|--interval) INTERVAL="${2-}"; shift 2 ;;
    -c|--count)    MAXFRAMES="${2-}"; shift 2 ;;
    -a|--ascii)    ASCII=1; shift ;;
    -n|--no-color) WANT_COLOR=0; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) printf 'sysmon: unknown option %q\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$INTERVAL"  =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "sysmon: bad interval" >&2; exit 2; }
[[ "$MAXFRAMES" =~ ^[0-9]+$ ]]            || { echo "sysmon: bad count" >&2; exit 2; }

# ------------------------------------------------------------------ styling ---
ESC=$'\e'
INTERACTIVE=0
[[ -t 1 ]] && INTERACTIVE=1

NCOLORS=8
command -v tput >/dev/null 2>&1 && NCOLORS=$(tput colors 2>/dev/null || echo 8)

if (( WANT_COLOR )) && (( NCOLORS >= 8 )); then
  RESET="${ESC}[0m"; BOLD="${ESC}[1m"; DIM="${ESC}[2m"
  TITLE="${ESC}[1;38;5;39m"; LABEL="${ESC}[38;5;110m"
  VALUE="${ESC}[1;38;5;253m"; MUTED="${ESC}[38;5;240m"
  ACCENT="${ESC}[38;5;208m"
  if (( NCOLORS >= 256 )); then
    PALETTE=(46 82 118 154 190 226 220 214 208 202 196)
  else
    PALETTE=(32 32 32 32 33 33 33 31 31 31 31)   # green / yellow / red
  fi
else
  RESET=""; BOLD=""; DIM=""; TITLE=""; LABEL=""; VALUE=""; MUTED=""; ACCENT=""
  PALETTE=()
fi
CLR="${ESC}[K"

if (( ASCII )); then FULL='#'; EMPTY='.'; else FULL='█'; EMPTY='░'; fi

seg_color() {   # $1 = cell index, $2 = bar width
  (( ${#PALETTE[@]} )) || { printf ''; return; }
  local n=${#PALETTE[@]} i=$(( $1 * ${#PALETTE[@]} / $2 ))
  (( i >= n )) && i=$(( n - 1 ))
  if (( NCOLORS >= 256 )); then printf '%s[38;5;%sm' "$ESC" "${PALETTE[i]}"
  else printf '%s[%sm' "$ESC" "${PALETTE[i]}"; fi
}

# Draw a gradient bar. $1 = percent 0..100, $2 = width. Emits a colour code
# only when it actually changes, so a 60-cell bar costs a handful of escapes.
bar() {
  local pct=$1 w=$2 i filled out="" last=-1 idx
  (( pct < 0 )) && pct=0
  (( pct > 100 )) && pct=100
  filled=$(( pct * w / 100 ))
  for (( i = 0; i < filled; i++ )); do
    idx=$(( i * 11 / w ))
    if (( idx != last )); then out+="$(seg_color "$i" "$w")"; last=$idx; fi
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
  while read -r key val unit; do
    case "$key" in
      MemTotal:)     MEM_TOTAL=$(( val * 1024 )) ;;
      MemFree:)      free=$(( val * 1024 )) ;;
      MemAvailable:) avail=$(( val * 1024 )) ;;
      Buffers:)      buffers=$(( val * 1024 )) ;;
      Cached:)       cached=$(( val * 1024 )) ;;
      SReclaimable:) sreclaim=$(( val * 1024 )) ;;
      SwapTotal:)    SWAP_TOTAL=$(( val * 1024 )) ;;
      SwapFree:)     swfree=$(( val * 1024 )); break ;;
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
  local line rx=0 tx=0
  NET_IFACES=0
  while IFS= read -r line; do
    line="${line//:/ }"
    # shellcheck disable=SC2086
    set -- $line
    (( $# >= 17 )) || continue
    [[ "$2" =~ ^[0-9]+$ ]] || continue
    case "$1" in lo|veth*|docker*|br-*|virbr*) continue ;; esac
    rx=$(( rx + $2 )); tx=$(( tx + ${10} )); (( NET_IFACES++ ))
  done < /proc/net/dev
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

# ------------------------------------------------------------------ display ---
declare -a REAL_MOUNTS=()
scan_mounts() {   # only physically-backed filesystems; skips tmpfs, cgroup, fuse, ...
  local -A seen=()
  local dev mp fstype rest
  REAL_MOUNTS=()
  while read -r dev mp fstype rest; do
    case "$fstype" in
      ext2|ext3|ext4|xfs|btrfs|zfs|f2fs|jfs|reiserfs|bcachefs|\
      vfat|exfat|ntfs|ntfs3|hfsplus|apfs|ufs|nfs|nfs4|cifs) ;;
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
measure() { COLS=$( { tput cols; } 2>/dev/null || echo 80 ); [[ "$COLS" =~ ^[0-9]+$ ]] || COLS=80; (( COLS < 46 )) && COLS=46; RESIZED=0; }
trap 'RESIZED=1' WINCH

FRAME=""
line() { FRAME+="${1-}${CLR}"$'\n'; }

rule() {
  local title="${1-}" w=$(( COLS - 2 )) i txt=""
  if [[ -n "$title" ]]; then
    txt="${TITLE}${title}${RESET}${MUTED}"
    local pad=$(( w - ${#title} - 3 ))
    (( pad < 0 )) && pad=0
    local dashes=""; for (( i = 0; i < pad; i++ )); do dashes+="─"; done
    line "${MUTED}──${RESET} ${txt} ${dashes}${RESET}"
  else
    local dashes=""; for (( i = 0; i < w; i++ )); do dashes+="─"; done
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

render() {
  local host kernel up load1 load5 load15 procs temp now
  host=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo linux)
  read -r kernel < /proc/sys/kernel/osrelease
  read -r up _ < /proc/uptime
  read -r load1 load5 load15 procs _ < /proc/loadavg
  temp=$(read_temp)
  now=$(date '+%H:%M:%S')

  FRAME=""
  line "${BOLD}${TITLE} ⬤ ${host}${RESET}  ${DIM}${kernel}${RESET}   ${LABEL}up${RESET} ${VALUE}$(fmt_uptime "$up")${RESET}   ${LABEL}load${RESET} ${VALUE}${load1} ${load5} ${load15}${RESET}   ${LABEL}tasks${RESET} ${VALUE}${procs}${RESET}$( [[ -n $temp ]] && printf '   %stemp%s %s%s°C%s' "$LABEL" "$RESET" "$ACCENT" "$temp" "$RESET" )   ${DIM}${now}${RESET}"
  line ""

  # ---- CPU
  rule "CPU"
  local cores=$(( NCPU - 1 )) percol=24 ncol row rows c idx
  meter "total" "${CPU_PCT[0]:-0}" "$cores core$( (( cores == 1 )) || printf s )"
  if (( cores > 0 )); then
    ncol=$(( COLS / percol )); (( ncol < 1 )) && ncol=1; (( ncol > 4 )) && ncol=4
    rows=$(( (cores + ncol - 1) / ncol ))
    for (( row = 0; row < rows; row++ )); do
      local out=""
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
  line ""

  # ---- Memory
  rule "MEMORY"
  meter "ram" "$(pct_of "$MEM_USED" "$MEM_TOTAL")" "$(human "$MEM_USED") / $(human "$MEM_TOTAL")"
  if (( SWAP_TOTAL > 0 )); then
    meter "swap" "$(pct_of "$SWAP_USED" "$SWAP_TOTAL")" "$(human "$SWAP_USED") / $(human "$SWAP_TOTAL")"
  else
    line "$(printf '%s%-9s%s %s' "$LABEL" "swap" "$RESET" "${DIM}not configured${RESET}")"
  fi
  line "$(printf '%s%-9s%s %s%s%s   %sbuffers + reclaimable page cache%s' "$LABEL" "cache" "$RESET" "$VALUE" "$(human "$MEM_CACHE")" "$RESET" "$DIM" "$RESET")"
  line ""

  # ---- Disks
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
  line ""

  # ---- Network
  rule "NETWORK"
  if (( NET_IFACES == 0 )); then
    line "${DIM}  no physical interfaces found (loopback and virtual devices are excluded)${RESET}"
    line ""
  else
  local nw=$(( COLS / 3 )); (( nw > 30 )) && nw=30; (( nw < 10 )) && nw=10
  # Scale the sparkline against 12 MiB/s so ordinary traffic stays legible.
  local rxp=$(( RX_RATE / 125829 )) txp=$(( TX_RATE / 125829 ))
  line "$(printf '%s%-9s%s ' "$LABEL" "down" "$RESET")$(bar "$rxp" "$nw") $(printf '%s%9s/s%s  %stotal %s%s' "$VALUE" "$(human "$RX_RATE")" "$RESET" "$DIM" "$(human "$RX_TOTAL")" "$RESET")"
  line "$(printf '%s%-9s%s ' "$LABEL" "up" "$RESET")$(bar "$txp" "$nw") $(printf '%s%9s/s%s  %stotal %s%s' "$VALUE" "$(human "$TX_RATE")" "$RESET" "$DIM" "$(human "$TX_TOTAL")" "$RESET")"
  line ""
  fi

  # ---- Processes
  rule "TOP PROCESSES"
  line "$(printf '%s  %-7s %-24s %8s %8s%s' "$MUTED" "PID" "COMMAND" "CPU%" "MEM%" "$RESET")"
  local pid pcpu pmem comm
  while read -r pid pcpu pmem comm; do
    [[ -n "${comm:-}" ]] || continue
    line "$(printf '  %s%-7s%s %-24s %s%8s%s %8s' "$VALUE" "$pid" "$RESET" "${comm:0:24}" "$ACCENT" "$pcpu" "$RESET" "$pmem")"
  done < <(ps -eo pid=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | head -n 6)
  line ""
  line "${MUTED}  q quit${RESET}${DIM} · refresh ${INTERVAL}s · process CPU% is a lifetime average reported by ps${RESET}"
}

# --------------------------------------------------------------------- main ---
cleanup() {
  if (( INTERACTIVE )); then printf '%s[?25h%s[?1049l' "$ESC" "$ESC"; fi
  exit 0
}
trap cleanup INT TERM HUP EXIT

if (( INTERACTIVE )); then printf '%s[?1049h%s[?25l' "$ESC" "$ESC"; fi

# Prime the counters so the first painted frame shows real deltas, not a spike.
scan_mounts
sample_cpu; sample_net
sleep "$INTERVAL"

frames=0
while :; do
  (( RESIZED )) && measure
  (( frames % 10 == 0 )) && scan_mounts
  sample_cpu; sample_mem; sample_net
  render
  printf '%s[H%s%s[J' "$ESC" "$FRAME" "$ESC"

  (( ++frames ))
  if (( MAXFRAMES > 0 && frames >= MAXFRAMES )); then break; fi

  if (( INTERACTIVE )) && [[ -t 0 ]]; then
    if read -rsn1 -t "$INTERVAL" key 2>/dev/null; then
      case "$key" in q|Q) break ;; esac
    fi
  else
    sleep "$INTERVAL"
  fi
done
