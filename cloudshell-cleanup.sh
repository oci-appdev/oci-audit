#!/usr/bin/env bash
#
# cloudshell-cleanup.sh — reclaim space in OCI Cloud Shell, with a visual report.
#
# Only $HOME is persistent and it is capped at 5 GB. Everything outside $HOME
# (/tmp, /var, container layers) is ephemeral and does NOT count against your
# quota, so this script never leaves your home directory.
#
# Usage:
#   ./cloudshell-cleanup.sh                      # report only — deletes nothing
#   ./cloudshell-cleanup.sh --apply              # purge trash + safe caches
#   ./cloudshell-cleanup.sh --apply --deep       # + terraform / go / maven / cargo caches
#   ./cloudshell-cleanup.sh --html               # also write ~/cleanup-report.html
#   ./cloudshell-cleanup.sh --html=/path/x.html  # ...to a specific path
#   ./cloudshell-cleanup.sh --plain              # no colour / no bar characters
#
set -uo pipefail

APPLY=0
DEEP=0
HTML=0
PLAIN=0
HTML_OUT="$HOME/cleanup-report.html"
QUOTA_BYTES=$(( 5 * 1024 * 1024 * 1024 ))

usage() { sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case "$arg" in
    --apply)   APPLY=1 ;;
    --deep)    DEEP=1 ;;
    --plain)   PLAIN=1 ;;
    --html)    HTML=1 ;;
    --html=*)  HTML=1; HTML_OUT="${arg#--html=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; usage; exit 2 ;;
  esac
done

# ------------------------------------------------------------- plumbing -----
TMP=$(mktemp -d "${TMPDIR:-/tmp}/cscleanup.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT
T_TARGETS="$TMP/targets.tsv"   # size \t label \t path \t category \t mode
T_DIRS="$TMP/dirs.tsv"         # size \t path   (before)
T_DIRS_AFTER="$TMP/dirs2.tsv"  # size \t path   (after)
T_FILES="$TMP/files.tsv"       # size \t path
T_KEEP="$TMP/keep.tsv"         # size \t path \t kind  (reported, never deleted)
: > "$T_TARGETS"; : > "$T_DIRS"; : > "$T_DIRS_AFTER"; : > "$T_FILES"; : > "$T_KEEP"

if [[ -t 1 && $PLAIN -eq 0 ]]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[38;5;203m'; C_AMB=$'\033[38;5;214m'; C_VIO=$'\033[38;5;141m'
  C_BLU=$'\033[38;5;75m';  C_GRY=$'\033[38;5;245m'; C_GRN=$'\033[38;5;114m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""
  C_RED=""; C_AMB=""; C_VIO=""; C_BLU=""; C_GRY=""; C_GRN=""
fi

if [[ $PLAIN -eq 0 ]]; then BAR_CH="█"; BAR_BG="·"; else BAR_CH="#"; BAR_BG="."; fi

human()    { numfmt --to=iec --suffix=B "${1:-0}" 2>/dev/null || echo "${1:-0}B"; }
bytes_of() { du -sxb "$1" 2>/dev/null | awk '{print $1}'; }
rule()     { printf "%s%s%s\n" "$C_DIM" "$(printf '─%.0s' $(seq 1 64))" "$C_RESET"; }

cat_colour() {
  case "$1" in
    trash)     printf '%s' "$C_RED" ;;
    cache)     printf '%s' "$C_AMB" ;;
    terraform) printf '%s' "$C_VIO" ;;
    toolchain) printf '%s' "$C_BLU" ;;
    *)         printf '%s' "$C_GRY" ;;
  esac
}

# bar <value> <max> <width>
bar() {
  local v="${1:-0}" max="${2:-1}" w="${3:-28}" n
  (( max > 0 )) || max=1
  n=$(( v * w / max ))
  (( n < 1 && v > 0 )) && n=1
  (( n > w )) && n=w
  (( n > 0 ))     && printf '%s' "$(printf "${BAR_CH}%.0s" $(seq 1 "$n"))"
  (( w - n > 0 )) && printf '%s%s%s' "$C_DIM" "$(printf "${BAR_BG}%.0s" $(seq 1 $(( w - n ))))" "$C_RESET"
}

safe_path() {
  local p="${1:-}"
  [[ -n "$p" ]]           || return 1
  [[ "$p" == "$HOME"/* ]] || return 1
  [[ "$p" != *".."* ]]    || return 1
  return 0
}

# add_target <path> <label> <category> <contents|whole>
add_target() {
  local path="$1" label="$2" cat="$3" mode="$4" sz
  safe_path "$path" || return 0
  [[ -e "$path" ]]  || return 0
  sz=$(bytes_of "$path")
  [[ -n "$sz" ]]    || return 0
  (( sz < 1048576 )) && return 0          # ignore anything under 1 MB
  printf '%s\t%s\t%s\t%s\t%s\n' "$sz" "$label" "$path" "$cat" "$mode" >> "$T_TARGETS"
}

# ------------------------------------------------------------ discovery -----
printf '%sScanning %s ...%s\n' "$C_DIM" "$HOME" "$C_RESET" >&2

HOME_BEFORE=$(bytes_of "$HOME"); HOME_BEFORE=${HOME_BEFORE:-0}

du -xb "$HOME" --max-depth=2 2>/dev/null \
  | awk -F"\t" -v h="$HOME" '$2 != h { print $1 "\t" $2 }' \
  | sort -rn | head -25 > "$T_DIRS"

find "$HOME" -xdev -type f -size +5M -printf '%s\t%p\n' 2>/dev/null \
  | sort -rn | head -15 > "$T_FILES"

# --- trash: every casing and variant the Code Editor / desktop specs use -----
while IFS= read -r t; do
  add_target "$t" "trash — ${t#$HOME/}" trash contents
done < <(find "$HOME" -xdev -maxdepth 5 -type d \( -iname 'trash' -o -iname '.trash' \) 2>/dev/null)

# --- safe, always-rebuildable caches ----------------------------------------
add_target "$HOME/.cache"                   "generic user cache"        cache contents
add_target "$HOME/.npm/_cacache"            "npm cache"                 cache contents
add_target "$HOME/.node-gyp"                "node-gyp headers"          cache contents
add_target "$HOME/.yarn/cache"              "yarn cache"                cache contents
add_target "$HOME/.pip/cache"               "pip cache (legacy path)"   cache contents
add_target "$HOME/.ansible/tmp"             "ansible temp"              cache contents
add_target "$HOME/.theia/logs"              "Code Editor (Theia) logs"  cache contents
add_target "$HOME/.vscode-server/data/logs" "vscode-server logs"        cache contents
add_target "$HOME/.oci_cli_cache"           "OCI CLI response cache"    cache contents
add_target "$HOME/.local/share/containers"  "rootless container store"  cache contents

# --- deep: toolchain caches, need network to restore ------------------------
if (( DEEP )); then
  while IFS= read -r d; do
    add_target "$d" "terraform providers — ${d#$HOME/}" terraform whole
  done < <(find "$HOME" -xdev -type d -name '.terraform' 2>/dev/null)

  add_target "$HOME/.terraform.d/plugin-cache" "terraform plugin cache"  terraform contents
  add_target "$HOME/go/pkg/mod"                "go module cache"         toolchain contents
  add_target "$HOME/.m2/repository"            "maven repository"        toolchain contents
  add_target "$HOME/.gradle/caches"            "gradle caches"           toolchain contents
  add_target "$HOME/.cargo/registry"           "cargo registry"          toolchain contents
  add_target "$HOME/.rustup/toolchains"        "rust toolchains"         toolchain contents
  add_target "$HOME/.nvm/.cache"               "nvm cache"               toolchain contents
  add_target "$HOME/.conda/pkgs"               "conda package cache"     toolchain contents
  add_target "$HOME/miniconda3/pkgs"           "miniconda package cache" toolchain contents
fi

sort -rn -o "$T_TARGETS" "$T_TARGETS"
RECLAIMABLE=$(awk -F'\t' '{s+=$1} END {print s+0}' "$T_TARGETS")

# --- things worth a look, never auto-deleted --------------------------------
find "$HOME" -xdev -type f \
  \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' -o -name '*.rpm' \
     -o -name '*.iso' -o -name '*.qcow2' -o -name '*.jar' \) \
  -size +10M -printf '%s\t%p\tarchive\n' 2>/dev/null | sort -rn | head -10 >> "$T_KEEP"

while IFS= read -r d; do
  sz=$(bytes_of "$d")
  [[ -n "$sz" ]] && printf '%s\t%s\tbuild dir\n' "$sz" "$d" >> "$T_KEEP"
done < <(find "$HOME" -xdev -maxdepth 4 -type d \
         \( -name 'node_modules' -o -name '.venv' -o -name 'venv' \) -prune 2>/dev/null | head -10)

sort -rn -o "$T_KEEP" "$T_KEEP"

# --------------------------------------------------------------- delete -----
FREED=0
if (( APPLY )); then
  while IFS=$'\t' read -r sz label path cat mode; do
    safe_path "$path" || continue
    if [[ "$mode" == "whole" ]]; then
      rm -rf -- "$path" 2>/dev/null
    else
      find "$path" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null
    fi
    FREED=$(( FREED + sz ))
  done < "$T_TARGETS"

  find "$HOME" -xdev -maxdepth 3 -type f \
    \( -name 'core.[0-9]*' -o -name '*.log.[0-9]*' -o -name '*.log.gz' \) -delete 2>/dev/null

  HOME_AFTER=$(bytes_of "$HOME"); HOME_AFTER=${HOME_AFTER:-0}
  du -xb "$HOME" --max-depth=2 2>/dev/null \
    | awk -F"\t" -v h="$HOME" '$2 != h { print $1 "\t" $2 }' \
    | sort -rn | head -20 > "$T_DIRS_AFTER"
else
  HOME_AFTER=$HOME_BEFORE
fi

PCT_BEFORE=$(( HOME_BEFORE * 100 / QUOTA_BYTES ))
PCT_AFTER=$((  HOME_AFTER  * 100 / QUOTA_BYTES ))

# ------------------------------------------------------ terminal report -----
echo
rule
printf '%s  OCI Cloud Shell — storage report%s   %s%s%s\n' \
  "$C_BOLD" "$C_RESET" "$C_DIM" "$(date '+%Y-%m-%d %H:%M')" "$C_RESET"
rule
echo

gauge() { # gauge <label> <used> <pct>
  local label="$1" used="$2" pct="$3" col="$C_GRN"
  (( pct >= 75 )) && col="$C_AMB"
  (( pct >= 90 )) && col="$C_RED"
  printf '  %-7s %s%s%s  %s / %s  (%s%%)\n' \
    "$label" "$col" "$(bar "$used" "$QUOTA_BYTES" 32)" "$C_RESET" \
    "$(human "$used")" "$(human "$QUOTA_BYTES")" "$pct"
}

if (( APPLY )); then
  gauge "before" "$HOME_BEFORE" "$PCT_BEFORE"
  gauge "after"  "$HOME_AFTER"  "$PCT_AFTER"
  printf '\n  %sReclaimed%s %s%s%s\n' "$C_DIM" "$C_RESET" "$C_GRN$C_BOLD" "$(human "$FREED")" "$C_RESET"
else
  gauge "used" "$HOME_BEFORE" "$PCT_BEFORE"
  printf '\n  %sReclaimable%s %s%s%s%s — re-run with --apply to delete%s\n' \
    "$C_DIM" "$C_RESET" "$C_GRN$C_BOLD" "$(human "$RECLAIMABLE")" "$C_RESET" "$C_DIM" "$C_RESET"
fi
echo

if [[ -s "$T_TARGETS" ]]; then
  MAXT=$(head -1 "$T_TARGETS" | cut -f1)
  printf '  %sCLEANUP TARGETS%s  %sred trash · amber cache · violet terraform · blue toolchain%s\n\n' \
    "$C_BOLD" "$C_RESET" "$C_DIM" "$C_RESET"
  while IFS=$'\t' read -r sz label path cat mode; do
    printf '  %s%s%s %9s  %s\n' \
      "$(cat_colour "$cat")" "$(bar "$sz" "$MAXT" 24)" "$C_RESET" "$(human "$sz")" "$label"
  done < "$T_TARGETS"
  echo
else
  printf '  %sNothing over 1 MB found in trash or the known caches.%s\n\n' "$C_DIM" "$C_RESET"
fi

CHART_SRC="$T_DIRS"; CHART_LBL="TOP DIRECTORIES (before)"
if (( APPLY )) && [[ -s "$T_DIRS_AFTER" ]]; then
  CHART_SRC="$T_DIRS_AFTER"; CHART_LBL="TOP DIRECTORIES (after)"
fi
if [[ -s "$CHART_SRC" ]]; then
  MAXD=$(head -1 "$CHART_SRC" | cut -f1)
  printf '  %s%s%s\n\n' "$C_BOLD" "$CHART_LBL" "$C_RESET"
  head -15 "$CHART_SRC" | while IFS=$'\t' read -r sz path; do
    printf '  %s%s%s %9s  %s\n' \
      "$C_BLU" "$(bar "$sz" "$MAXD" 24)" "$C_RESET" "$(human "$sz")" "~/${path#$HOME/}"
  done
  echo
fi

if [[ -s "$T_KEEP" ]]; then
  printf '  %sREVIEW BY HAND%s  %s(archives and build dirs — never auto-deleted)%s\n\n' \
    "$C_BOLD" "$C_RESET" "$C_DIM" "$C_RESET"
  head -10 "$T_KEEP" | while IFS=$'\t' read -r sz path kind; do
    printf '  %9s  %-10s ~/%s\n' "$(human "$sz")" "$kind" "${path#$HOME/}"
  done
  echo
fi

# ---------------------------------------------------------- html report -----
gauge_html() { # gauge_html <label> <used> <pct>
  local col="var(--ok)"
  (( $3 >= 75 )) && col="var(--cache)"
  (( $3 >= 90 )) && col="var(--trash)"
  printf '<div class="gauge"><div class="top"><b>%s</b><span class="r">%s / 5.0 GB &middot; %s%%</span></div>' \
    "$1" "$(human "$2")" "$3"
  printf '<div class="track"><div class="fill" style="width:%s%%;background:%s"></div></div></div>\n' \
    "$(( $3 > 100 ? 100 : $3 ))" "$col"
}

if (( HTML )); then
  {
    cat <<'HEAD'
<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OCI Cloud Shell — storage report</title>
<style>
  :root{--bg:#0f1117;--card:#171a23;--line:#242938;--fg:#e6e9f0;--mut:#8b93a7;
        --trash:#e11d48;--cache:#f59e0b;--terraform:#8b5cf6;--toolchain:#38bdf8;
        --other:#64748b;--ok:#34d399}
  *{box-sizing:border-box}
  body{margin:0;padding:32px 20px;background:var(--bg);color:var(--fg);
       font:15px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
  .wrap{max-width:900px;margin:0 auto}
  h1{font-size:22px;margin:0 0 4px;font-weight:650;letter-spacing:-.01em}
  .sub{color:var(--mut);font-size:13px;margin-bottom:24px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;
        padding:20px;margin-bottom:16px}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);
     margin:0 0 16px;font-weight:600}
  .stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
  .stat{flex:1 1 150px;background:var(--card);border:1px solid var(--line);
        border-radius:12px;padding:16px 18px}
  .stat .n{font-size:24px;font-weight:650;letter-spacing:-.02em}
  .stat .l{font-size:12px;color:var(--mut);margin-top:2px}
  .gauge{margin-bottom:14px}
  .gauge .top{display:flex;justify-content:space-between;font-size:13px;margin-bottom:6px}
  .gauge .top .r{color:var(--mut);font-variant-numeric:tabular-nums}
  .track{height:12px;border-radius:6px;background:#0b0d13;border:1px solid var(--line);
         overflow:hidden}
  .fill{height:100%;border-radius:6px}
  .row{display:grid;grid-template-columns:1fr 84px;gap:12px;align-items:center;margin-bottom:10px}
  .row .meta{font-size:13px;overflow:hidden}
  .row .name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .row .path{color:var(--mut);font-size:11px;
             font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
             white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .row .b{height:8px;border-radius:4px;background:#0b0d13;margin-top:5px;overflow:hidden}
  .row .b i{display:block;height:100%;border-radius:4px}
  .row .sz{text-align:right;font-variant-numeric:tabular-nums;font-size:13px;color:var(--mut)}
  .key{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin-bottom:16px}
  .key span{display:flex;align-items:center;gap:6px}
  .key i{width:9px;height:9px;border-radius:3px;display:inline-block}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td{padding:7px 0;border-bottom:1px solid var(--line)}
  td.sz{text-align:right;color:var(--mut);font-variant-numeric:tabular-nums;
        white-space:nowrap;padding-left:12px}
  td.p{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut);
       font-size:12px;word-break:break-all}
  tr:last-child td{border-bottom:0}
  .foot{color:var(--mut);font-size:12px;text-align:center;margin-top:24px}
  .none{color:var(--mut);font-size:13px}
</style>
<div class="wrap">
HEAD

    printf '<h1>OCI Cloud Shell — storage report</h1>\n'
    printf '<div class="sub">%s &middot; %s &middot; %s</div>\n' \
      "$(date '+%A %d %B %Y, %H:%M')" \
      "$(hostname 2>/dev/null || echo cloudshell)" \
      "$( (( APPLY )) && echo 'cleanup applied' || echo 'dry run — nothing deleted' )"

    printf '<div class="stats">'
    printf '<div class="stat"><div class="n">%s</div><div class="l">home directory now</div></div>' "$(human "$HOME_AFTER")"
    printf '<div class="stat"><div class="n">%s%%</div><div class="l">of 5 GB quota</div></div>' "$PCT_AFTER"
    if (( APPLY )); then
      printf '<div class="stat"><div class="n" style="color:var(--ok)">%s</div><div class="l">reclaimed</div></div>' "$(human "$FREED")"
    else
      printf '<div class="stat"><div class="n" style="color:var(--ok)">%s</div><div class="l">reclaimable</div></div>' "$(human "$RECLAIMABLE")"
    fi
    printf '<div class="stat"><div class="n">%s</div><div class="l">targets found</div></div>' "$(wc -l < "$T_TARGETS")"
    printf '</div>\n'

    printf '<div class="card"><h2>Quota</h2>\n'
    if (( APPLY )); then
      gauge_html "Before" "$HOME_BEFORE" "$PCT_BEFORE"
      gauge_html "After"  "$HOME_AFTER"  "$PCT_AFTER"
    else
      gauge_html "Used"   "$HOME_BEFORE" "$PCT_BEFORE"
    fi
    printf '</div>\n'

    printf '<div class="card"><h2>%s</h2>\n' "$( (( APPLY )) && echo 'Removed' || echo 'Reclaimable' )"
    printf '<div class="key"><span><i style="background:var(--trash)"></i>trash</span>'
    printf '<span><i style="background:var(--cache)"></i>cache</span>'
    printf '<span><i style="background:var(--terraform)"></i>terraform</span>'
    printf '<span><i style="background:var(--toolchain)"></i>toolchain</span></div>\n'
    if [[ -s "$T_TARGETS" ]]; then
      awk -F'\t' -v max="$(head -1 "$T_TARGETS" | cut -f1)" -v home="$HOME" '
        function hs(b,  u,i){split("B KB MB GB TB",u," ");i=1;
          while(b>=1024&&i<5){b/=1024;i++} return sprintf("%.1f %s",b,u[i])}
        function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
        { w=(max>0)? $1*100/max : 0; if(w<0.6) w=0.6;
          p=$3; sub("^" home "/", "~/", p);
          printf "<div class=\"row\"><div class=\"meta\"><div class=\"name\">%s</div><div class=\"path\">%s</div><div class=\"b\"><i style=\"width:%.1f%%;background:var(--%s)\"></i></div></div><div class=\"sz\">%s</div></div>\n",
                 esc($2), esc(p), w, $4, hs($1) }
      ' "$T_TARGETS"
    else
      printf '<div class="none">Nothing over 1 MB found in trash or the known caches.</div>\n'
    fi
    printf '</div>\n'

    SRC="$T_DIRS"; LBL="Largest directories (before cleanup)"
    if (( APPLY )) && [[ -s "$T_DIRS_AFTER" ]]; then
      SRC="$T_DIRS_AFTER"; LBL="Largest directories (after cleanup)"
    fi
    printf '<div class="card"><h2>%s</h2>\n' "$LBL"
    awk -F'\t' -v max="$(head -1 "$SRC" | cut -f1)" -v home="$HOME" '
      function hs(b,  u,i){split("B KB MB GB TB",u," ");i=1;
        while(b>=1024&&i<5){b/=1024;i++} return sprintf("%.1f %s",b,u[i])}
      function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
      NR<=15 { w=(max>0)? $1*100/max : 0; if(w<0.6) w=0.6;
        p=$2; sub("^" home "/", "~/", p);
        printf "<div class=\"row\"><div class=\"meta\"><div class=\"name\">%s</div><div class=\"b\"><i style=\"width:%.1f%%;background:var(--toolchain)\"></i></div></div><div class=\"sz\">%s</div></div>\n",
               esc(p), w, hs($1) }
    ' "$SRC"
    printf '</div>\n'

    if [[ -s "$T_FILES" ]]; then
      printf '<div class="card"><h2>Largest individual files</h2><table>\n'
      awk -F'\t' -v home="$HOME" '
        function hs(b,  u,i){split("B KB MB GB TB",u," ");i=1;
          while(b>=1024&&i<5){b/=1024;i++} return sprintf("%.1f %s",b,u[i])}
        function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
        { p=$2; sub("^" home "/", "~/", p);
          printf "<tr><td class=\"p\">%s</td><td class=\"sz\">%s</td></tr>\n", esc(p), hs($1) }
      ' "$T_FILES"
      printf '</table></div>\n'
    fi

    if [[ -s "$T_KEEP" ]]; then
      printf '<div class="card"><h2>Review by hand — never auto-deleted</h2><table>\n'
      awk -F'\t' -v home="$HOME" '
        function hs(b,  u,i){split("B KB MB GB TB",u," ");i=1;
          while(b>=1024&&i<5){b/=1024;i++} return sprintf("%.1f %s",b,u[i])}
        function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
        NR<=12 { p=$2; sub("^" home "/", "~/", p);
          printf "<tr><td class=\"p\">%s</td><td>%s</td><td class=\"sz\">%s</td></tr>\n",
                 esc(p), esc($3), hs($1) }
      ' "$T_KEEP"
      printf '</table></div>\n'
    fi

    printf '<div class="foot">Generated by cloudshell-cleanup.sh &middot; only $HOME counts against the 5 GB quota</div>\n'
    printf '</div>\n'
  } > "$HTML_OUT"

  printf '  %sHTML report written to%s %s\n\n' "$C_DIM" "$C_RESET" "$HTML_OUT"
fi

if (( ! APPLY )); then
  printf '  %sDry run — nothing was deleted. Add --apply (and --deep for toolchain caches).%s\n\n' \
    "$C_DIM" "$C_RESET"
fi
