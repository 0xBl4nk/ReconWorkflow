#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Verifying dependencies
for cmd in bbrf subfinder findomain puredns httpx hakrawler haklistgen sdlookup gau qsreplace airixss subtack anew nilo jq parallel amass; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is not installed or not found in PATH."
    exit 1
  fi
done

# Logging everything to a file
timestamp_now=$(date +%Y%m%d-%H%M%S)
log_file="script_log_$timestamp_now.txt"
exec > >(tee -a "$log_file") 2>&1

# --------------------------------------------------------------------------
# Recon Script -> github.com/0xBl4nk/ReconWorkflow
# --------------------------------------------------------------------------

# ------------------
# Parse arguments
# ------------------
target=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            target="$2"
            shift
            ;;
        *)
            # Ignore other arguments
            ;;
    esac
    shift
done

if [ -z "$target" ]; then
    echo "Error: --target not specified"
    exit 1
fi

# ------------------
# Setup environment
# ------------------
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bbrf use "$target"
timestamp=$(date +%Y%m%d-%H%M%S)
output_dir="$target"
mkdir -p "$output_dir"

# Using absolute paths for wordlists and resolvers
static_wordlist="$script_dir/src/wordlist/http/subdomain-wordlist.txt"
resolvers_file="$script_dir/src/http/resolvers.txt"

echo "Target: $target"
echo ""

# --------------------------------------------------------------------------
# SUBDOMAIN DISCOVERY
# --------------------------------------------------------------------------
echo "=== [SUBDOMAIN DISCOVERY] ==="
echo "Collecting domains and creating a dynamic wordlist..."

echo "Running subfinder..."
subfinder_out="$output_dir/subfinder_${target}_subs_${timestamp}.txt"
bbrf scope in --wildcard --top \
  | subfinder -silent \
  | anew "$subfinder_out" \
  | bbrf domain add - --show-new \
  > /dev/null

echo "Running findomain..."
findomain_out="$output_dir/findomain_${target}_domains_${timestamp}.txt"
bbrf scope in --wildcard --top \
  | xargs -I@ sh -c 'findomain -t @ -q' \
  | anew "$findomain_out" \
  | bbrf domain add - --show-new \
  > /dev/null

echo "Running crt.sh..."
bbrf scope in --wildcard --top \
  | sed 's/^\*\.//g' \
  | xargs -I@ sh -c 'curl -s "https://crt.sh/?q=@&output=json"' \
  | jq -r '.[].name_value' \
  | bbrf domain add - --show-new \
  > /dev/null

echo "Running assetfinder..."
bbrf scope in --wildcard --top \
  | sed 's/^\*\.//g' \
  | xargs -I@ sh -c 'assetfinder --subs-only @' \
  | bbrf domain add - --show-new \
  > /dev/null

echo "Running jsubfinder..."
bbrf scope in --wildcard --top \
  | jsubfinder search \
  | bbrf domain add - --show-new \
  > /dev/null

echo "Running amass..."
bbrf scope in --wildcard --top \
  | xargs -I@ sh -c '
      amass enum -rf "'"$resolvers_file"'" -nocolor -d @' \
  | grep "(FQDN)" \
  | awk "{print \$1}" \
  | sort -u \
  | anew "$output_dir/amass_subdomains.txt" \
  | bbrf domain add - --show-new \
  > /dev/null

# Run puredns using a static wordlist
echo "Running puredns (subdomain brute force with static wordlist)..."
puredns_static_out="$output_dir/puredns_${target}_static-subdomains_${timestamp}.txt"
bbrf scope in --wildcard --top \
  | xargs -I@ sh -c 'puredns bruteforce "'"$static_wordlist"'" @ -r "'"$resolvers_file"'" -w "'"$puredns_static_out"'" -q' \
  | bbrf domain add - --show-new \
  > /dev/null

# Create the dynamic wordlist
subdomains_file="$output_dir/subdomains.txt"
urls_file="$output_dir/urls.txt"
endpoints_file="$output_dir/endpoints.txt"
dynamic_wordlist="$output_dir/wordlist.txt"

echo "Creating dynamic wordlist..."

# Export all bbrf domains to subdomains_file
bbrf domains \
  | anew "$subdomains_file" \
  > /dev/null

# Use httpx on all subdomains to get live URLs
httpx -silent -l "$subdomains_file" \
  | anew "$urls_file" \
  > /dev/null

# Use hakrawler to extract endpoints
cat "$urls_file" \
  | hakrawler \
  | anew "$endpoints_file" \
  > /dev/null

# For each endpoint, use curl + haklistgen (parallel)
cat "$endpoints_file" \
  | parallel -j 5 'curl {} --insecure 2>/dev/null | haklistgen' \
  | anew "$dynamic_wordlist" \
  > /dev/null

# Feed all files (subdomains, urls, endpoints) into haklistgen
cat "$subdomains_file" "$urls_file" "$endpoints_file" \
  | haklistgen \
  | anew "$dynamic_wordlist" \
  > /dev/null

echo "Dynamic wordlist created: $dynamic_wordlist"
echo ""

# Run puredns using the dynamic wordlist
echo "Running puredns (subdomain brute force with new wordlist)..."
puredns_out="$output_dir/puredns_${target}_domains_${timestamp}.txt"
bbrf scope in --wildcard --top \
  | xargs -I@ sh -c 'puredns bruteforce "'"$dynamic_wordlist"'" @ -r "'"$resolvers_file"'" -w "'"$puredns_out"'" -q' \
  | bbrf domain add - --show-new \
  > /dev/null

# --------------------------------------------------------------------------
# SCANNING CACHED URLS
# --------------------------------------------------------------------------
echo "Running subtack..."
subtack_out="$output_dir/subtack_${target}_${timestamp}.txt"
bbrf domains \
  | subtack -t 10 -silent \
  | tee "$subtack_out" \
  | notify -silent \
  > /dev/null

echo "Running sdlookup..."
sdlookup_out="$output_dir/sdlookup_${target}_${timestamp}.txt"
bbrf domains \
  | httpx -silent -ip \
  | awk '{print $2}' | tr -d '[]' \
  | xargs -I@ sh -c 'echo @ | sdlookup -json | jq' \
  | tee "$sdlookup_out" \
  > /dev/null

echo "Running gau..."
gau_out="$output_dir/gau_${target}_200_${timestamp}.txt"
bbrf scope in --wildcard --top \
  | gau \
  | nilo \
  | anew "$gau_out" \
  > /dev/null

echo "Running XSS polyglot scan..."
xssPolyglot_out="$output_dir/xssPolyglot_${target}_${timestamp}.txt"
tr '\n' '\0' < "$script_dir/src/xss/polyglots.txt" \
  | xargs -0 -n 1 bash -c '
     payload="$1"
     cat "'"$gau_out"'" | grep "=" | qsreplace "$payload" | airixss -payload "alert()" | grep -E -v "Not"
  ' _ \
  | tee "$xssPolyglot_out" \
  > /dev/null

echo ""
echo "=== Process completed. Results saved in: $output_dir ==="
echo "Log file: $log_file"
