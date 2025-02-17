#!/usr/bin/env bash

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
bbrf use "$target"
timestamp=$(date +%Y%m%d-%H%M%S)
output_dir="$target"
mkdir -p "$output_dir"

echo "Target: $target"
echo ""

# --------------------------------------------------------------------------
# SUBDOMAIN DISCOVERY
# --------------------------------------------------------------------------
echo "=== [SUBDOMAIN DISCOVERY] ==="
echo "Collecting domains and creating a dynamic wordlist..."

echo "Running subfinder..."
subfinder_out="$output_dir/subfinder_${target}_subs_${timestamp}.txt"
bbrf scope in --wildcard --top | subfinder -silent | tee "$subfinder_out" | bbrf domain add - --show-new

echo "Running findomain..."
findomain_out="$output_dir/findomain_${target}_domains_${timestamp}.txt"
bbrf scope in --wildcard --top | xargs -I@ sh -c 'findomain -t @ -q' | tee "$findomain_out" | bbrf domain add - --show-new

echo "Running crt.sh..."
bbrf scope in --wildcard --top | sed 's/^\*\.//g' \
  | xargs -I@ sh -c 'curl -s "https://crt.sh/?q=@&output=json"' \
  | jq -r '.[].name_value' \
  | bbrf domain add - --show-new

echo "Running assetfinder..."
bbrf scope in --wildcard --top | sed 's/^\*\.//g' \
  | xargs -I@ sh -c 'assetfinder --subs-only @' \
  | bbrf domain add - --show-new

echo "Running jsubfinder..."
bbrf scope in --wildcard --top | jsubfinder search | bbrf domain add - --show-new

# Create the dynamic wordlist
subdomains_file="$output_dir/subdomains.txt"
urls_file="$output_dir/urls.txt"
endpoints_file="$output_dir/endpoints.txt"
dynamic_wordlist="$output_dir/wordlist.txt"

# Export all bbrf domains to subdomains_file
bbrf domains | anew "$subdomains_file"

# Use httpx on all subdomains to get live URLs
cat "$subdomains_file" | httpx -silent | anew "$urls_file"

# Use hakrawler to extract endpoints
cat "$urls_file" | hakrawler | anew "$endpoints_file"

# For each endpoint, use curl + haklistgen
while read -r url; do
  curl "$url" --insecure 2>/dev/null \
    | haklistgen \
    | anew "$dynamic_wordlist"
done < "$endpoints_file"

# Feed all files (subdomains, urls, endpoints) into haklistgen
cat "$subdomains_file" "$urls_file" "$endpoints_file" \
  | haklistgen \
  | anew "$dynamic_wordlist"

echo "Dynamic wordlist created: $dynamic_wordlist"
echo ""

# --------------------------------------------------------------------------
# Run puredns using the dynamic wordlist
# --------------------------------------------------------------------------
echo "Running puredns (subdomain brute force with new wordlist)..."
puredns_out="$output_dir/puredns_${target}_domains_${timestamp}.txt"
bbrf scope in --wildcard --top \
  | xargs -I{ sh -c 'puredns bruteforce "'"$dynamic_wordlist"'" { -r src/http/resolvers.txt -w "'"$puredns_out"'" -q' \
  | bbrf domain add - --show-new

# --------------------------------------------------------------------------
# SCANNING CACHED URLS
# --------------------------------------------------------------------------
echo "Running subtack..."
subtack_out="$output_dir/subtack_${target}_${timestamp}.txt"
bbrf domains | subtack -t 10 -silent | tee "$subtack_out" | notify -silent

echo "Running sdlookup..."
sdlookup_out="$output_dir/sdlookup_${target}_${timestamp}.txt"
bbrf domains \
  | httpx -silent -ip \
  | awk '{print $2}' | tr -d '[]' \
  | xargs -I@ sh -c 'echo @ | sdlookup -json | jq' \
  | tee "$sdlookup_out"

echo "Running gau..."
gau_out="$output_dir/gau_${target}_200_${timestamp}.txt"
bbrf scope in --wildcard --top | gau | nilo | anew "$gau_out"

echo "Running XSS polyglot scan..."
xssPolyglot_out="$output_dir/xssPolyglot_${target}_${timestamp}.txt"
tr '\n' '\0' < src/xss/polyglots.txt \
  | xargs -0 -n 1 bash -c '
     payload="$1"
     cat "'"$gau_out"'" | grep "=" | qsreplace "$payload" | airixss -payload "alert()" | grep -E -v "Not"
  ' _ \
  | tee "$xssPolyglot_out"

echo ""
echo "=== Process completed. Results saved in: $output_dir ==="

