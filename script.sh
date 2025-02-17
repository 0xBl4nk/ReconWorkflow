#!/bin/bash                                                                                                                                          
                                                                                                                                                     
# Parse arguments                                                                                                                                    
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
                                                                                                               
# Setup environment                                                                                            
bbrf use "$target"                                                                                             
timestamp=$(date +%Y%m%d-%H%M%S)                                                                               
output_dir="$target"                                                                                           
mkdir -p "$output_dir"                                                                                         
                                                                                                               
echo "Target: $target"                                                                                         
echo ""                                                                                                        
                  

# SUBDOMAIN  -  SCANNER
#######################################################################################################################################################
# Run subfinder                                                                                                
echo "Running subfinder..."                                                                                                            
subfinder_out="$output_dir/subfinder_${target}_subs_${timestamp}.txt"                                                                  
bbrf scope in --wildcard --top | subfinder -silent | tee "$subfinder_out" | bbrf domain add - --show-new                                             
                           
# Run findomain                                                    
echo "Running findomain..."                                                                                                            
findomain_out="$output_dir/findomain_${target}_domains_${timestamp}.txt"                                                               
bbrf scope in --wildcard --top | xargs -I@ sh -c 'findomain -t @ -q' | tee "$findomain_out" | bbrf domain add - --show-new                           
                                                                                                               
# Run crt.sh
echo "Running crt.sh (passive subdomain scanning)"
bbrf scope in --wildcard --top | xargs -I@ sh -c 'curl -s "https://crt.sh/?q=@&output=json"' | jq -r '.[].name_value' | bbrf domain add - --show-new

# Run puredns (bruteforce)
echo "Running puredns (subdomain bruteforce)"
bbrf scope in --wildcard --top | puredns bruteforce - -w src/wordlist/http/10m-subdomain.txt --resolvers src/http/resolvers.txt | bbrf domain add - --show-new

#######################################################################################################################################################

# Run subtack                                                                                                  
echo "Running subtack..."            
subtack_out="$output_dir/subtack_${target}_${timestamp}.txt"                                                                                         
bbrf domains | subtack -t 10 -silent | tee "$subtack_out" | notify -silent

# Run sdlookup                       
sdlookup_out="$output_dir/sdlookup_${target}_${timestamp}.txt"                                                                                       
bbrf domains | httpx -silent -ip | awk '{print $2}' | tr -d '[]' | xargs -I@ sh -c 'echo @ | sdlookup -json | jq' | tee "$sdlookup_out" 

# Scanning URL's
# Run gau
echo "Running gau..."                
gau_out="$output_dir/gau_${target}_200_${timestamp}.txt"
bbrf scope in --wildcard --top | gau | nilo | anew "$gau_out" 

# Gau: XSS Scanning
echo "Running xss polyglot scan"
xssPolyglot_out="$output_dir/xssPolyglot_${target}_${timestamp}.txt"
tr '\n' '\0' < src/xss/polyglots.txt | xargs -0 -n 1 bash -c '
  payload="$1"
  cat "$gau_out" | grep "=" | qsreplace "$payload" | airixss -payload "alert()" | grep -E -v "Not"
' _ | tee "$xssPolyglot_out"

echo "Process completed. Results saved in: $output_dir"





