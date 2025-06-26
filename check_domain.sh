# check_domain - v2.0.0
# Author: A. Stoyanov
# GitHub: https://github.com/a-stoyanov/zabbix-domain-expiry
# License: Apache License 2.0
# Original source: https://github.com/glensc/monitoring-plugin-check_domain (E. Ruusamäe)
#
# This script checks the expiration status of a domain using RDAP or WHOIS protocols.
# It outputs a JSON-formatted status including the state (OK, WARNING, CRITICAL, UNKNOWN),
# days left until expiration, expiration date, days since expired (if applicable), and a message.
#
# Usage: check_domain.sh -h | -d <domain> [-c <critical>] [-w <warning>] [-P <path_to_whois>] [-s <whois_server>] [-r <rdap_server>] [-z]
# Note: domain (-d) is required
#
# Examples:
#   ./check_domain.sh -d example.com
#   ./check_domain.sh -d example.com -w 15 -c 5 -r https://rdap.example.com -s whois.example.com -z
#
# Options:
#   -h, --help            Display detailed help information
#   -V, --version         Display version information in JSON format
#   -d, --domain          Specify the domain name to check (required)
#   -w, --warning         Set warning threshold in days (default: 30)
#   -c, --critical        Set critical threshold in days (default: 7)
#   -P, --path            Specify path to whois executable
#   -s, --whois-server    Specify WHOIS server hostname (use "" for default rfc-3912 lookup)
#   -r, --rdap-server     Specify RDAP server URL (use "" for IANA lookup)
#   -z, --debug           Enable debug output to stderr
#
# Exit Codes:
#   0: STATE_OK           Domain is valid and not near expiration
#   1: STATE_WARNING      Domain is nearing expiration (within warning threshold)
#   2: STATE_CRITICAL     Domain is expired or very close to expiration (within critical threshold)
#   3: STATE_UNKNOWN      Unable to determine domain status (e.g., invalid domain, no WHOIS server)
#
# Dependencies:
#   - curl: For RDAP queries
#   - mktemp: For creating temporary files
#   - date: For date calculations
#   - whois: For WHOIS queries
#   - grep: For parsing output
#   - awk: For parsing WHOIS and RDAP data
#   - jq: For parsing RDAP JSON responses
#
# Notes:
#   - The script first attempts RDAP lookup and if that fails, it falls back to WHOIS.
#   - Specific switches (-r / -s) for RDAP and WHOIS respectively allow queries against target servers (e.g: -r https://valid.rdap.server -s whois.godaddy.com)
#   - Debug output is enabled with -z and sent to stderr.
#   - Temporary files are cleaned up on exit.

#!/bin/sh
set -e
exec 2>&1

# Create temp directory for storing output files
tmpdir=$(mktemp -d -t check_domain.XXXXXX 2>/dev/null || echo "${TMPDIR:-/tmp}/check_domain_$$_$RANDOM")
[ -d "$tmpdir" ] || mkdir -p "$tmpdir" || die "$STATE_UNKNOWN" "State: UNKNOWN ; Cannot create temporary directory"

PROGRAM="${0##*/}"
VERSION=2.0.0
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

default_warning="30"
default_critical="7"
whois_server_override="0"
rdap_server_override="0"
awk="${AWK:-awk}"
outfile="$tmpdir/whois_output.txt"
error_file="$tmpdir/error.txt"
rdap_bootstrap_file="$tmpdir/rdap_bootstrap.json"
debug="false"

# Terminates the script with a specified exit code and JSON-formatted message
# Parameters:
#   $1: Exit code (STATE_OK, STATE_WARNING, STATE_CRITICAL, or STATE_UNKNOWN)
#   $2: Message describing the script's status
# Returns:
#   Outputs JSON with state, days left, expire date, days since expired, and message
#   Cleans up temporary files and exits with the specified code
die() {
    local rc="$1" msg="$2"
    local state
    case "$rc" in
        0) state="OK" ;;
        1) state="WARNING" ;;
        2) state="CRITICAL" ;;
        3) state="UNKNOWN" ;;
        *) state="UNKNOWN" ;;
    esac

    days_left="${expdays:-0}"
    expire_date="${expdate:-unknown}"
    days_since_expired=$([ "$days_left" -lt 0 ] && echo "${days_left#-}" || echo "0")

    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Entering die() with rc=$rc, msg='$msg'" >&2
        echo "INFO [$(date +'%H:%M:%S')]: Cleaning up temporary directory: $tmpdir and files: $outfile $rdap_bootstrap_file $error_file" >&2
    fi

    json_output=$(printf '{"state":"%s","days_left":%s,"days_since_expired":%s,"expire_date":"%s","message":"%s"}' \
        "$state" "$days_left" "$days_since_expired" "$expire_date" "$msg")

    # Output JSON to stderr
    printf '%s\n' "$json_output" >&2

    # Clean up temporary files
    rm -rf "$tmpdir" 2>/dev/null

    exit "$rc"
}

# Checks if a string is a valid numeric value
# Parameters:
#   $1: String to check
# Returns:
#   0 if numeric, 1 otherwise
is_numeric() {
    echo "$1" | grep -q -E '^[0-9]+$'
}

# Validates if a string is a valid URL or "0"
# Parameters:
#   $1: String to validate
# Returns:
#   0 if valid URL or "0", 1 otherwise
is_valid_url() {
    echo "$1" | grep -q -E '^https?://[a-zA-Z0-9.-]+(/.*)?$|^0$'
}

# Validates if a string is a valid WHOIS server hostname or "0"
# Parameters:
#   $1: String to validate
# Returns:
#   0 if valid hostname or "0", 1 otherwise
is_valid_server() {
    echo "$1" | grep -q -E '^[a-zA-Z0-9.-]+$|^0$'
}

# Outputs the script's version in JSON format
# Parameters: None
# Returns:
#   JSON object with the version number
version() {
    echo "{\"version\":\"$VERSION\"}"
}

# Displays basic usage information
# Parameters: None
# Returns:
#   Outputs usage string to stdout
usage() {
    echo "Usage: $PROGRAM -h | -d <domain> [-c <critical>] [-w <warning>] [-P <path_to_whois>] [-s <whois_server>] [-r <rdap_server>] [-z]"
}

# Displays detailed help information
# Parameters: None
# Returns:
#   Outputs detailed help message to stdout
fullusage() {
    cat <<EOF
check_domain - v$VERSION

This script checks the expiration status of a domain using RDAP or WHOIS protocols.

Usage: $PROGRAM -h | -d <domain> [-c <critical>] [-w <warning>] [-P <path_to_whois>] [-s <whois_server>] [-r <rdap_server>] [-z]
Options:
-h|--help            Print detailed help
-V|--version         Print version information
-d|--domain          Domain name to check
-w|--warning         Warning threshold (days)
-c|--critical        Critical threshold (days)
-P|--path            Path to whois executable
-s|--whois-server    Specific WHOIS server (use "" or for default rfc-3912 lookup)
-r|--rdap-server     Specific RDAP server URL (use "" for IANA lookup)
-z|--debug           Enable debug output
EOF
}

# Adjusts RDAP URL for specific TLDs (e.g., .uk, .br, .jp)
# Parameters:
#   $1: TLD (e.g., "uk", "br")
#   $2: RDAP server URL
# Returns:
#   Adjusted RDAP server URL or original if no adjustment needed
adjust_rdap_url() {
    local tld="$1" rdap_server="$2"
    case "$tld" in
        uk)
            if ! echo "$rdap_server" | grep -q -E '/uk/$'; then
                rdap_server="${rdap_server%/}/uk/"
                if [ "$debug" = "true" ]; then
                    echo "INFO [$(date +'%H:%M:%S')]: Adjusted RDAP server for .uk TLD to: $rdap_server" >&3
                fi
            fi
            ;;
        br)
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: No RDAP URL adjustment needed for .br TLD (preserves /v1/): $rdap_server" >&3
            fi
            ;;
        jp)
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: No RDAP URL adjustment needed for .jp TLD (preserves /rdap/): $rdap_server" >&3
            fi
            ;;
        *)
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: No RDAP URL adjustment needed for TLD .$tld" >&3
            fi
            ;;
    esac
    echo "$rdap_server"
}

# Retrieves RDAP server URL for a given TLD from IANA bootstrap file
# Parameters:
#   $1: TLD (e.g., "com", "uk")
# Returns:
#   RDAP server URL or empty string if not found
#   Exit code 0 on success, 1 on failure
get_rdap_server() {
    local tld="$1"
    local bootstrap_url="https://data.iana.org/rdap/dns.json"

    rdap_bootstrap_file="$tmpdir/rdap_bootstrap.json"
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Using rdap_bootstrap_file: $rdap_bootstrap_file" >&3
    fi

    if [ ! -s "$rdap_bootstrap_file" ]; then
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: Fetching IANA RDAP bootstrap from $bootstrap_url" >&3
        fi
        set +e
        curl -s -f --retry 3 --connect-timeout 3 --max-time 5 "$bootstrap_url" > "$rdap_bootstrap_file" 2>"$error_file"
        curl_rc=$?
        set -e
        if [ $curl_rc -ne 0 ]; then
            if [ "$debug" = "true" ]; then
                echo "ERROR [$(date +'%H:%M:%S')]: Failed to fetch $bootstrap_url, curl exit code: $curl_rc, error: $(cat "$error_file")" >&3
            fi
            return 1
        fi
        if ! grep -q '"services"' "$rdap_bootstrap_file"; then
            if [ "$debug" = "true" ]; then
                echo "ERROR [$(date +'%H:%M:%S')]: Invalid RDAP bootstrap file, missing 'services' key" >&3
            fi
            rm -f "$rdap_bootstrap_file"
            return 1
        fi
    fi

    # Check if jq is available for parsing JSON
    local rdap_server
    if command -v jq >/dev/null 2>&1; then
        set +e
        rdap_server=$(jq -r --arg tld "$tld" '.services[] | select(.[0][] == $tld) | .[1][0]' "$rdap_bootstrap_file" 2>"$error_file")
        jq_rc=$?
        set -e
        if [ $jq_rc -ne 0 ] || [ -z "$rdap_server" ] || ! echo "$rdap_server" | grep -q -E '^https://'; then
            if [ "$debug" = "true" ]; then
                echo "ERROR [$(date +'%H:%M:%S')]: jq failed or invalid/no RDAP server found for TLD .$tld, jq exit code: $jq_rc, output: '$rdap_server', error: $(cat "$error_file")" >&3
            fi
        else
            # Ensure we only use the first RDAP server if multiple are returned
            url_count=$(echo "$rdap_server" | wc -l)
            if [ "$url_count" -gt 1 ]; then
                if [ "$debug" = "true" ]; then
                    echo "ERROR [$(date +'%H:%M:%S')]: Multiple RDAP servers found for TLD .$tld: $rdap_server, using first" >&3
                fi
                rdap_server=$(echo "$rdap_server" | head -n 1)
            fi
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: RDAP server for TLD .$tld: $rdap_server" >&3
            fi
            echo "$rdap_server"
            return 0
        fi
    fi
    
    echo "$rdap_server"
    return 0
}

# Queries RDAP server for domain expiration date
# Parameters:
#   $1: Domain name
# Returns:
#   Expiration date in YYYY-MM-DD format or empty string if RDAP fails
#   Exit code 0 on success or fallback to WHOIS
get_rdap_expiration() {
    local domain="$1"
    local tld="${domain##*.}"
    local rdap_server="$rdap_server_override"
    local response curl_rc error_output

    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Starting RDAP lookup for $domain" >&3
    fi

    if [ "$rdap_server" = "0" ]; then
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: Attempting IANA RDAP lookup for TLD .$tld" >&3
        fi
        rdap_server=$(get_rdap_server "$tld") || {
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: No RDAP server found for TLD .$tld, falling back to WHOIS" >&3
            fi
            return 0
        }
        if [ -z "$rdap_server" ] || ! echo "$rdap_server" | grep -q -E '^https://'; then
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: Invalid RDAP server for TLD .$tld, falling back to WHOIS" >&3
            fi
            return 0
        fi
    fi

    rdap_server=$(adjust_rdap_url "$tld" "$rdap_server")

    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Using RDAP server: $rdap_server" >&3
    fi
    if ! echo "$rdap_server" | grep -q -E '^https?://[a-zA-Z0-9.-]+(/.*)?$|^0$'; then
        if [ "$debug" = "true" ]; then
            echo "ERROR [$(date +'%H:%M:%S')]: Invalid RDAP server URL format: $rdap_server, falling back to WHOIS" >&3
        fi
        return 0
    fi
    rdap_url="${rdap_server%/}/domain/$domain"

    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Querying RDAP URL: $rdap_url" >&3
    fi
    set +e
    error_output=$(curl -s -f --retry 3 --connect-timeout 3 --max-time 5 "$rdap_url" 2>"$error_file")
    curl_rc=$?
    set -e
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: curl completed with exit code $curl_rc" >&3
    fi
    if [ $curl_rc -ne 0 ]; then
        if [ "$debug" = "true" ]; then
            echo "ERROR [$(date +'%H:%M:%S')]: curl failed for $rdap_url, error: $(cat "$error_file"), code: $curl_rc, falling back to WHOIS" >&3
        fi
        return 0
    fi
    response="$error_output"
    if [ -z "$response" ]; then
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: RDAP query failed for $rdap_url, no response, falling back to WHOIS" >&3
        fi
        return 0
    fi

    if command -v jq >/dev/null 2>&1; then
        set +e
        expiration=$(echo "$response" | jq -r '.events[] | select(.eventAction | test("expiration")) | .eventDate' 2>"$error_file")
        jq_rc=$?
        set -e
        if [ $jq_rc -ne 0 ] || [ -z "$expiration" ]; then
            if [ "$debug" = "true" ]; then
                echo "INFO [$(date +'%H:%M:%S')]: jq failed to parse RDAP response for $rdap_url, error: $(cat "$error_file"), falling back to WHOIS" >&3
            fi
            return 0
        fi
    else
        expiration=$(echo "$response" | grep -A 1 '"eventAction":".*expiration"' | grep '"eventDate"' | awk -F'"' '{print $4}')
    fi

    if [ -z "$expiration" ]; then
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: No expiration date found in RDAP response for $rdap_url, falling back to WHOIS" >&3
        fi
        return 0
    fi

    echo "$expiration" | awk -F'T' '{print $1}'
    return 0
}

# Preprocesses command-line arguments to handle empty server values
# Parameters:
#   $@: All command-line arguments
# Returns:
#   Space-separated string of processed arguments
preprocess_args() {
    new_args=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -r|--rdap-server)
                shift
                if [ $# -gt 0 ] && [ -z "$1" ]; then
                    new_args="$new_args -r 0"
                    shift
                else
                    new_args="$new_args -r"
                    [ $# -gt 0 ] && new_args="$new_args $1"
                    [ $# -gt 0 ] && shift
                fi
                ;;
            -s|--whois-server)
                shift
                if [ $# -gt 0 ] && [ -z "$1" ]; then
                    new_args="$new_args -s 0"
                    shift
                else
                    new_args="$new_args -s"
                    [ $# -gt 0 ] && new_args="$new_args $1"
                    [ $# -gt 0 ] && shift
                fi
                ;;
            *)
                new_args="$new_args $1"
                shift
                ;;
        esac
    done
    echo "$new_args"
}

# Parses command-line arguments and sets global variables
# Parameters:
#   $@: Command-line arguments
# Returns:
#   Sets global variables (domain, whois_server_override, rdap_server_override, etc.)
#   Exits with STATE_UNKNOWN on invalid arguments
parse_arguments() {
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Entering parse_arguments with args: $@" >&2
    fi
    local short_opts="hVd:w:c:P:s:r:z"
    local long_opts="help,version,domain:,warning:,critical:,path:,whois-server:,rdap-server:,debug"
    local default_warning="30" default_critical="7"
    local processed_args=$(preprocess_args "$@")
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Processed args: $processed_args" >&2
    fi

    set +e
    args=$(getopt -o "$short_opts" --long "$long_opts" -u -n "$PROGRAM" -- $processed_args 2>"$error_file")
    getopt_rc=$?
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: getopt returned: $args, rc: $getopt_rc" >&2
    fi
    if [ $getopt_rc -ne 0 ]; then
        echo "ERROR [$(date +'%H:%M:%S')]: getopt failed to parse arguments: $(cat "$error_file")" >&2
        die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid arguments"
    fi
    eval set -- "$args" 2>"$error_file"
    eval_rc=$?
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: eval set -- returned rc: $eval_rc" >&2
    fi
    if [ $eval_rc -ne 0 ]; then
        echo "ERROR [$(date +'%H:%M:%S')]: eval set -- failed: $(cat "$error_file")" >&2
        die "$STATE_UNKNOWN" "State: UNKNOWN ; Argument processing failed"
    fi
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: After eval set --: $@" >&2
    fi

    warning="$default_warning"
    critical="$default_critical"
    domain=""
    whois_server_override="0"
    rdap_server_override="0"
    whoispath=""

    while [ $# -gt 0 ]; do
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: Processing argument: $1, remaining args: $@" >&2
        fi
        case "$1" in
            -c|--critical)
                if [ $# -ge 2 ] && is_numeric "$2"; then
                    critical="$2"
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Set critical=$critical" >&2
                    fi
                    shift 2
                else
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Invalid or missing critical value, using default: $default_critical" >&2
                    fi
                    critical="$default_critical"
                    shift
                    [ $# -ge 1 ] && ! echo "$1" | grep -q '^-' && shift
                fi
                ;;
            -w|--warning)
                if [ $# -ge 2 ] && is_numeric "$2"; then
                    warning="$2"
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Set warning=$warning" >&2
                    fi
                    shift 2
                else
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Invalid or missing warning value, using default: $default_warning" >&2
                    fi
                    warning="$default_warning"
                    shift
                    [ $# -ge 1 ] && ! echo "$1" | grep -q '^-' && shift
                fi
                ;;
            -d|--domain)
                if [ $# -ge 2 ]; then
                    domain="$2"
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Set domain=$domain" >&2
                    fi
                    shift 2
                else
                    shift
                fi
                ;;
            -P|--path)
                if [ $# -ge 2 ]; then
                    whoispath="$2"
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Set whoispath=$whoispath" >&2
                    fi
                    shift 2
                else
                    shift
                fi
                ;;
            -s|--whois-server)
                if [ $# -ge 2 ]; then
                    whois_server_override="$2"
                    is_valid_server "$whois_server_override" || die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid WHOIS server: '$whois_server_override'"
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Set whois_server='$whois_server_override'" >&2
                    fi
                    shift 2
                else
                    shift
                fi
                ;;
            -r|--rdap-server)
                if [ $# -ge 2 ]; then
                    rdap_server_override="$2"
                    is_valid_url "$rdap_server_override" || die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid RDAP server: '$rdap_server_override'"
                    if [ "$debug" = "true" ]; then
                        echo "INFO [$(date +'%H:%M:%S')]: Set rdap_server='$rdap_server_override'" >&2
                    fi
                    shift 2
                else
                    shift
                fi
                ;;
            -V|--version)
                version
                exit 0
                ;;
            -z|--debug)
                debug="true"
                if [ "$debug" = "true" ]; then
                    echo "INFO [$(date +'%H:%M:%S')]: Set debug=$debug" >&2
                fi
                shift
                ;;
            -h|--help)
                fullusage
                exit 0
                ;;
            --)
                if [ "$debug" = "true" ]; then
                    echo "INFO [$(date +'%H:%M:%S')]: Entering -- case" >&2
                fi
                shift
                break
                ;;
            *)
                die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid argument: $1"
                ;;
        esac
    done

    set -e
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Successfully completed parsing. domain=$domain, whois_server=$whois_server_override, rdap_server=$rdap_server_override, warning=$warning, critical=$critical" >&2
    fi
    [ -z "$domain" ] && die "$STATE_UNKNOWN" "State: UNKNOWN ; No domain specified"
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Exiting parse_arguments" >&2
    fi
}

# Configures the whois command path
# Parameters: None
# Returns:
#   Sets global whois variable to valid whois executable path
#   Exits with STATE_UNKNOWN if whois is not found
setup_whois() {
    if [ -n "$whoispath" ]; then
        [ -x "$whoispath" ] && whois=$whoispath
        [ -x "$whoispath/whois" ] && whois=$whoispath/whois
        [ -n "$whois" ] || die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid whois path"
    else
        command -v whois >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; whois not found in PATH"
        whois=whois
    fi
}

# Executes WHOIS query for the domain and saves output
# Parameters: None
# Returns:
#   Saves WHOIS output to $outfile
#   Exits with STATE_UNKNOWN on query failure or invalid domain
run_whois() {
    setup_whois
    local output error
    if [ "$whois_server_override" = "0" ]; then
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: Running whois for $domain without specific server" >&2
        fi
        set +e
        output=$("$whois" "$domain" 2>&1)
        error=$?
        set -e
    else
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: Running whois for $domain with server $whois_server_override" >&2
        fi
        set +e
        output=$("$whois" -h "$whois_server_override" "$domain" 2>&1)
        error=$?
        set -e
    fi
    echo "$output" > "$outfile"
    cp "$outfile" "$tmpdir/whois_raw.txt"

    [ -s "$outfile" ] || die "$STATE_UNKNOWN" "State: UNKNOWN ; Domain $domain doesn't exist or no WHOIS server available"

    if grep -q -E "No match for|NOT FOUND|NO DOMAIN" "$outfile"; then
        die "$STATE_UNKNOWN" "State: UNKNOWN ; Domain $domain doesn't exist"
    fi

    if grep -q -E "Query rate limit exceeded|WHOIS_LIMIT_EXCEEDED" "$outfile"; then
        die "$STATE_UNKNOWN" "State: UNKNOWN ; Rate limited WHOIS"
    fi

    if [ $error -ne 0 ] || grep -q -E "fgets|Connection refused|Timeout|No whois server|socket" "$outfile"; then
        die "$STATE_UNKNOWN" "State: UNKNOWN ; WHOIS query failed for $domain with error $error"
    fi
}

# Extracts expiration date from WHOIS output file
# Parameters:
#   $1: Path to WHOIS output file
# Returns:
#   Expiration date in YYYY-MM-DD format
#   Exits with STATE_UNKNOWN if parsing fails
get_expiration() {
    local outfile="$1"
    local expiration
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Running awk on $outfile" >&2
    fi
    set +e
    expiration=$($awk '
    BEGIN {
        split("january february march april may june july august september october november december", months, " ")
        for (i in months) {
            Month[tolower(months[i])] = sprintf("%02d", i)
            Mon[tolower(substr(months[i],1,3))] = sprintf("%02d", i)
        }
        HH_MM_DD = "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
        YYYY = "[0-9][0-9][0-9][0-9]"
        DD = "[0-9][0-9]"
        MON = "[A-Za-z][a-z][a-z]"
        DATE_DD_MM_YYYY_DOT = "[0-9][0-9]\\.[0-9][0-9]\\.[0-9][0-9][0-9][0-9]"
        DATE_DD_MON_YYYY = "[0-9][0-9]-[A-Za-z][a-z][a-z]-[0-9][0-9][0-9][0-9]"
        DATE_ISO_FULL = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T"
        DATE_YYYY_MM_DD_DASH = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
        DATE_YYYY_MM_DD_DOT = "[0-9][0-9][0-9][0-9]\\.[0-9][0-9]\\.[0-9][0-9]"
        DATE_YYYY_MM_DD_SLASH = "[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]"
        DATE_DD_MM_YYYY_SLASH = "[0-9][0-9]/[0-9][0-9]/[0-9][0-9][0-9][0-9]"
        DATE_YYYY_MM_DD_NUM = "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
        DATE_YYYY_MM_DD_DASH_HH_MM_SS = DATE_YYYY_MM_DD_DASH " " HH_MM_DD
        DATE_DD_MM_YYYY_DOT_HH_MM_SS = DATE_DD_MM_YYYY_DOT " " HH_MM_DD
        DATE_DAY_MON_DD_HHMMSS_TZ_YYYY = "[A-Z][a-z][a-z] [A-Z][a-z][a-z] [0-9][0-9] " HH_MM_DD " GMT " YYYY
        DATE_DD_MON_YYYY_HHMMSS = "[0-9][0-9]-" MON "-" YYYY " " HH_MM_DD
        DATE_DD_MON_YYYY_HHMMSS_TZ = "[0-9][0-9]-" MON "-" YYYY " " HH_MM_DD " UTC"
        DATE_YYYYMMDD_HHMMSS = DATE_YYYY_MM_DD_DOT " " HH_MM_DD
        DATE_DD_MM_YYYY_SLASH_HHMMSS_TZ = DATE_DD_MM_YYYY_SLASH " " HH_MM_DD " [A-Z]+"
        DATE_DD_MON_YYYY_HHMMSS_TZ_SPACE = "[0-9][0-9] " MON " " YYYY " " HH_MM_DD " UTC"
        DATE_YYYY_MM_DD_DASH_HH_MM_SS_TZ_SPACE_OFFSET = DATE_YYYY_MM_DD_DASH " " HH_MM_DD " \\(UTC\\+[0-9]+\\)"
        DATE_YYYY_MM_DD_HH_MM_SS = DATE_YYYY_MM_DD_DASH " " HH_MM_DD "\\+[0-9]+"
        DATE_ISO_LIKE = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] "
    }

    function mon2moy(month) { month = tolower(month); return Mon[month] ? Mon[month] : 0 }
    function month2moy(month) { month = tolower(month); return Month[month] ? Month[month] : 0 }
    function get_iso_date(line, fs, field, a, d) {
        if (split(line, a, fs)) { if (split(a[field], d, /T/)) { return d[1] } }
    }
    
    # Matches "expires: Month Day Year" (e.g., "expires: December 31 2025")
    # Extracts year ($4), month ($2 via month2moy), day ($3) and formats as YYYY-MM-DD
    /expires:/ && $0 ~ /[A-Za-z]+[ \t]+[0-9]+[ \t]+[0-9]{4}/ { printf("%s-%02d-%02d\n", $4, month2moy($2), $3); exit }

    # Matches "Expiry Date: DD-MMM-YYYY" or "expiry date: DD-MMM-YYYY" (e.g., "Expiry Date: 31-Dec-2025")
    # Extracts date via regex match, splits by "-", converts month (MMM) to number, formats as YYYY-MM-DD
    /[Ee][xpiryYy][Dd][Aa][Tt][Ee]:.*[0-9]{2}-[A-Za-z]{3}-[0-9]{4}/ { match($0, /[0-9]{2}-[A-Za-z]{3}-[0-9]{4}/); date = substr($0, RSTART, RLENGTH); split(date, a, "-"); m = mon2moy(a[2]); if (m) { printf("%04d-%02d-%02d", a[3], m, a[1]); exit } }

    # Matches "Expire Date: YYYY-MM-DD" or "expire-date: YYYY-MM-DD" (e.g., "Expire Date: 2025-12-31")
    # Removes prefix before colon, extracts YYYY-MM-DD via regex, outputs directly
    /[Ee]xpire[- ][Dd]ate:.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { sub(/^.*: */, "", $0); match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); print substr($0, RSTART, RLENGTH); exit }

    # Matches "Expiry Date: DD/MM/YYYY" (e.g., "Expiry Date: 31/12/2025")
    # Splits last field ($NF) by "/", formats as YYYY-MM-DD using fields 3, 2, 1
    /[Ee]xpiry [Dd]ate:.*[0-3][0-9]\/[0-1][0-9]\/[0-9]{4}/ { split($NF, a, "/"); printf("%04d-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "Expiry Date: YYYY/MM/DD" (e.g., "Expiry Date: 2025/12/31")
    # Splits last field ($NF) by "/", formats as YYYY-MM-DD using fields 1, 2, 3
    /[Ee]xpiry [Dd]ate:.*[0-9]{4}\/[0-9]{2}\/[0-9]{2}/ { split($NF, a, "/"); printf("%04d-%02d-%02d", a[1], a[2], a[3]); exit }

    # Matches "Expiration Date: YYYY-MM-DDThh:mm:ss" (e.g., "Expiration Date: 2025-12-31T23:59:59")
    # Uses get_iso_date to split by ":" and extract YYYY-MM-DD before "T"
    /Expiration Date:.*[0-9]{4}-[0-9]{2}-[0-9]{2}T/ { print get_iso_date($0, ":", 2); exit }

    # Matches "Expiration Date: DD.MM.YYYY" (e.g., "Expiration Date: 31.12.2025")
    # Splits last field ($NF) by ".", formats as YYYY-MM-DD using fields 3, 2, 1
    /Expiration [Dd]ate:.*[0-9]{2}\.[0-9]{2}\.[0-9]{4}/ { split($NF, a, "."); printf("%04d-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "expires: YYYYMMDD" (e.g., "expires: 20251231")
    # Extracts substrings from second field ($2) for year, month, day, formats as YYYY-MM-DD
    /expires:.*[0-9]{8}/ { printf("%s-%s-%s", substr($2,1,4), substr($2,5,2), substr($2,7,2)); exit }

    # Matches "[Expires on] YYYY/MM/DD" (e.g., "[Expires on] 2025/12/31")
    # Splits last field ($NF) by "/", formats as YYYY-MM-DD using fields 1, 2, 3
    /\[Expires on\].*[0-9]{4}\/[0-9]{2}\/[0-9]{2}/ { split($NF, a, "/"); printf("%04d-%02d-%02d", a[1], a[2], a[3]); exit }

    # Matches "Record expires on YYYY-MM-DD" (e.g., "Record expires on 2025-12-31")
    # Extracts YYYY-MM-DD via regex match, outputs directly
    /Record expires on[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); print substr($0, RSTART, RLENGTH); exit }

    # Matches "Expiry Date: YYYY-MM-DD" (e.g., "Expiry Date: 2025-12-31")
    # Extracts YYYY-MM-DD via regex match, outputs directly
    /Expiry Date:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); print substr($0, RSTART, RLENGTH); exit }

    # Matches "Domain Expiration Date: MMM MMM DD hh:mm:ss YYYY" (e.g., "Domain Expiration Date: Wed Dec 31 23:59:59 2025")
    # Extracts DD MMM YYYY via regex, splits by space, converts month (MMM) to number, formats as YYYY-MM-DD
    /Domain Expiration Date:[[:space:]]*[A-Za-z]{3} [A-Za-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}/ { match($0, /[0-9]{2} [A-Za-z]{3} [0-9]{4}/); date = substr($0, RSTART, RLENGTH); split(date, a, " "); m = mon2moy(a[2]); if (m) { printf("%04d-%02d-%02d", a[3], m, a[1]); exit } }

    # Matches "expires: DD-MMM-YYYY" (e.g., "expires: 31-Dec-2025")
    # Splits third field ($3) by "-", converts month (MMM) to number, formats as YYYY-MM-DD
    /expires:.*[0-9]{2}-[A-Za-z]{3}-[0-9]{4}/ { split($3, a, "-"); printf("%s-%s-%s\n", a[3], mon2moy(a[2]), a[1]); exit }

    # Matches "Expiration date: DD.MM.YYYY hh:mm" (e.g., "Expiration date: 31.12.2025 23:59")
    # Splits second-to-last field ($(NF-1)) by ".", formats as YYYY-MM-DD using fields 3, 2, 1
    /Expiration date:.*[0-9]{2}\.[0-9]{2}\.[0-9]{4} [0-9]{2}:[0-9]{2}/ { split($(NF-1), a, "."); printf("%s-%s-%s", a[3], a[2], a[1]); exit }

    # Matches "expires: YYYY-MM-DD" (e.g., "expires: 2025-12-31")
    # Outputs last field ($NF) directly as YYYY-MM-DD
    /expires:.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { print $NF; exit }

    # Matches "expire: YYYY-MM-DD hh:mm:ss" (e.g., "expire: 2025-12-31 23:59:59")
    # Extracts YYYY-MM-DD via regex match, outputs directly
    /expire:.*[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/ { match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); print substr($0, RSTART, RLENGTH); exit }

    # Matches "expire: YYYY-MM-DD hh:mm" (e.g., "expire: 2025-12-31 23:59")
    # Splits entire line by space, splits first field by "-", formats as YYYY-MM-DD
    /expire:.*[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}/ { split($0, a, " "); split(a[1], b, "-"); printf("%s-%s-%s", b[1], b[2], b[3]); exit }

    # Matches "renewal date: YYYY.MM.DD hh" (e.g., "renewal date: 2025.12.31 23")
    # Splits second-to-last field ($(NF-1)) by ".", formats as YYYY-MM-DD using fields 1, 2, 3
    /renewal date:.*[0-9]{4}\.[0-9]{2}\.[0-9]{2} [0-9]{2}/ { split($(NF-1), a, "."); printf("%s-%s-%s", a[1], a[2], a[3]); exit }

    # Matches "paid-till: YYYY.MM.DD" (e.g., "paid-till: 2025.12.31")
    # Splits second field ($2) by ".", formats as YYYY-MM-DD using fields 1, 2, 3
    /paid-till:.*[0-9]{4}\.[0-9]{2}\.[0-9]{2}/ { split($2, a, "."); printf("%s-%s-%s", a[1], a[2], a[3]); exit }

    # Matches "paid-till: YYYY-MM-DD" or "paid-till: YYYY-MM-DDThh:mm:ss" (e.g., "paid-till: 2025-07-03T04:00:09Z")
    # Extracts YYYY-MM-DD via regex match, outputs directly
    /paid-till:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}(T.*)?$/ { match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); print substr($0, RSTART, RLENGTH); exit }

    # Matches "Valid Until: YYYY-MM-DD" (e.g., "Valid Until: 2025-12-31")
    # Outputs last field ($NF) directly as YYYY-MM-DD
    /Valid Until:.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { print $NF; exit }

    # Matches "expire: DD.MM.YYYY" (e.g., "expire: 31.12.2025")
    # Splits second field ($2) by ".", formats as YYYY-MM-DD using fields 3, 2, 1
    /expire:.*[0-9]{2}\.[0-9]{2}\.[0-9]{4}/ { split($2, a, "."); printf("%s-%s-%s", a[3], a[2], a[1]); exit }

    # Matches "expires: YYYY-MM-DD" (e.g., "expires: 2025-12-31")
    # Outputs last field ($NF) directly as YYYY-MM-DD
    /expires:.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { print $NF; exit }

    # Matches "domain_datebilleduntil: YYYY-MM-DDThh:mm:ss" (e.g., "domain_datebilleduntil: 2025-12-31T23:59:59")
    # Uses get_iso_date to split by ":" and extract YYYY-MM-DD before "T"
    /domain_datebilleduntil:.*[0-9]{4}-[0-9]{2}-[0-9]{2}T/ { print get_iso_date($0, ":", 2); exit }
    
    # Matches "Registrar Registration Expiration Date: YYYY-MM-DDThh:mm:ss[optional TZ]" (e.g., "Registrar Registration Expiration Date: 2025-12-31T23:59:59Z")
    # Extracts YYYY-MM-DD using regex match, outputs directly
    /Registrar Registration Expiration Date:.*[0-9]{4}-[0-9]{2}-[0-9]{2}T/ { match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); printf("%s", substr($0, RSTART, RLENGTH)); exit }

    # Matches "Expiration Date (dd/mm/yyyy): DD/MM/YYYY" (e.g., "Expiration Date (dd/mm/yyyy): 31/12/2025")
    # Splits third field ($3) by "/", formats as YYYY-MM-DD using fields 3, 2, 1
    /Expiration Date.*\(dd\/mm\/yyyy)/ { split($3, a, "/"); printf("%s-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "Domain Expiration Date: Day MMM DD hh:mm:ss GMT YYYY" (e.g., "Domain Expiration Date: Wed Dec 31 23:59:59 GMT 2025")
    # Formats as YYYY-MM-DD using fields 9 (year), 5 (month via mon2moy), 6 (day)
    /Domain Expiration Date:.*[A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT [0-9]{4}/ { printf("%s-%02d-%02d", $9, mon2moy($5), $6); exit }

    # Matches "Expiration Date: DD-MMM-YYYY hh:mm:ss UTC" (e.g., "Expiration Date: 31-Dec-2025 23:59:59 UTC")
    # Removes prefix, splits first field ($1) by "-", converts month (MMM) to number, formats as YYYY-MM-DD
    /Expiration Date:.*[0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC/ { sub(/^.*Expiration Date: */, "", $0); split($1, a, "-"); printf("%s-%02d-%02d", a[3], mon2moy(a[2]), a[1]); exit }

    # Matches "Expiration Date: DD-MMM-YYYY hh:mm:ss" (e.g., "Expiration Date: 31-Dec-2025 23:59:59")
    # Removes prefix, splits first field ($1) by "-", converts month (MMM) to number, formats as YYYY-MM-DD
    /Expiration Date:.*[0-3][0-9]-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}/ { sub(/^.*Expiration Date: */, "", $0); split($1, a, "-"); printf("%s-%02d-%02d", a[3], mon2moy(a[2]), a[1]); exit }

    # Matches "Expiry Date: DD MMM YYYY hh:mm:ss UTC" (e.g., "Expiry Date: 31 Dec 2025 23:59:59 UTC")
    # Formats as YYYY-MM-DD using fields 5 (year), 4 (month via mon2moy), 3 (day)
    /Expiry Date:.*[0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC/ { printf("%s-%02d-%02d", $5, mon2moy($4), $3); exit }

    # Matches "expires on.*YYYY-MM-DD hh:mm:ss \(UTC\+[0-9]+\)" (e.g., "expires on 2025-12-31 23:59:59 (UTC+1)")
    # Splits line by space, outputs fourth field (a[3]) as YYYY-MM-DD
    /expires on.*[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \(UTC\+[0-9]+\)/ { split($0, a, " "); print a[3]; exit }

    # Matches "date: YYYY/MM/DD.*" (e.g., "date: 2025/12/31")
    # Splits second field ($2) by "/", formats as YYYY-MM-DD using fields 1, 2, 3
    /date:.*[0-9]{4}\/[0-9]{2}\/[0-9]{2}/ { split($2, a, "/"); printf("%s-%02d-%02d", a[1], a[2], a[3]); exit }

    # Matches "Expiry Date: DD/MM/YYYY" (e.g., "Expiry Date: 31/12/2025")
    # Splits last field ($NF) by "/", formats as YYYY-MM-DD using fields 3, 2, 1
    /Expiry Date:.*[0-9]{2}\/[0-9]{2}\/[0-9]{4}/ { split($NF, a, "/"); printf("%s-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "Valid-date: YYYY-MM-DD" or "Expires: YYYY-MM-DD" or "Expiry: YYYY-MM-DD" (e.g., "Valid-date: 2025-12-31")
    # Outputs last field ($NF) directly as YYYY-MM-DD
    /(Valid-date|Expir(es|y)):.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { print $NF; exit }

    # Matches "[State] YYYY/MM/DD/YYYY" (e.g., "[State] 2025/12/31")
    # Removes parentheses from last field ($NF), splits by "/", formats as YYYY-MM-DD using fields 1, 2, 3
    /\[State\].*[0-9]{4}\/[0-9]{2}\/[0-9]{2}/ { gsub(/[()]/, "", $NF); split($NF, a, "/"); printf("%s-%s-%s", a[1], a[2], a[3]); exit }

    # Matches "expires at: DD/MM/YYYY" (e.g., "expires at: 31/12/2025")
    # Splits third field ($3) by "/", formats as YYYY-MM-DD using fields 3, 2, 1
    /expires at:.*[0-9]{2}\/[0-9]{2}\/[0-9]{4}/ { split($3, a, "/"); printf("%s-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "Renewal Date: YYYY-MM-DD" (e.g., "Renewal Date: 2025-12-31")
    # Outputs third field ($3) directly as YYYY-MM-DD
    /Renewal Date:.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { print $3; exit }

    # Matches "Expiry Date: DD-MM-YYYY" (e.g., "Expiry Date: 31-12-2025")
    # Splits third field ($3) by "-", formats as YYYY-MM-DD using fields 3, 2, 1
    /Expiry Date:.*[0-9]{2}-[0-9]{2}-[0-9]{4}/ { split($3, a, "-"); printf("%s-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "validity: DD-MM-YYYY" (e.g., "validity: 31-12-2025") or "validity: N/A"
    # If second field ($2) is "N/A", outputs "2100-01-01"; otherwise, splits $2 by "-", formats as YYYY-MM-DD
    /validity:.*[0-9]{2}-[0-9]{2}-[0-9]{4}/ { if ($2 == "N/A") { printf "2100-01-01\n"; exit } else { split($2, a, "-"); printf("%s-%02d-%02d", a[3], a[2], a[1]); exit } }

    # Matches "Expired on: YYYY-MM-DD-DD" (e.g., "Expired on: 2025-12-31")
    # Splits third field ($3) by "-", formats as YYYY-MM-DD using fields 1, 2, 3
    /Expired on:.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { split($3, a, "-"); printf("%s-%02d-%02d", a[1], a[2], a[3]); exit }

    # Matches "Expires.*YYYY-MM-DD" (e.g., "Expires 2025-12-31")
    # Splits second field ($2) by "-", formats as YYYY-MM-DD using fields 1, 2, 3
    /Expires.*[0-9]{4}-[0-9]{2}-[0-9]{2}/ { split($2, a, "-"); printf("%s-%02d-%02d", a[1], a[2], a[3]); exit }

    # Matches "expires: DD.MM.YYYY hh:mm:ss" or "expires.: DD.MM.YYYY hh:mm:ss" (e.g., "expires: 31.12.2025 23:59:59")
    # Removes prefix, splits first field ($1) by ".", formats as YYYY-MM-DD using fields 3, 2, 1
    /^expires\.*:.*[0-9][0-9]?\.[0-9][0-9]?\.[0-9]{4}\s[0-9]{2}:[0-9]{2}:[0-9]{2}/ { sub(/^expires\.*: */, "", $0); split($1, a, "."); printf("%04d-%02d-%02d", a[3], a[2], a[1]); exit }

    # Matches "expires: YYYY-MM-DD hh:mm:ss" (e.g., "expires: 2025-12-31 23:59:59")
    # Extracts YYYY-MM-DD via regex match, outputs directly
    /expires:.*[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2}/ { match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/); print substr($0, RSTART, RLENGTH); exit }

    # Matches "expires: YYYY-MM-DD hh:mm" (e.g., "expires: 2025-12-31 23:59")
    # Splits line by space, splits first field (a[1]) by "-", formats as YYYY-MM-DD
    /expires:.*[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}/ { split($0, a, " "); split(a[1], b, "-"); printf("%s-%s-%s", b[1], b[2], b[3]); exit }

    # Matches "renewal:" to set flag for next line processing
    # Sets renewal variable to 1, skips to next line
    /renewal:/ { renewal=1; next }

    # Matches line following "renewal:" (e.g., "DD MMM YYYY" after "renewal:")
    # Removes non-digits from second field ($2), converts month ($3) to number, formats as YYYY-MM-DD
    /renewal/ { sub(/[^0-9]+/, "", $2); printf("%s-%02d-%02d", $4, mon2moy($3), $2); exit }

    # Matches "Expiry date: DD-MMM-YYYY" (e.g., "Expiry date: 31-Dec-2025")
    # Splits last field ($NF) by "-", converts month (MMM) to number, formats as YYYY-MM-DD
    /Expiry date:.*[0-9]{2}-[A-Za-z]{3}-[0-9]{4}/ { split($NF, a, "-"); printf("%s-%02d-%02d", a[3], mon2moy(a[2]), a[1]); exit }

    # Matches "Expiration Date: YYYY-MM-DD\s" (e.g., "Expiration Date: 2025-12-31 ")
    # Uses get_iso_date to split by ":" and extract YYYY-MM-DD
    $0 ~ "Expiration Date:\s" DATE_ISO_LIKE { print get_iso_date($0, ":", 2); exit }

    # Matches "Expiration Time: YYYY-MM-DD hh:mm:ss" (e.g., "Expiration Time: 2025-12-31 23:59:59")
    # Splits third field ($3) by "-", formats as YYYY-MM-DD using fields 1, 2, 3
    $0 ~ "Expiration Time:.*" DATE_YYYY_MM_DD_DASH_HH_MM_SS { split($3, a, "-"); printf("%s-%s-%s", a[1], a[2], a[3]); exit }

    # Matches "billed until: YYYY-MM-DDThh:mm:ss" (e.g., "billed until: 2025-12-31T23:59:59")
    # Uses get_iso_date to split by ":" and extract YYYY-MM-DD before "T"
    $0 ~ "billed[ ]*until:\s" DATE_ISO_FULL { print get_iso_date($0, ":", 2); exit }
    ' "$outfile" 2>"$error_file")
    awk_rc=$?
    set -e
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: awk completed with exit code $awk_rc, expiration='$expiration'" >&2
    fi
    if [ $awk_rc -ne 0 ]; then
        if [ "$debug" = "true" ]; then
            echo "ERROR [$(date +'%H:%M:%S')]: awk failed, error: $(cat "$error_file")" >&2
        fi
        die "$STATE_UNKNOWN" "State: UNKNOWN ; Failed to parse WHOIS data for $domain"
    fi
    if [ -z "$expiration" ]; then
        if [ "$debug" = "true" ]; then
            echo "INFO [$(date +'%H:%M:%S')]: No expiration date found in WHOIS data for $domain" >&2
        fi
        die "$STATE_UNKNOWN" "State: UNKNOWN ; No expiration date found for $domain"
    fi
    # Validate expiration date format/trim whitespace
    expiration=$(echo "$expiration" | tr -d '[:space:]')
    if ! echo "$expiration" | grep -q -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
        if [ "$debug" = "true" ]; then
            echo "ERROR [$(date +'%H:%M:%S')]: Invalid expiration date format: '$expiration' for $domain" >&2
        fi
        die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid expiration date format '$expiration' for $domain"
    fi
    echo "$expiration"
}

# Parse command line arguments
if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Parsing Arguments" >&2
fi
parse_arguments "$@"
if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Parsed arguments" >&2
fi

# Check dependencies
if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Checking dependencies" >&2
fi
command -v curl >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; curl dependency not found in PATH"
command -v mktemp >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; mktemp dependency not found in PATH"
command -v date >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; date dependency not found in PATH"
command -v whois >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; whois dependency not found in PATH"
command -v grep >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; grep dependency not found in PATH"
command -v jq >/dev/null || die "$STATE_UNKNOWN" "State: UNKNOWN ; jq dependency not found in PATH"
if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Dependencies checked" >&2
fi

if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Reached main execution block after parse_arguments" >&2
fi
if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Outfile set to: $outfile" >&2
fi

set +e
exec 3>&2
expiration=$(get_rdap_expiration "$domain" 2>"$error_file")
rdap_rc=$?
exec 3>&-
set -e

if [ $rdap_rc -ne 0 ]; then
    echo "ERROR [$(date +'%H:%M:%S')]: get_rdap_expiration failed for $domain, exit code: $rdap_rc, error: $(cat "$error_file")" >&2
    expiration=""
fi

if [ -z "$expiration" ]; then
    if [ "$debug" = "true" ]; then
        echo "INFO [$(date +'%H:%M:%S')]: Falling back to WHOIS for $domain" >&2
    fi
    run_whois
    expiration=$(get_expiration "$outfile")
fi

if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Expiration date: $expiration" >&2
fi

# Validate expiration date format
if ! echo "$expiration" | grep -q -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    die "$STATE_UNKNOWN" "State: UNKNOWN ; Invalid expiration date format: $expiration"
fi

# Calculate seconds since epoch for expiration date at midnight UTC
expseconds=$(date -u +%s --date="$expiration 00:00:00 UTC" 2>/dev/null) || die "$STATE_UNKNOWN" "State: UNKNOWN ; Failed to parse expiration date: $expiration"
nowseconds=$(date -u +%s 2>/dev/null) || die "$STATE_UNKNOWN" "State: UNKNOWN ; Failed to get current time"
expdays=$(( (expseconds - nowseconds) / 86400 ))
expdate="$expiration"

if [ "$debug" = "true" ]; then
    echo "INFO [$(date +'%H:%M:%S')]: Time calculation: expseconds=$expseconds, nowseconds=$nowseconds, expdays=$expdays, expdate=$expdate" >&2
    echo "INFO [$(date +'%H:%M:%S')]: Days left: $expdays ; Exp date: $expdate" >&2
fi

if [ $expdays -ge 0 ]; then
    [ $expdays -le "$critical" ] && die "$STATE_CRITICAL" "State: CRITICAL ; Days left: $expdays ; Expire date: $expdate"
    [ $expdays -le "$warning" ] && die "$STATE_WARNING" "State: WARNING ; Days left: $expdays ; Expire date: $expdate"
    die "$STATE_OK" "State: OK ; Days left: $expdays ; Expire date: $expdate"
fi
die "$STATE_CRITICAL" "State: CRITICAL ; Days since expired: ${expdays#-} ; Expire date: $expdate"

exit 0