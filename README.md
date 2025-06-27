# zabbix-domain-expiry

Monitor domain expiration dates using RDAP or WHOIS protocols.

</br>

## Features
- **(NEW) RDAP and WHOIS Support**: Queries domain expiration via RDAP (preferred) with fallback to WHOIS.
- **(NEW) JSON Output**: Script outputs JSON for easy parsing by Zabbix.
- **(NEW) Debug Mode**: Detailed debug output for troubleshooting.

## Requirements
- **Zabbix Server/Agent**: Version 6.4 or higher
- **OS**: GNU/Linux systems
- **Shell Script Dependencies**:
  - `curl`: For RDAP queries.
  - `mktemp`: For temporary files.
  - `date`: For date calculations.
  - `whois`: For WHOIS queries.
  - `grep`: For parsing output.
  - `awk`: For parsing WHOIS and RDAP data.
  - `jq`: For parsing RDAP JSON responses.

## Tested on
- **OS**: RHEL/Rocky (bash) and Debian/Ubuntu (dash)
- **Zabbix Server**: 6.4
- **Note**: Shell script is *mostly* POSIX compliant so should be widely compatible

## Installation (Zabbix server)

### Install Dependencies
Ensure the required dependencies are installed on your system.

**For RHEL/Rocky**:
```bash
sudo dnf install -y epel-release
sudo dnf install -y curl coreutils whois grep gawk jq
```

**For Debian/Ubuntu**:
```bash
sudo apt update
sudo apt install -y curl coreutils whois grep gawk jq
```

### Setup Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/a-stoyanov/zabbix-domain-expiry.git
   cd zabbix-domain-expiry
   ```
2. Copy shell script `check_domain.sh` to your Zabbix server external scripts dir (default: `/usr/lib/zabbix/externalscripts/`)
3. Make it executable (e.g. `chmod +x /usr/lib/zabbix/externalscripts/check_domain.sh`)
4. Import yaml template `zbx_domain_expiry.yaml` to your zabbix server
5. Create a host with a domain name (e.g: `example.com`) as the Host name and attach the template to the host

## Upgrading

If you are upgrading from the old version just import/overwrite the existing template and copy/overwite the old shell script with new version

## Configuration

### Template Macros
The template uses the following macros, configurable at the host or template level:

| Macro            | Default Value | Description                                                                 |
|------------------|---------------|-----------------------------------------------------------------------------|
| `{$EXP_CRIT}`    | 7             | Days remaining before triggering a HIGH (critical) alert.                   |
| `{$EXP_WARN}`    | 30            | Days remaining before triggering a WARNING alert.                           |
| `{$RDAP_SERVER}` | (empty)       | Specify which RDAP server to use. Default empty value will use IANA lookup.  |
| `{$WHOIS_SERVER}`| (empty)       | Specify which WHOIS server to use. Default empty value will use rfc-3912 lookup. |

### Template Items
The template includes the following items to monitor domain expiration:

| Name                | Key                                    | Type       | Value Type | Description                                                                 |
|---------------------|----------------------------------------|------------|------------|-----------------------------------------------------------------------------|
| Days Left           | `check_domain.days_left`               | Dependent  | Float      | Number of days until the domain expires.                                    |
| Days Since Expired  | `check_domain.days_since_expired`      | Dependent  | Float      | Number of days since the domain expired (0 if not expired).                 |
| Expire Date         | `check_domain.expire_date`             | Dependent  | Text       | Domain expiration date in YYYY-MM-DD format.                                |
| Message             | `check_domain.message`                 | Dependent  | Text       | Status message returned by the script.                                      |
| State               | `check_domain.state`                   | Dependent  | Text       | Domain status: OK, WARNING, CRITICAL, or UNKNOWN.                           |
| Check Domain        | `check_domain.sh[...]`                 | External   | Text       | Executes the external script to check domain status.                        |

### Template Triggers
The template defines the following triggers for alerting:

| Name                                    | Expression                                                                 | Priority  | Description                                                                 |
|-----------------------------------------|---------------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------|
| Domain Expiry: {HOST.HOST} - {ITEM.LASTVALUE2} | `last(/Domain Expiry/check_domain.state)="UNKNOWN" and last(/Domain Expiry/check_domain.message)<>0` | Not Classified   | Alerts if the script cannot determine the domain's expiration status.        |
| Domain Expiry: {HOST.HOST} has expired  | `last(/Domain Expiry/check_domain.state)="CRITICAL" and last(/Domain Expiry/check_domain.days_since_expired)>0 and last(/Domain Expiry/check_domain.expire_date)<>0` | Disaster  | Alerts if the domain has expired.                                           |
| Domain Expiry: {HOST.HOST} will expire soon (Critical) | `last(/Domain Expiry/check_domain.state)="CRITICAL" and last(/Domain Expiry/check_domain.days_left)<={$EXP_CRIT} and last(/Domain Expiry/check_domain.expire_date)<>0` | High      | Alerts if days remaining are below the critical threshold (`{$EXP_CRIT}`).  |
| Domain Expiry: {HOST.HOST} will expire soon (Warning)  | `last(/Domain Expiry/check_domain.state)="WARNING" and last(/Domain Expiry/check_domain.days_left)<={$EXP_WARN} and last(/Domain Expiry/check_domain.expire_date)<>0` | Warning   | Alerts if days remaining are below the warning threshold (`{$EXP_WARN}`).   |

### Script Usage
The `check_domain.sh` script can be run manually for testing:

```bash
./check_domain.sh -d example.com
./check_domain.sh -d example.com -r 'https://rdap.example.com' -s 'whois.example.com' -w 30 -c 7
```

**Options**:
- `-d, --domain`: Domain name to check (required).
- `-w, --warning`: Warning threshold in days (default: 30).
- `-c, --critical`: Critical threshold in days (default: 7).
- `-r, --rdap-server`: RDAP server URL (use `""` for IANA lookup).
- `-s, --whois-server`: WHOIS server hostname (use `""` for default lookup).
- `-P, --path`: Path to `whois` executable.
- `-z, --debug`: Enable debug output to stderr.
- `-h, --help`: Display help.
- `-V, --version`: Display version in JSON format.

**Example Output**:
```json
{"state":"OK","days_left":365,"days_since_expired":0,"expire_date":"2026-06-24","message":"State: OK ; Days left: 365 ; Expire date: 2026-06-24"}
```

## Debugging
- Enable debug mode in the script with `-z`:
  ```bash
  ./check_domain.sh -d example.com -z
  ```
- Check Zabbix logs for issues with script execution.
- Verify RDAP/WHOIS server availability and response format outside of script

## Notes
- The script prioritizes RDAP for faster, structured queries but falls back to WHOIS if RDAP fails.
- WHOIS awk parsing supports various date formats but may fail if whois query returns non-standard responses (no awk pattern match).
- Rate limits on WHOIS servers may trigger UNKNOWN states; increase or use custom check interval to mitigate (the default 1d is very reasonable).
- For some specific TLDs (e.g: `.uk`, `.br`) RDAP URL paths may have to be adjusted due to non-standard URL format. See `adjust_rdap_url()` function, which already handles /uk/ path adjustment.

## License
This project is licensed under the Apache License 2.0
