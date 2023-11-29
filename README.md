# zabbix-domain-expiry

## Description

Zabbix template to check domain registration expiry

Tested on:
* Zabbix 6.4

## Requirements:
* Zabbix v6.4 or later
* whois (GNU utils)

## Setup:

1. Copy shell script check_domain.sh to your Zabbix server external scripts dir (default: /usr/lib/zabbix/externalscripts/)
2. Make it executable (e.g. chmod +x /usr/lib/zabbix/externalscripts/check_domain.sh)
2. Import yaml template to your zabbix server
3. Create a host with a domain name as the Host name and attach the template to the host. Make sure required macros are filled out

## Required macros:

|Macro|Default Value|Description|
|-----|-------------|-----------|
|{$EXP_CRIT}|7|Threshold value of days remaining before triggering a HIGH alert|
|{$EXP_WARN}|30|Threshold value of days remaining before triggering a WARNING alert|
|{$WHOIS_SERVER}|""|Used to specify which whois service to use. Default value "" uses the whois util config default|

## Items:

|Name|Description|Type|Key and additional info|
|----|-----------|----|----|
|Domain Check Expiry|Run external script to check domain registration status|External check|check_domain.sh["-d",{HOST.NAME},"-s",{$WHOIS_SERVER},"-w",{$EXP_WARN},"-c",{$EXP_CRIT}], Update interval: 1d|
|Domain Check Expiry: Status|Get "State:" from script output|Dependant item|domain_check_expiry.status|
|Domain Check Expiry: Expire Date|Get "Expire date:" from script output|Dependant item|domain_check_expiry.expire_date|
|Domain Check Expiry: Days Since Expired|Get "Days since expired:" from script output|Dependant item|domain_check_expiry.days_since_expired|
|Domain Check Expiry: Days Left|Get "Days left:" from script output|Dependant item|domain_check_expiry.days_left|

## Triggers:
<b>Note: There is operational data included in the triggers to display live data from checks. You can include this in your "Problems" dashboard widget > Show operational data > With problem name</b>

|Name|Description|Expression|Severity|
|----|-----------|----------|--------|
|Domain Expiry: {HOST.NAME} - {ITEM.LASTVALUE1}|Raise alert in case of script output error|find(/Domain Expiry/domain_check_expiry.status,#1,"like","UNKNOWN")=1|Not classified|
|Domain Expiry: {HOST.NAME} will expire soon|Raise alert when number days remaining is below threshold|last(/Domain Expiry/domain_check_expiry.days_left)<={$EXP_WARN} and last(/Domain Expiry/domain_check_expiry.expire_date)<>0|Warning|
|Domain Expiry: {HOST.NAME} will expire soon|Raise alert when number days remaining is below threshold|last(/Domain Expiry/domain_check_expiry.days_left)<={$EXP_CRIT} and last(/Domain Expiry/domain_check_expiry.expire_date)<>0|High|
|Domain Expiry: {HOST.NAME} has expired|Raise alert domain registarion has expired|find(/Domain Expiry/domain_check_expiry.status,#1,"like","EXPIRED")=1 and last(/Domain Expiry/domain_check_expiry.days_since_expired)>=0 and last(/Domain Expiry/domain_check_expiry.expire_date)<>0|Disaster|
