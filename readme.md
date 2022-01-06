[comment]: # "Auto-generated SOAR connector documentation"
# AbuseIPDB

Publisher: Splunk  
Connector Version: 2\.0\.6  
Product Vendor: AbuseIPDB  
Product Name: AbuseIPDB  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app integrates with AbuseIPDB to perform investigative actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a AbuseIPDB asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup ip](#action-lookup-ip) - Queries IP info  
[post ip](#action-post-ip) - Report an IP for abusive behavior  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Queries IP info

Type: **investigate**  
Read only: **True**

The AbuseIPDB service has a limit of 1000 lookups per day\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IPv4 to query | string |  `ip` 
**days** |  required  | Check for IP Reports within this number of days | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.days | numeric | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.data\.abuseConfidenceScore | numeric | 
action\_result\.data\.\*\.data\.countryCode | string | 
action\_result\.data\.\*\.data\.countryName | string | 
action\_result\.data\.\*\.data\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.data\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.data\.ipVersion | numeric | 
action\_result\.data\.\*\.data\.isPublic | boolean | 
action\_result\.data\.\*\.data\.isWhitelisted | boolean | 
action\_result\.data\.\*\.data\.isp | string | 
action\_result\.data\.\*\.data\.lastReportedAt | string | 
action\_result\.data\.\*\.data\.reports\.\*\.categories | numeric | 
action\_result\.data\.\*\.data\.reports\.\*\.comment | string | 
action\_result\.data\.\*\.data\.reports\.\*\.reportedAt | string | 
action\_result\.data\.\*\.data\.reports\.\*\.reporterCountryCode | string | 
action\_result\.data\.\*\.data\.reports\.\*\.reporterCountryName | string | 
action\_result\.data\.\*\.data\.reports\.\*\.reporterId | numeric | 
action\_result\.data\.\*\.data\.totalReports | numeric | 
action\_result\.data\.\*\.data\.usageType | string | 
action\_result\.summary\.reports\_found | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.data\.numDistinctUsers | numeric |   

## action: 'post ip'
Report an IP for abusive behavior

Type: **generic**  
Read only: **False**

Reports an IP given the categories\. The categories can be found in <a href='https\://www\.abuseipdb\.com/categories'>Report Categories</a>\. There is a limit on reporting the same IP for an interval of <b>15 minutes</b>\. There is a comment limit of <b>1024 characters</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IPv4 to report on | string |  `ip` 
**category\_ids** |  required  | Comma delineated list of category IDs | string | 
**comment** |  optional  | Description of malicious activity | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.category\_ids | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data | string | 
action\_result\.summary\.categories\_filed | numeric | 
action\_result\.summary\.comment\_length | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.data\.ipAddress | string | 
action\_result\.data\.\*\.data\.abuseConfidenceScore | numeric | 