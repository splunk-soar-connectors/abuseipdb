[comment]: # "Auto-generated SOAR connector documentation"
# AbuseIPDB

Publisher: Splunk  
Connector Version: 2.1.0  
Product Vendor: AbuseIPDB  
Product Name: AbuseIPDB  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.1  

This app integrates with AbuseIPDB to perform investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a AbuseIPDB asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** |  required  | password | API Key

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

The AbuseIPDB service has a limit of 1000 lookups per day.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IPv4 or IPv6 to query | string |  `ip`  `ipv6` 
**days** |  required  | Check for IP Reports within this number of days | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.days | numeric |  |   10 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8  2001:4860:4860::8888 
action_result.data.\*.data.abuseConfidenceScore | numeric |  |   0 
action_result.data.\*.data.countryCode | string |  |   US 
action_result.data.\*.data.countryName | string |  |   United States 
action_result.data.\*.data.domain | string |  `domain`  `url`  |  
action_result.data.\*.data.ipAddress | string |  `ip`  `ipv6`  |   8.8.8.8  2001:4860:4860::8888 
action_result.data.\*.data.ipVersion | numeric |  |   4 
action_result.data.\*.data.isPublic | boolean |  |   True  False 
action_result.data.\*.data.isWhitelisted | boolean |  |   True  False 
action_result.data.\*.data.isp | string |  |   Private IP Address LAN 
action_result.data.\*.data.lastReportedAt | string |  |   2019-05-21T10:18:49+01:00 
action_result.data.\*.data.reports.\*.categories | numeric |  |   3 
action_result.data.\*.data.reports.\*.comment | string |  |   Secure Shell (SSH) abuse. This category in combination with more specific categories. 
action_result.data.\*.data.reports.\*.reportedAt | string |  |   2019-05-21T10:18:49+01:00 
action_result.data.\*.data.reports.\*.reporterCountryCode | string |  |   US 
action_result.data.\*.data.reports.\*.reporterCountryName | string |  |   United States 
action_result.data.\*.data.reports.\*.reporterId | numeric |  |   29933 
action_result.data.\*.data.totalReports | numeric |  |   5 
action_result.data.\*.data.usageType | string |  |   Reserved 
action_result.summary.reports_found | numeric |  |   1 
action_result.message | string |  |   IP lookup complete. Reports found: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.data.numDistinctUsers | numeric |  |    

## action: 'post ip'
Report an IP for abusive behavior

Type: **generic**  
Read only: **False**

Reports an IP given the categories. The categories can be found in <a href='https://www.abuseipdb.com/categories'>Report Categories</a>. There is a limit on reporting the same IP for an interval of <b>15 minutes</b>. There is a comment limit of <b>1024 characters</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IPv4 or IPv6 to report on | string |  `ip`  `ipv6` 
**category_ids** |  required  | Comma delineated list of category IDs | string | 
**comment** |  optional  | Description of malicious activity | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.category_ids | string |  |   3, 4 
action_result.parameter.comment | string |  |   Secure Shell (SSH) abuse. This category in combination with more specific categories. 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8  2001:4860:4860::8888 
action_result.data | string |  |  
action_result.summary.categories_filed | numeric |  |   4 
action_result.summary.comment_length | numeric |  |   8 
action_result.message | string |  |   IP reported. Number of categories filed: 2, Comment length: 193 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.data.ipAddress | string |  `ip`  `ipv6`  |   8.8.8.8  2001:4860:4860::8888 
action_result.data.\*.data.abuseConfidenceScore | numeric |  |  