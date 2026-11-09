# AbuseIPDB

Publisher: Splunk <br>
Connector Version: 2.1.3 <br>
Product Vendor: AbuseIPDB <br>
Product Name: AbuseIPDB <br>
Minimum Product Version: 7.0.0

This app integrates with AbuseIPDB to perform investigative actions

### Configuration variables

This table lists the configuration variables required to operate AbuseIPDB. These variables are specified when configuring a AbuseIPDB asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | API Key |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[make request](#action-make-request) - make request <br>
[lookup ip](#action-lookup-ip) - Queries IP info <br>
[post ip](#action-post-ip) - Report an IP for abusive behavior

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

make request

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | The endpoint to send the request to. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is True. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ip'

Queries IP info

Type: **investigate** <br>
Read only: **True**

The AbuseIPDB service has a limit of 1000 lookups per day.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IPv4 or IPv6 to query | string | `ip` `ipv6` |
**days** | required | Check for IP Reports within this number of days | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.days | numeric | | |
action_result.data.\*.data.abuseConfidenceScore | numeric | | 0 |
action_result.data.\*.data.countryCode | string | | US |
action_result.data.\*.data.countryName | string | | United States |
action_result.data.\*.data.domain | string | `domain` `url` | |
action_result.data.\*.data.ipAddress | string | `ip` `ipv6` | 8.8.8.8 2001:4860:4860::8888 |
action_result.data.\*.data.ipVersion | numeric | | 4 |
action_result.data.\*.data.isPublic | boolean | | True False |
action_result.data.\*.data.isWhitelisted | boolean | | True False |
action_result.data.\*.data.isp | string | | Private IP Address LAN |
action_result.data.\*.data.lastReportedAt | string | | 2019-05-21T10:18:49+01:00 |
action_result.data.\*.data.reports.\*.categories.\* | numeric | | 3 |
action_result.data.\*.data.reports.\*.comment | string | | Secure Shell (SSH) abuse. This category in combination with more specific categories. |
action_result.data.\*.data.reports.\*.reportedAt | string | | 2019-05-21T10:18:49+01:00 |
action_result.data.\*.data.reports.\*.reporterCountryCode | string | | US |
action_result.data.\*.data.reports.\*.reporterCountryName | string | | United States |
action_result.data.\*.data.reports.\*.reporterId | numeric | | 29933 |
action_result.data.\*.data.totalReports | numeric | | 5 |
action_result.data.\*.data.usageType | string | | Reserved |
action_result.data.\*.data.numDistinctUsers | numeric | | 0 |
action_result.summary.reports_found | numeric | | 0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'post ip'

Report an IP for abusive behavior

Type: **generic** <br>
Read only: **False**

Reports an IP given the categories. The categories can be found in <a href='https://www.abuseipdb.com/categories'>Report Categories</a>. There is a limit on reporting the same IP for an interval of <b>15 minutes</b>. There is a comment limit of <b>1024 characters</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IPv4 or IPv6 to report on | string | `ip` `ipv6` |
**category_ids** | required | Comma delineated list of category IDs | string | |
**comment** | optional | Description of malicious activity | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.category_ids | string | | |
action_result.parameter.comment | string | | |
action_result.data.\*.data.ipAddress | string | `ip` `ipv6` | 8.8.8.8 2001:4860:4860::8888 |
action_result.data.\*.data.abuseConfidenceScore | numeric | | 0 |
action_result.summary.categories_filed | numeric | | 4 |
action_result.summary.comment_length | numeric | | 8 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
