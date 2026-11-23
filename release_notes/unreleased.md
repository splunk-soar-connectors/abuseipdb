**Unreleased**

* Add the SDK-native Make Request action.
* **Breaking change:** Require Splunk SOAR 7.0.0 or later.
* Restore lookup details and per-report information through native table columns; display report categories together while preserving their array output.
* Honor configured CA trust and Automation Broker proxy settings.
* **Breaking change:** Require JSON for successful API responses, including responses with an empty body. Report HTTP failures without HTML parsing.
* Preserve action input parameters in expected failure results.
* **Breaking change:** Apply a 30-second network inactivity timeout instead of waiting indefinitely. Override it with lookup/report `request_timeout`, the Test Connectivity asset setting, or Make Request's native `timeout` parameter.
* Display persistent Test Connectivity warnings for HTTP 429 responses, including duplicate reports and exhausted daily quota.
