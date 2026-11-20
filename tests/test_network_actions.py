# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Verify custom CA settings reach all action clients over real local TLS."""

import pytest
from soar_sdk.params import MakeRequestParams

from src.actions.connectivity import test_connectivity as run_connectivity
from src.actions.lookup_ip import LookupIpParams, lookup_ip
from src.actions.make_request import make_request
from src.actions.report_ip import ReportIpParams, report_ip
from src.asset import Asset

TEST_API_KEY = "offline-test-value"  # pragma: allowlist secret - local test value


@pytest.mark.parametrize(
    "identifier", ["lookup", "report", "connectivity", "make_request"]
)
@pytest.mark.parametrize("ca_variable", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_action_custom_ca_reaches_httpx(
    identifier, ca_variable, configured_service, network_env, soar
):
    network_env.pop("REQUESTS_CA_BUNDLE", None)
    network_env[ca_variable] = configured_service["ca"]
    configured_service["response"]["body"] = (
        b'{"data":{"ipAddress":"8.8.8.8","reports":[],"abuseConfidenceScore":0}}'
    )
    asset = Asset(api_key=TEST_API_KEY)
    if identifier == "lookup":
        output = lookup_ip(LookupIpParams(ip="8.8.8.8"), soar, asset)
        assert output.data.ipAddress == "8.8.8.8"
    elif identifier == "report":
        output = report_ip(ReportIpParams(ip="8.8.8.8", category_ids="1"), soar, asset)
        assert output.data.ipAddress == "8.8.8.8"
    elif identifier == "connectivity":
        assert run_connectivity(soar, asset) is None
    else:
        output = make_request(
            MakeRequestParams(http_method="GET", endpoint="check"), asset
        )
        assert output.status_code == 200
    assert len(configured_service["events"]) == 1
    headers = {
        key.lower(): value
        for key, value in configured_service["events"][0]["headers"].items()
    }
    assert headers["key"] == TEST_API_KEY
