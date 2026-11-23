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
"""Exercise timeout overrides and failures with real stalled TLS responses."""

import pytest
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from src.actions.connectivity import test_connectivity as run_connectivity
from src.actions.lookup_ip import LookupIpParams
from src.actions.make_request import make_request
from src.actions.report_ip import ReportIpParams
from src.asset import Asset

TEST_API_KEY = "offline-test-value"  # pragma: allowlist secret - local test value


@pytest.mark.parametrize("identifier", ["lookup_ip", "report_ip", "make_request"])
@pytest.mark.parametrize("timeout", [1, 0, -1])
def test_registered_timeout_failures_keep_parameters(
    identifier, timeout, connector_app, configured_service
):
    configured_service["response"]["delay"] = 2
    if identifier == "lookup_ip":
        params = LookupIpParams(ip="192.0.2.1", request_timeout=timeout)
    elif identifier == "report_ip":
        params = ReportIpParams(
            ip="192.0.2.1", category_ids="1", request_timeout=timeout
        )
    else:
        params = MakeRequestParams(http_method="GET", endpoint="check", timeout=timeout)
    action = connector_app.get_actions()[identifier]
    assert action(params, asset=Asset(api_key=TEST_API_KEY)) is False
    result = connector_app.actions_manager.get_results()[-1]
    assert result.get_param() == params.model_dump(by_alias=True)
    if timeout > 0:
        assert (
            "Request timed out after 1 seconds of network inactivity"
            in result.get_message()
        )
        assert len(configured_service["events"]) == 1
    else:
        assert "must be greater than zero" in result.get_message()
        assert configured_service["events"] == []


@pytest.mark.parametrize("timeout", [1, 0, -1])
def test_connectivity_timeout(timeout, configured_service, soar):
    configured_service["response"]["delay"] = 2
    asset = Asset(api_key=TEST_API_KEY, request_timeout=timeout)
    expected = (
        "Request timed out after 1 seconds"
        if timeout > 0
        else "must be greater than zero"
    )
    with pytest.raises(ActionFailure, match=expected):
        run_connectivity(soar, asset)
    assert len(configured_service["events"]) == (1 if timeout > 0 else 0)


def test_make_request_omitted_timeout_is_finite(configured_service):
    # Exercise the actual 30-second fallback; no patched clock or HTTP client.
    configured_service["response"]["delay"] = 31
    output = make_request(
        MakeRequestParams(http_method="GET", endpoint="check"),
        Asset(api_key=TEST_API_KEY),
    )
    assert output.get_status() is False
    assert "Request timed out after 30 seconds" in output.get_message()
    assert len(configured_service["events"]) == 1


def test_timeout_defaults_are_optional_in_sdk_models(connector_app):
    asset = Asset(api_key=TEST_API_KEY)
    assert asset.request_timeout == 30
    assert LookupIpParams(ip="192.0.2.1").request_timeout == 30
    assert ReportIpParams(ip="192.0.2.1", category_ids="1").request_timeout == 30
    for identifier in ("lookup_ip", "report_ip"):
        parameters = connector_app.get_actions()[identifier].meta.model_dump()[
            "parameters"
        ]
        timeout = parameters["request_timeout"]
        assert timeout["default"] == 30
        assert timeout["required"] is False
