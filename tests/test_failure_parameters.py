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
"""Exercise parameter preservation through real registered SDK actions."""

import pytest
from soar_sdk.params import MakeRequestParams

from src.actions.lookup_ip import LookupIpParams
from src.actions.report_ip import ReportIpParams
from src.asset import Asset

TEST_API_KEY = "offline-test-value"  # pragma: allowlist secret - local test value


@pytest.fixture(params=["lookup_ip", "report_ip", "make_request"])
def action_case(request, connector_app):
    identifier = request.param
    if identifier == "lookup_ip":
        valid = LookupIpParams(ip="192.0.2.1", days=10)
        invalid = LookupIpParams(ip="invalid-ip", days=30)
    elif identifier == "report_ip":
        valid = ReportIpParams(ip="192.0.2.1", category_ids="1,3", comment="test")
        invalid = ReportIpParams(ip="invalid-ip", category_ids="1,3", comment="test")
    else:
        valid = MakeRequestParams(http_method="GET", endpoint="check")
        invalid = MakeRequestParams(
            http_method="GET", endpoint="https://example.invalid/check"
        )
    return identifier, connector_app.get_actions()[identifier], valid, invalid


def test_registered_validation_failure_keeps_inputs(action_case, connector_app):
    identifier, action, _, params = action_case
    assert action(params, asset=Asset(api_key=TEST_API_KEY)) is False
    result = connector_app.actions_manager.get_results()[-1]
    assert result.get_status() is False
    assert result.get_param() == params.model_dump(by_alias=True)
    assert "Action failure in" in result.get_message()
    expected = "relative path" if identifier == "make_request" else "Invalid IP address"
    assert expected in result.get_message()
    assert result.get_data() == []


@pytest.mark.parametrize("failure", ["untrusted_certificate", "invalid_ca_bundle"])
def test_registered_connection_failure_keeps_inputs(
    action_case, connector_app, configured_service, network_env, tmp_path, failure
):
    _, action, params, _ = action_case
    if failure == "untrusted_certificate":
        network_env.pop("REQUESTS_CA_BUNDLE")
    else:
        network_env["REQUESTS_CA_BUNDLE"] = str(tmp_path / "missing-ca.crt")
    assert action(params, asset=Asset(api_key=TEST_API_KEY)) is False
    result = connector_app.actions_manager.get_results()[-1]
    assert result.get_status() is False
    assert result.get_param() == params.model_dump(by_alias=True)
    expected = (
        "Error Connecting" if failure == "untrusted_certificate" else "CA trust bundle"
    )
    assert expected in result.get_message()


def test_registered_http_error_keeps_inputs_and_make_request_contract(
    action_case, connector_app, configured_service
):
    identifier, action, params, _ = action_case
    configured_service["response"].update(
        status=422,
        body=b'{"errors":[{"detail":"Invalid input"}]}',
    )
    status = action(params, asset=Asset(api_key=TEST_API_KEY))
    result = connector_app.actions_manager.get_results()[-1]
    assert result.get_param() == params.model_dump(by_alias=True)
    if identifier == "make_request":
        assert status is True
        assert result.get_data()[0]["status_code"] == 422
        assert (
            result.get_data()[0]["response_body"]
            == configured_service["response"]["body"].decode()
        )
    else:
        assert status is False
        assert "Status Code: 422" in result.get_message()
        assert "Invalid input" in result.get_message()


def test_registered_failure_followed_by_success_keeps_each_input(
    action_case, connector_app, configured_service
):
    _, action, valid, invalid = action_case
    configured_service["response"]["body"] = (
        b'{"data":{"ipAddress":"192.0.2.1","reports":[]}}'
    )
    asset = Asset(api_key=TEST_API_KEY)
    assert action(invalid, asset=asset) is False
    assert action(valid, asset=asset) is True
    results = connector_app.actions_manager.get_results()
    assert len(results) == 2
    assert [result.get_status() for result in results] == [False, True]
    assert [result.get_param() for result in results] == [
        invalid.model_dump(by_alias=True),
        valid.model_dump(by_alias=True),
    ]
    assert results[0].get_data() == []
    assert len(results[1].get_data()) == 1
