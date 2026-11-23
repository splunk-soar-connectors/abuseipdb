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
"""Check status-based API failures and invalid successful responses over local TLS."""

import pytest
from soar_sdk.action_results import ActionResult
from soar_sdk.exceptions import ActionFailure

from src.actions.connectivity import test_connectivity as run_connectivity
from src.actions.lookup_ip import LookupIpParams, lookup_ip
from src.actions.report_ip import ReportIpParams, report_ip
from src.asset import Asset

TEST_API_KEY = "offline-test-value"  # pragma: allowlist secret - local test value


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            b'{"errors":[{"detail":"You can only report the same IP address (`127.0.0.1`) once in 15 minutes.","status":429,"source":{"parameter":"ip"}}]}',
            "this IP was reported within the last 15 minutes",
        ),
        (
            b'{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.","status":429}]}',
            "daily report quota is exhausted",
        ),
        (
            b'{"errors":[{"detail":"Unknown throttle"}]}',
            "does not confirm authentication",
        ),
        (b"<html>Too many requests</html>", "does not confirm authentication"),
        (b"", "does not confirm authentication"),
        (b"[]", "does not confirm authentication"),
        (b'{"errors":null}', "does not confirm authentication"),
        (b'{"errors":[null,{"detail":42}]}', "does not confirm authentication"),
    ],
)
def test_connectivity_429_passes_with_native_progress(
    body, expected, configured_service, connector_app, capsys
):
    configured_service["response"].update(
        status=429, body=body, headers={"Retry-After": "60"}
    )
    # Configure a real SDK asset and invoke its native connectivity wrapper.
    connector_app._asset = Asset(api_key=TEST_API_KEY)
    action = connector_app.get_actions()["test_connectivity"]
    assert action() is True
    result = connector_app.actions_manager.get_results()[-1]
    assert result.get_status() is True
    assert result.get_message() == "Test connectivity successful"
    progress = capsys.readouterr().out
    assert "Warning: Connectivity test passed" in progress
    assert expected in progress
    assert "Retry after 60 seconds." in progress
    assert len(configured_service["events"]) == 1


@pytest.mark.parametrize("retry_after", [None, "invalid"])
def test_connectivity_unknown_429_without_numeric_retry(
    retry_after, configured_service, soar, capsys
):
    configured_service["response"].update(
        status=429,
        body=b"{}",
        headers={"Retry-After": retry_after} if retry_after is not None else {},
    )
    assert run_connectivity(soar, Asset(api_key=TEST_API_KEY)) is None
    progress = capsys.readouterr().out
    assert "HTTP 429 (Too Many Requests)" in progress
    assert "Retry after" not in progress


@pytest.mark.parametrize("identifier", ["lookup_ip", "report_ip"])
def test_regular_actions_still_fail_on_429(
    identifier, configured_service, connector_app
):
    configured_service["response"].update(status=429, body=b'{"errors":[]}')
    params = (
        LookupIpParams(ip="192.0.2.1")
        if identifier == "lookup_ip"
        else ReportIpParams(ip="192.0.2.1", category_ids="1")
    )
    action = connector_app.get_actions()[identifier]
    assert action(params, asset=Asset(api_key=TEST_API_KEY)) is False
    result = connector_app.actions_manager.get_results()[-1]
    assert "Status Code: 429" in result.get_message()
    assert result.get_param() == params.model_dump(by_alias=True)


@pytest.mark.parametrize("identifier", ["lookup", "report", "connectivity"])
@pytest.mark.parametrize(
    ("status", "content_type", "body", "expected_prefix"),
    [
        (
            422,
            "application/json",
            b'{"errors":[{"detail":"Invalid input","status":422}]}',
            "Error from server.",
        ),
        (
            502,
            "text/html",
            b"<html><body>Gateway unavailable</body></html>",
            "Error from server.",
        ),
        (
            200,
            "text/html",
            b"<html>Unexpected response</html>",
            "Unable to parse JSON response.",
        ),
        (200, "text/plain", b"", "Unable to parse JSON response."),
    ],
)
def test_response_failure(
    identifier, status, content_type, body, expected_prefix, configured_service, soar
):
    configured_service["response"].update(
        status=status, content_type=content_type, body=body
    )
    asset = Asset(api_key=TEST_API_KEY)
    if identifier == "lookup":
        handler, arguments = lookup_ip, (LookupIpParams(ip="8.8.8.8"), soar, asset)
    elif identifier == "report":
        handler, arguments = (
            report_ip,
            (ReportIpParams(ip="8.8.8.8", category_ids="1"), soar, asset),
        )
    else:
        handler, arguments = run_connectivity, (soar, asset)
    if identifier == "connectivity":
        with pytest.raises(ActionFailure) as error:
            handler(*arguments)
        message = error.value.message
    else:
        result = handler(*arguments)
        assert isinstance(result, ActionResult)
        assert result.get_status() is False
        assert result.get_param() == arguments[0].model_dump(by_alias=True)
        message = result.get_message()
    assert expected_prefix in message
    if status >= 400:
        assert f"Status Code: {status}" in message
        # The SDK's offline shim retains escaped braces; SOAR's result class
        # formats them when setting the message.
        assert body.decode() in message.replace("{{", "{").replace("}}", "}")
    headers = {
        key.lower(): value
        for key, value in configured_service["events"][0]["headers"].items()
    }
    assert headers["accept"] == "application/json"
