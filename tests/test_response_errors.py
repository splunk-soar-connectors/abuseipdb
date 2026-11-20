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
