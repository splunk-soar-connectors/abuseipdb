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
"""Targeted unit coverage for successful connectivity with throttling warnings."""

import httpx
import pytest

from src.actions.connectivity import test_connectivity as run_connectivity
from src.asset import Asset

TEST_API_KEY = "offline-test-value"  # pragma: allowlist secret - local test value


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        (
            "You can only report the same IP address (`127.0.0.1`) once in 15 minutes.",
            "this IP was reported within the last 15 minutes",
        ),
        (
            "Daily rate limit of 1000 requests exceeded for this endpoint.",
            "daily report quota is exhausted",
        ),
        (
            "Unknown throttle",
            "does not confirm authentication or reporting permissions",
        ),
    ],
)
def test_429_passes_and_emits_persistent_warning(
    detail, expected, mocker, network_env, soar
):
    client = mocker.patch("src.actions.connectivity.httpx.Client")
    client.return_value.__enter__.return_value.post.return_value = httpx.Response(
        429,
        json={"errors": [{"detail": detail, "status": 429}]},
        headers={"Retry-After": "60"},
    )
    native_info = mocker.patch("src.actions.connectivity.info")

    assert run_connectivity(soar, Asset(api_key=TEST_API_KEY)) is None

    native_info.assert_called_once()
    message = native_info.call_args.args[0]
    assert message.startswith("Warning: Connectivity test passed")
    assert expected in message
    assert message.endswith("Retry after 60 seconds.")
