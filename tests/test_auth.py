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
"""Exercise the real SDK authentication flow without sending requests."""

import httpx
import pytest

from src.auth import create_auth


@pytest.mark.parametrize("header_name", [None, "key", "Key", "KEY"])
def test_auth_sends_raw_configured_key_and_overrides_caller(header_name):
    headers = {"accept": "application/json", "X-Test": "preserved"}
    if header_name:
        headers[header_name] = "caller-value"
    request = httpx.Request(
        "GET", "https://api.abuseipdb.com/api/v2/check", headers=headers
    )

    flow = create_auth("configured-test-value").sync_auth_flow(request)
    authenticated_request = next(flow)

    assert authenticated_request.headers.get_list("key") == ["configured-test-value"]
    assert "authorization" not in authenticated_request.headers
    assert authenticated_request.headers["accept"] == "application/json"
    assert authenticated_request.headers["X-Test"] == "preserved"
    flow.close()
