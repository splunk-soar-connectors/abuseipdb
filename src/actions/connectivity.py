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

import httpx
from soar_sdk.shims.phantom.install_info import is_onprem_broker_install
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure

from ..asset import Asset
from ..auth import create_auth
from ..network import get_proxy_options, get_tls_verification

BASE_URL = "https://api.abuseipdb.com/api/v2"


def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    headers = {"accept": "application/json"}
    body = {"ip": "127.0.0.1", "categories": "4", "comment": "Test Connectivity"}
    try:
        with httpx.Client(
            auth=create_auth(asset.api_key),
            headers=headers,
            verify=get_tls_verification(),
            **get_proxy_options(
                f"{BASE_URL}/report", broker_mode=is_onprem_broker_install()
            ),
            timeout=None,  # noqa: S113 - preserve the legacy no-timeout behavior.
            follow_redirects=True,
        ) as client:
            response = client.post(f"{BASE_URL}/report", json=body)
    except httpx.HTTPError as error:
        raise ActionFailure(
            f"Error Connecting to server. Details: {error!s}"
        ) from error

    # AbuseIPDB rejects a repeat test report for the same IP within 15 minutes.
    if response.status_code == 429:
        return

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        body = response.text.replace("{", "{{").replace("}", "}}")
        raise ActionFailure(
            f"Error from server. Status Code: {response.status_code} Data from server: {body}"
        ) from error

    try:
        response.json()
    except ValueError as error:
        raise ActionFailure(
            f"Unable to parse JSON response. Error: {error!s}"
        ) from error
