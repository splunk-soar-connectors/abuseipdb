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
from soar_sdk.logging import info

from ..asset import Asset
from ..auth import create_auth
from ..network import get_proxy_options, get_tls_verification

BASE_URL = "https://api.abuseipdb.com/api/v2"


def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    if asset.request_timeout <= 0:
        raise ActionFailure("The request_timeout setting must be greater than zero")
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
            timeout=asset.request_timeout,
            follow_redirects=True,
        ) as client:
            response = client.post(f"{BASE_URL}/report", json=body)
    except httpx.TimeoutException as error:
        raise ActionFailure(
            f"Request timed out after {asset.request_timeout} seconds of network inactivity"
        ) from error
    except httpx.HTTPError as error:
        raise ActionFailure(
            f"Error Connecting to server. Details: {error!s}"
        ) from error

    # A throttled request still passes connectivity. Persist the limitation in
    # the native UI progress stream; SDK warning-level logs are not UI messages.
    if response.status_code == 429:
        try:
            error_response = response.json()
        except ValueError:
            error_response = {}
        errors = (
            error_response.get("errors", []) if isinstance(error_response, dict) else []
        )
        details = (
            [
                error["detail"].lower()
                for error in errors
                if isinstance(error, dict) and isinstance(error.get("detail"), str)
            ]
            if isinstance(errors, list)
            else []
        )
        if any(
            "daily rate limit" in detail and "exceeded" in detail for detail in details
        ):
            warning = (
                "Warning: Connectivity test passed, but the daily report quota is exhausted. "
                "Reporting is unavailable until the quota resets."
            )
        elif any(
            "same ip address" in detail and "once in 15 minutes" in detail
            for detail in details
        ):
            warning = (
                "Warning: Connectivity test passed, but the test report was rejected "
                "because this IP was reported within the last 15 minutes."
            )
        else:
            warning = (
                "Warning: Connectivity test passed with HTTP 429 (Too Many Requests). "
                "The service is reachable, but this response does not confirm "
                "authentication or reporting permissions."
            )
        retry_after = response.headers.get("Retry-After", "")
        if retry_after.isascii() and retry_after.isdecimal():
            warning += f" Retry after {retry_after} seconds."
        info(warning)
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
