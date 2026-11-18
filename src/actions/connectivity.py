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
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure

from ..asset import Asset
from ..auth import create_auth
from .utils import html_error_text

BASE_URL = "https://api.abuseipdb.com/api/v2"


def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    headers = {"accept": "application/json"}
    body = {"ip": "127.0.0.1", "categories": "4", "comment": "Test Connectivity"}
    try:
        with httpx.Client(
            auth=create_auth(asset.api_key),
            headers=headers,
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

    content_type = response.headers.get("Content-Type", "")
    if "json" in content_type:
        try:
            response.json()
        except Exception as error:
            raise ActionFailure(
                f"Unable to parse JSON response. Error: {error!s}"
            ) from error
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            if not 200 <= response.status_code < 399:
                response_text = response.text.replace("{", "{{").replace("}", "}}")
                raise ActionFailure(
                    "Error from server. Status Code: "
                    f"{response.status_code} Data from server: {response_text}"
                ) from error
        return

    if "html" in content_type:
        error_text = html_error_text(response.text)
        message = (
            f"Status Code: {response.status_code}. Data from server:\n{error_text}\n"
        )
        raise ActionFailure(message)

    if not response.text:
        if response.status_code == 200:
            return
        raise ActionFailure("Empty response and no information in the header")

    response_text = response.text.replace("{", "{{").replace("}", "}}")
    raise ActionFailure(
        "Can't process response from server. Status Code: "
        f"{response.status_code} Data from server: {response_text}"
    )
