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
import ipaddress

import httpx
from soar_sdk.shims.phantom.install_info import is_onprem_broker_install
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import create_auth
from ..network import get_proxy_options, get_tls_verification

BASE_URL = "https://api.abuseipdb.com/api/v2"


class ReportIpParams(Params):
    ip: str = Param(
        description="IPv4 or IPv6 to report on",
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    category_ids: str = Param(description="Comma delineated list of category IDs")
    comment: str | None = Param(description="Description of malicious activity")
    request_timeout: int = Param(
        description="Network inactivity timeout in seconds (greater than zero)",
        required=False,
        default=30,
    )


class ReportIpData(ActionOutput):
    ipAddress: str | None = OutputField(
        cef_types=["ip", "ipv6"],
        column_name="IP",
        example_values=["8.8.8.8", "2001:4860:4860::8888"],
    )
    abuseConfidenceScore: int | None = OutputField(
        example_values=[0], column_name="Abuse Confidence Score"
    )


class ReportIpOutput(ActionOutput):
    data: ReportIpData | None = OutputField()


class ReportIpSummary(ActionOutput):
    categories_filed: int = OutputField(example_values=[4])
    comment_length: int = OutputField(example_values=[8])


def report_ip(
    params: ReportIpParams,
    soar: SOARClient,
    asset: Asset,
) -> ReportIpOutput:
    # SDK 7.2.1 drops parameters when it adapts a raised ActionFailure.
    # Keep the typed success annotation for schemas and native rendering; use
    # the SDK's ActionResult compatibility path only for expected failures.
    try:
        if params.request_timeout <= 0:
            raise ActionFailure(
                "The request_timeout parameter must be greater than zero"
            )
        try:
            ipaddress.ip_address(params.ip)
        except ValueError as error:
            raise ActionFailure(f"Invalid IP address: {params.ip}") from error

        categories = ",".join(filter(None, params.category_ids.split(",")))
        comment = params.comment or ""
        headers = {"accept": "application/json"}
        body = {"ip": params.ip, "categories": categories, "comment": comment}
        try:
            with httpx.Client(
                auth=create_auth(asset.api_key),
                headers=headers,
                verify=get_tls_verification(),
                **get_proxy_options(
                    f"{BASE_URL}/report", broker_mode=is_onprem_broker_install()
                ),
                timeout=params.request_timeout,
                follow_redirects=True,
            ) as client:
                response = client.post(f"{BASE_URL}/report", json=body)
        except httpx.TimeoutException as error:
            raise ActionFailure(
                f"Request timed out after {params.request_timeout} seconds of network inactivity"
            ) from error
        except httpx.HTTPError as error:
            raise ActionFailure(
                f"Error Connecting to server. Details: {error!s}"
            ) from error

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            body = response.text.replace("{", "{{").replace("}", "}}")
            raise ActionFailure(
                f"Error from server. Status Code: {response.status_code} Data from server: {body}"
            ) from error

        try:
            raw_response = response.json()
        except ValueError as error:
            raise ActionFailure(
                f"Unable to parse JSON response. Error: {error!s}"
            ) from error
        if not isinstance(raw_response, dict):
            raise ActionFailure("Unable to parse JSON response.")

        raw_data = raw_response.get("data")
        data = (
            ReportIpData.model_validate(raw_data)
            if isinstance(raw_data, dict)
            else None
        )
        categories_filed = len(categories.strip().replace(" ", "").split(","))

        soar.set_summary(
            ReportIpSummary(
                categories_filed=categories_filed,
                comment_length=len(comment),
            )
        )
        soar.set_message(
            "IP reported. Number of categories filed: "
            f"{categories_filed}, Comment length: {len(comment)}"
        )
        return ReportIpOutput(data=data)
    except ActionFailure as error:
        error.set_action_name("post ip")
        return ActionResult(  # type: ignore[return-value]
            status=False,
            message=str(error),
            param=params.model_dump(by_alias=True),
        )
