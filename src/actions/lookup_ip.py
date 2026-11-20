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


class LookupIpParams(Params):
    ip: str = Param(
        description="IPv4 or IPv6 to query",
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    days: int = Param(
        description="Check for IP Reports within this number of days",
        default=10,
        column_name="Days",
    )


class ReportOutput(ActionOutput):
    # The API returns categories as a list; the legacy manifest declared a scalar.
    categories: list[int] | None = OutputField(example_values=[3])
    # Native table datapaths expand lists with a trailing wildcard, which cannot
    # render the category array as one cell. Keep the API array for playbooks
    # and use a scalar display value to keep categories aligned with each report.
    categoriesDisplay: str | None = OutputField(column_name="Categories")
    comment: str | None = OutputField(
        column_name="Comment",
        example_values=[
            "Secure Shell (SSH) abuse. This category in combination with more specific categories."
        ],
    )
    reportedAt: str | None = OutputField(
        example_values=["2019-05-21T10:18:49+01:00"], column_name="Reported At"
    )
    reporterCountryCode: str | None = OutputField(
        example_values=["US"], column_name="Reporter Country Code"
    )
    reporterCountryName: str | None = OutputField(
        example_values=["United States"], column_name="Reporter Country Name"
    )
    reporterId: int | None = OutputField(
        example_values=[29933], column_name="Reporter ID"
    )


class LookupIpData(ActionOutput):
    abuseConfidenceScore: int | None = OutputField(
        example_values=[0], column_name="Abuse Confidence Score"
    )
    countryCode: str | None = OutputField(
        example_values=["US"], column_name="Country Code"
    )
    countryName: str | None = OutputField(
        example_values=["United States"], column_name="Country"
    )
    domain: str | None = OutputField(cef_types=["domain", "url"], column_name="Domain")
    hostnames: list[str] | None = OutputField()
    ipAddress: str | None = OutputField(
        cef_types=["ip", "ipv6"],
        column_name="IP",
        example_values=["8.8.8.8", "2001:4860:4860::8888"],
    )
    ipVersion: int | None = OutputField(example_values=[4])
    isPublic: bool | None = OutputField(column_name="Is Public")
    isTor: bool | None = OutputField()
    isWhitelisted: bool | None = OutputField()
    isp: str | None = OutputField(
        example_values=["Private IP Address LAN"], column_name="ISP"
    )
    lastReportedAt: str | None = OutputField(
        example_values=["2019-05-21T10:18:49+01:00"], column_name="Last Reported At"
    )
    reports: list[ReportOutput] | None = OutputField()
    totalReports: int | None = OutputField(
        example_values=[5], column_name="Total Reports"
    )
    usageType: str | None = OutputField(
        example_values=["Reserved"], column_name="Usage Type"
    )
    numDistinctUsers: int | None = OutputField(example_values=[0])


class LookupIpOutput(ActionOutput):
    data: LookupIpData | None = OutputField()


class LookupIpSummary(ActionOutput):
    reports_found: int = OutputField(example_values=[0])


def lookup_ip(
    params: LookupIpParams,
    soar: SOARClient,
    asset: Asset,
) -> LookupIpOutput:
    # SDK 7.2.1 drops parameters when it adapts a raised ActionFailure.
    # Keep the typed success annotation for schemas and native rendering; use
    # the SDK's ActionResult compatibility path only for expected failures.
    try:
        try:
            ipaddress.ip_address(params.ip)
        except ValueError as error:
            raise ActionFailure(f"Invalid IP address: {params.ip}") from error

        headers = {"accept": "application/json"}
        query = {"ipAddress": params.ip, "maxAgeInDays": params.days, "verbose": "yes"}
        try:
            with httpx.Client(
                auth=create_auth(asset.api_key),
                headers=headers,
                verify=get_tls_verification(),
                **get_proxy_options(
                    f"{BASE_URL}/check", broker_mode=is_onprem_broker_install()
                ),
                timeout=None,  # noqa: S113 - preserve the legacy no-timeout behavior.
                follow_redirects=True,
            ) as client:
                response = client.get(f"{BASE_URL}/check", params=query)
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
            LookupIpData.model_validate(raw_data)
            if isinstance(raw_data, dict)
            else None
        )
        if data:
            for report in data.reports or []:
                report.categoriesDisplay = (
                    ", ".join(str(category) for category in report.categories)
                    if report.categories is not None
                    else None
                )
        reports_found = len(data.reports or []) if data else 0

        soar.set_summary(LookupIpSummary(reports_found=reports_found))
        soar.set_message(f"IP lookup complete. Reports found: {reports_found}")
        return LookupIpOutput(data=data)
    except ActionFailure as error:
        error.set_action_name("lookup ip")
        return ActionResult(  # type: ignore[return-value]
            status=False,
            message=str(error),
            param=params.model_dump(by_alias=True),
        )
