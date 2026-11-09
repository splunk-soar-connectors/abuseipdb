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
from html.parser import HTMLParser

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset

BASE_URL = "https://api.abuseipdb.com/api/v2"


class _HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)


class LookupIpParams(Params):
    ip: str = Param(
        description="IPv4 or IPv6 to query",
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    days: int = Param(
        description="Check for IP Reports within this number of days",
        default=10,
    )


class ReportOutput(ActionOutput):
    # The API returns categories as a list; the legacy manifest declared a scalar.
    categories: list[int] | None = OutputField(example_values=[3])
    comment: str | None = OutputField(
        example_values=[
            "Secure Shell (SSH) abuse. This category in combination with more specific categories."
        ]
    )
    reportedAt: str | None = OutputField(example_values=["2019-05-21T10:18:49+01:00"])
    reporterCountryCode: str | None = OutputField(example_values=["US"])
    reporterCountryName: str | None = OutputField(example_values=["United States"])
    reporterId: int | None = OutputField(example_values=[29933])


class LookupIpData(ActionOutput):
    abuseConfidenceScore: int | None = OutputField(example_values=[0])
    countryCode: str | None = OutputField(example_values=["US"])
    countryName: str | None = OutputField(example_values=["United States"])
    domain: str | None = OutputField(cef_types=["domain", "url"])
    ipAddress: str | None = OutputField(
        cef_types=["ip", "ipv6"],
        example_values=["8.8.8.8", "2001:4860:4860::8888"],
    )
    ipVersion: int | None = OutputField(example_values=[4])
    isPublic: bool | None = OutputField()
    isWhitelisted: bool | None = OutputField()
    isp: str | None = OutputField(example_values=["Private IP Address LAN"])
    lastReportedAt: str | None = OutputField(
        example_values=["2019-05-21T10:18:49+01:00"]
    )
    reports: list[ReportOutput] | None = OutputField()
    totalReports: int | None = OutputField(example_values=[5])
    usageType: str | None = OutputField(example_values=["Reserved"])
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
    try:
        ipaddress.ip_address(params.ip)
    except ValueError as error:
        raise ActionFailure(f"Invalid IP address: {params.ip}") from error

    headers = {"key": asset.api_key, "accept": "application/json"}
    query = {"ipAddress": params.ip, "maxAgeInDays": params.days, "verbose": "yes"}
    try:
        with httpx.Client(
            headers=headers,
            timeout=None,  # noqa: S113 - preserve the legacy no-timeout behavior.
            follow_redirects=True,
        ) as client:
            response = client.get(f"{BASE_URL}/check", params=query)
    except httpx.HTTPError as error:
        raise ActionFailure(
            f"Error Connecting to server. Details: {error!s}"
        ) from error

    content_type = response.headers.get("Content-Type", "")
    if "json" in content_type:
        try:
            raw_response = response.json()
        except Exception as error:
            raise ActionFailure(
                f"Unable to parse JSON response. Error: {error!s}"
            ) from error
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            if not 200 <= response.status_code < 399:
                body = response.text.replace("{", "{{").replace("}", "}}")
                raise ActionFailure(
                    "Error from server. Status Code: "
                    f"{response.status_code} Data from server: {body}"
                ) from error
        if not isinstance(raw_response, dict):
            raise ActionFailure("Unable to parse JSON response.")
    elif "html" in content_type:
        parser = _HTMLTextParser()
        parser.feed(response.text)
        lines = [part.strip() for part in "".join(parser.text_parts).split("\n")]
        error_text = "\n".join(line for line in lines if line)
        message = (
            f"Status Code: {response.status_code}. Data from server:\n{error_text}\n"
        )
        raise ActionFailure(message.replace("{", "{{").replace("}", "}}"))
    elif not response.text:
        if response.status_code != 200:
            raise ActionFailure("Empty response and no information in the header")
        raw_response = {}
    else:
        body = response.text.replace("{", "{{").replace("}", "}}")
        raise ActionFailure(
            "Can't process response from server. Status Code: "
            f"{response.status_code} Data from server: {body}"
        )

    raw_data = raw_response.get("data")
    data = LookupIpData.model_validate(raw_data) if isinstance(raw_data, dict) else None
    reports_found = len(data.reports or []) if data else 0

    soar.set_summary(LookupIpSummary(reports_found=reports_found))
    soar.set_message(f"IP lookup complete. Reports found: {reports_found}")
    return LookupIpOutput(data=data)
