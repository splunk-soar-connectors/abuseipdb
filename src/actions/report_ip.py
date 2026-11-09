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


class ReportIpParams(Params):
    ip: str = Param(
        description="IPv4 or IPv6 to report on",
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    category_ids: str = Param(description="Comma delineated list of category IDs")
    comment: str | None = Param(description="Description of malicious activity")


class ReportIpData(ActionOutput):
    ipAddress: str | None = OutputField(
        cef_types=["ip", "ipv6"],
        example_values=["8.8.8.8", "2001:4860:4860::8888"],
    )
    abuseConfidenceScore: int | None = OutputField(example_values=[0])


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
    try:
        ipaddress.ip_address(params.ip)
    except ValueError as error:
        raise ActionFailure(f"Invalid IP address: {params.ip}") from error

    categories = ",".join(filter(None, params.category_ids.split(",")))
    comment = params.comment or ""
    headers = {"key": asset.api_key, "accept": "application/json"}
    body = {"ip": params.ip, "categories": categories, "comment": comment}
    try:
        with httpx.Client(
            headers=headers,
            timeout=None,  # noqa: S113 - preserve the legacy no-timeout behavior.
            follow_redirects=True,
        ) as client:
            response = client.post(f"{BASE_URL}/report", json=body)
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
                response_text = response.text.replace("{", "{{").replace("}", "}}")
                raise ActionFailure(
                    "Error from server. Status Code: "
                    f"{response.status_code} Data from server: {response_text}"
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
        response_text = response.text.replace("{", "{{").replace("}", "}}")
        raise ActionFailure(
            "Can't process response from server. Status Code: "
            f"{response.status_code} Data from server: {response_text}"
        )

    raw_data = raw_response.get("data")
    data = ReportIpData.model_validate(raw_data) if isinstance(raw_data, dict) else None
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
