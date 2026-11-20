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
"""Regression coverage for the manifest consumed by SOAR's native table renderer."""

import json

import pytest

from src.actions.lookup_ip import LookupIpParams, lookup_ip
from src.app import app
from src.asset import Asset

TEST_API_KEY = "offline-test-value"  # pragma: allowlist secret - local test value


@pytest.mark.parametrize(
    ("identifier", "expected_columns"),
    [
        (
            "lookup_ip",
            [
                ("Days", "parameter.days"),
                ("Abuse Confidence Score", "abuseConfidenceScore"),
                ("Country Code", "countryCode"),
                ("Country", "countryName"),
                ("Domain", "domain"),
                ("IP", "ipAddress"),
                ("Is Public", "isPublic"),
                ("ISP", "isp"),
                ("Last Reported At", "lastReportedAt"),
                ("Categories", "reports.*.categoriesDisplay"),
                ("Comment", "reports.*.comment"),
                ("Reported At", "reports.*.reportedAt"),
                ("Reporter Country Code", "reports.*.reporterCountryCode"),
                ("Reporter Country Name", "reports.*.reporterCountryName"),
                ("Reporter ID", "reports.*.reporterId"),
                ("Total Reports", "totalReports"),
                ("Usage Type", "usageType"),
            ],
        ),
        (
            "report_ip",
            [("IP", "ipAddress"), ("Abuse Confidence Score", "abuseConfidenceScore")],
        ),
    ],
)
def test_native_table_manifest(identifier, expected_columns):
    manifest = app.get_actions()[identifier].meta.model_dump()

    assert manifest["render"] == {"type": "table"}
    columns = [field for field in manifest["output"] if "column_name" in field]
    assert [
        (field["column_name"], field["data_path"], field["column_order"])
        for field in columns
    ] == [
        (
            name,
            f"action_result.{field}"
            if field.startswith("parameter.")
            else f"action_result.data.*.data.{field}",
            order,
        )
        for order, (name, field) in enumerate(expected_columns)
    ]
    ip_column = next(field for field in columns if field["column_name"] == "IP")
    assert ip_column["contains"] == ["ip", "ipv6"]


def test_lookup_preserves_category_array_and_request_window():
    manifest = app.get_actions()["lookup_ip"].meta.model_dump()
    category = next(
        field
        for field in manifest["output"]
        if field["data_path"].endswith(".reports.*.categories.*")
    )
    assert category["data_type"] == "numeric"
    assert "column_name" not in category
    days = next(
        field
        for field in manifest["output"]
        if field["data_path"] == "action_result.parameter.days"
    )
    assert days["column_name"] == "Days"


@pytest.mark.parametrize(
    "reports",
    [
        [
            {"reporterId": 11, "comment": "first", "categories": [3, 4]},
            {"reporterId": 22, "comment": "second", "categories": [5]},
            {"reporterId": 33, "comment": "empty categories", "categories": []},
            {"reporterId": 44, "comment": "missing categories"},
        ],
        [],
        None,
    ],
)
def test_lookup_report_display_preserves_data(reports, configured_service, soar):
    configured_service["response"]["body"] = json.dumps(
        {"data": {"ipAddress": "192.0.2.1", "reports": reports}}
    ).encode()
    output = lookup_ip(
        LookupIpParams(ip="192.0.2.1"), soar, Asset(api_key=TEST_API_KEY)
    )
    assert output.data.ipAddress == "192.0.2.1"
    if reports is None:
        assert output.data.reports is None
        return
    assert len(output.data.reports) == len(reports)
    for source, report in zip(reports, output.data.reports, strict=True):
        assert report.reporterId == source["reporterId"]
        assert report.comment == source["comment"]
        assert report.categories == source.get("categories")
        expected = source.get("categories")
        assert report.categoriesDisplay == (
            ", ".join(str(value) for value in expected)
            if expected is not None
            else None
        )
