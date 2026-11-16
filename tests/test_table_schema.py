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

import pytest

from src.app import app


@pytest.mark.parametrize(
    ("identifier", "expected_columns"),
    [
        (
            "lookup_ip",
            [
                ("Abuse Confidence Score", "abuseConfidenceScore"),
                ("Country", "countryName"),
                ("Domain", "domain"),
                ("IP", "ipAddress"),
                ("ISP", "isp"),
                ("Total Reports", "totalReports"),
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
        (name, f"action_result.data.*.data.{field}", order)
        for order, (name, field) in enumerate(expected_columns)
    ]
    ip_column = next(field for field in columns if field["column_name"] == "IP")
    assert ip_column["contains"] == ["ip", "ipv6"]
