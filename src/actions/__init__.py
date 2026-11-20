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
from soar_sdk.app import App

from .lookup_ip import LookupIpSummary, lookup_ip
from .report_ip import ReportIpSummary, report_ip

REPORT_VERBOSE = (
    "Reports an IP given the categories. The categories can be found in "
    "<a href='https://www.abuseipdb.com/categories'>Report Categories</a>. "
    "There is a limit on reporting the same IP for an interval of <b>15 "
    "minutes</b>. There is a comment limit of <b>1024 characters</b>."
)


def register_actions(app: App) -> App:
    app.register_action(
        lookup_ip,
        name="lookup ip",
        identifier="lookup_ip",
        description="Queries IP info",
        verbose="The AbuseIPDB service has a limit of 1000 lookups per day.",
        action_type="investigate",
        read_only=True,
        render_as="table",
        versions="EQ(*)",
        summary_type=LookupIpSummary,
    )
    app.register_action(
        report_ip,
        name="post ip",
        identifier="report_ip",
        description="Report an IP for abusive behavior",
        verbose=REPORT_VERBOSE,
        action_type="generic",
        read_only=False,
        render_as="table",
        versions="EQ(*)",
        summary_type=ReportIpSummary,
    )
    return app
