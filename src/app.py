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

from .actions import register_actions
from .actions.make_request import make_request
from .actions.test_connectivity import test_connectivity
from .asset import Asset


def create_abuseipdb_soar_connector_app() -> App:
    app = App(
        name="AbuseIPDB",
        app_type="reputation",
        logo="logo_abuseipdb.svg",
        logo_dark="logo_abuseipdb_dark.svg",
        product_vendor="AbuseIPDB",
        product_name="AbuseIPDB",
        publisher="Splunk",
        appid="52876771-17a7-45ad-8cc5-513bbd2172c5",
        python_version="3.13",
        min_phantom_version="7.0.0",
        fips_compliant=True,
        asset_cls=Asset,
    )

    app.test_connectivity()(test_connectivity)
    app.make_request()(make_request)

    return register_actions(app)


app: App = create_abuseipdb_soar_connector_app()


if __name__ == "__main__":
    app.cli()
