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
"""Validate actual proxy routing and TLS trust without vendor calls or mocks."""

import ssl

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.network import get_proxy_options, get_tls_verification


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("proxy_source", ["ASSET", "SOAR"])
def test_broker_proxy_routing(scheme, proxy_source, network_env, loopback_service):
    proxy_variable = f"{proxy_source}_{scheme.upper()}_PROXY"
    network_env[proxy_variable] = loopback_service["url"]
    network_env["REQUESTS_CA_BUNDLE"] = loopback_service["ca"]
    if proxy_source == "ASSET":
        network_env[f"SOAR_{scheme.upper()}_PROXY"] = "http://127.0.0.1:1"
    url = f"{scheme}://api.abuseipdb.com/probe"
    with httpx.Client(
        verify=get_tls_verification(), **get_proxy_options(url, broker_mode=True)
    ) as client:
        assert client.get(url).status_code == 200
    assert loopback_service["events"][-1]["path"] == (
        url if scheme == "http" else "/probe"
    )


@pytest.mark.parametrize("bypass", ["127.0.0.0/8", "127.0.0.1", "*"])
def test_broker_bypass_also_disables_ambient_proxy(
    bypass, network_env, loopback_service
):
    network_env.update(
        {
            "ASSET_HTTP_PROXY": "http://127.0.0.1:1",
            "HTTP_PROXY": "http://127.0.0.1:2",
            "ALL_PROXY": "http://127.0.0.1:3",
            "NO_PROXY": bypass,
        }
    )
    url = loopback_service["url"] + "/direct"
    with httpx.Client(**get_proxy_options(url, broker_mode=True)) as client:
        assert client.get(url).status_code == 200
    assert loopback_service["events"][-1]["path"] == "/direct"


def test_non_broker_ignores_soar_proxy_variables(network_env):
    network_env["ASSET_HTTPS_PROXY"] = "http://127.0.0.1:1"
    assert get_proxy_options("https://api.abuseipdb.com", broker_mode=False) == {}


@pytest.mark.parametrize("ca_variable", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_custom_ca_tls_handshake(ca_variable, network_env, loopback_service):
    network_env[ca_variable] = loopback_service["ca"]
    network_env["HTTPS_PROXY"] = loopback_service["url"]
    if ca_variable == "REQUESTS_CA_BUNDLE":
        network_env["CURL_CA_BUNDLE"] = "/nonexistent/fallback.crt"
    context = get_tls_verification()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    with httpx.Client(verify=context) as client:
        assert client.get("https://api.abuseipdb.com/check").status_code == 200


def test_invalid_ca_reports_configuration_error(network_env):
    network_env["REQUESTS_CA_BUNDLE"] = "/nonexistent/trust.crt"
    with pytest.raises(ActionFailure, match="configured CA trust bundle"):
        get_tls_verification()


def test_tls_defaults_and_explicit_opt_out(network_env):
    assert get_tls_verification() is True
    network_env["REQUESTS_CA_BUNDLE"] = "/nonexistent/trust.crt"
    assert get_tls_verification(False) is False
