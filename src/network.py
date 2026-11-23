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
"""Retain platform trust and broker proxy configuration with HTTPX."""

import os
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from requests.utils import should_bypass_proxies
from soar_sdk.exceptions import ActionFailure


def get_tls_verification(verify_ssl: bool = True) -> bool | ssl.SSLContext:
    """Honor Requests CA overrides before HTTPX's normal trust configuration."""
    if not verify_ssl:
        return False
    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")
    if not ca_bundle:
        return True
    try:
        if Path(ca_bundle).is_dir():
            return ssl.create_default_context(capath=ca_bundle)
        return ssl.create_default_context(cafile=ca_bundle)
    except OSError as error:
        raise ActionFailure("Unable to load the configured CA trust bundle") from error


def get_proxy_options(url: str, *, broker_mode: bool) -> dict[str, Any]:
    """Apply the legacy broker's asset-before-SOAR proxy precedence and bypass."""
    if not broker_mode:
        return {}
    scheme = urlsplit(url).scheme.upper()
    proxy = os.environ.get(f"ASSET_{scheme}_PROXY") or os.environ.get(
        f"SOAR_{scheme}_PROXY"
    )
    if not proxy:
        return {}
    # Reuse Requests' matching rules, including CIDR, just as the platform does.
    if should_bypass_proxies(url, os.environ.get("NO_PROXY")):
        # An explicit HTTPX proxy ignores NO_PROXY. Disable ambient proxies too
        # when the legacy bypass rules match, without disabling CA environment settings.
        return {"mounts": {"http://": None, "https://": None, "all://": None}}
    return {"proxy": proxy if "://" in proxy else f"http://{proxy}"}
