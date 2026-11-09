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
import json
from contextlib import suppress
from typing import Any
from urllib.parse import urlsplit

import httpx
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from ..asset import Asset

BASE_URL = "https://api.abuseipdb.com/api/v2/"


def make_request(params: MakeRequestParams, asset: Asset) -> MakeRequestOutput:
    endpoint = params.endpoint.strip()
    parsed_endpoint = urlsplit(endpoint)
    if not endpoint or parsed_endpoint.scheme or parsed_endpoint.netloc:
        raise ActionFailure("The endpoint must be a relative path")

    headers: dict[str, str] = {}
    if params.headers:
        try:
            custom_headers = json.loads(params.headers)
        except json.JSONDecodeError as error:
            raise ActionFailure(
                "The headers parameter must be a JSON object"
            ) from error
        if not isinstance(custom_headers, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in custom_headers.items()
        ):
            raise ActionFailure(
                "The headers parameter must contain string keys and values"
            )
        headers.update(
            {
                key: value
                for key, value in custom_headers.items()
                if key.lower() not in {"key", "accept"}
            }
        )
    # Keep the configured API key and JSON response preference authoritative.
    headers.update({"key": asset.api_key, "accept": "application/json"})

    query_parameters: str | dict[str, object] | None = None
    if params.query_parameters:
        try:
            parsed_query = json.loads(params.query_parameters)
        except json.JSONDecodeError:
            query_parameters = params.query_parameters.lstrip("?")
        else:
            if not isinstance(parsed_query, dict):
                raise ActionFailure(
                    "The query_parameters parameter must be a JSON object or query string"
                )
            query_parameters = parsed_query

    request_body: object = None
    body_as_json = False
    if params.body is not None:
        try:
            request_body = json.loads(params.body)
            body_as_json = True
        except json.JSONDecodeError:
            request_body = params.body

    if params.timeout is not None and params.timeout <= 0:
        raise ActionFailure("The timeout parameter must be greater than zero")

    try:
        with httpx.Client(
            base_url=BASE_URL,
            verify=params.verify_ssl,
            timeout=params.timeout,
            follow_redirects=True,
        ) as client:
            request_options: dict[str, Any] = {
                "params": query_parameters,
                "headers": headers,
            }
            if params.body is not None:
                request_options["json" if body_as_json else "content"] = request_body
            response = client.request(
                params.http_method,
                endpoint.lstrip("/"),
                **request_options,
            )
            with suppress(httpx.HTTPStatusError):
                response.raise_for_status()
                # Make Request returns the vendor response for HTTP status errors.
    except httpx.HTTPError as error:
        safe_error = str(error)
        if asset.api_key:
            safe_error = safe_error.replace(asset.api_key, "[REDACTED]")
        raise ActionFailure(
            f"Error Connecting to server. Details: {safe_error}"
        ) from error

    response_body = response.text
    if asset.api_key:
        response_body = response_body.replace(asset.api_key, "[REDACTED]")
    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response_body,
    )
