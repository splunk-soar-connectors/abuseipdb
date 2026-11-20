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
"""Real loopback HTTP/TLS services for request-level regression checks."""

import os
import ssl
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.app import create_abuseipdb_soar_connector_app


@pytest.fixture
def network_env():
    keys = [
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "ASSET_HTTP_PROXY",
        "ASSET_HTTPS_PROXY",
        "SOAR_HTTP_PROXY",
        "SOAR_HTTPS_PROXY",
    ]
    original = {key: os.environ.get(key) for key in keys}
    for key in keys:
        os.environ.pop(key, None)
    yield os.environ
    for key, value in original.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture
def loopback_service(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "AbuseIPDB local test CA")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("api.abuseipdb.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    ca_path = tmp_path / "trust.crt"
    key_path = tmp_path / "server.key"
    ca_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(ca_path, key_path)
    events = []
    response = {
        "status": 200,
        "content_type": "application/json",
        "body": b'{"data": {}}',
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_CONNECT(self):
            self.send_response(200, "Connection established")
            self.end_headers()
            try:
                self.connection = tls_context.wrap_socket(
                    self.connection, server_side=True
                )
            except ssl.SSLError:
                # The untrusted-CA tests deliberately reject this certificate.
                self.close_connection = True
                return
            self.rfile = self.connection.makefile("rb")
            self.wfile = self.connection.makefile("wb")
            self.handle_one_request()

        def do_GET(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            events.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body,
                }
            )
            payload = response["body"]
            self.send_response(response["status"])
            self.send_header("Content-Type", response["content_type"])
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        do_POST = do_GET

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"http://127.0.0.1:{server.server_port}",
            "ca": str(ca_path),
            "events": events,
            "response": response,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def configured_service(network_env, loopback_service):
    network_env["HTTPS_PROXY"] = loopback_service["url"]
    network_env["REQUESTS_CA_BUNDLE"] = loopback_service["ca"]
    return loopback_service


@pytest.fixture
def connector_app():
    app = create_abuseipdb_soar_connector_app()
    try:
        yield app
    finally:
        app.soar_client._client.close()


@pytest.fixture
def soar(connector_app):
    return connector_app.soar_client
