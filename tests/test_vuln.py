import typing
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from click.testing import CliRunner

from zeebountee.models import Finding, Severity, Target
from zeebountee.modules.vuln import (
    CookieSecurityCheck,
    InformationDisclosureCheck,
    SecurityHeadersCheck,
    TLSCheck,
    run_vuln_scan,
    vuln_command,
)


@pytest.mark.anyio
async def test_security_headers_check() -> None:
    target = Target(host="example.com")
    
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_response = httpx.Response(200, headers={"Some-Header": "Value"})
    mock_client.get.return_value = mock_response
    
    check = SecurityHeadersCheck()
    findings = await check.run(target, mock_client)
    
    assert len(findings) == 3
    titles = [f.title for f in findings]
    assert "Missing HSTS Header" in titles
    assert "Missing X-Frame-Options Header" in titles
    assert "Missing X-Content-Type-Options Header" in titles
    
    # Test with secure headers
    mock_response = httpx.Response(200, headers={
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
    })
    mock_client.get.return_value = mock_response
    
    findings = await check.run(target, mock_client)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_cookie_security_check() -> None:
    target = Target(host="example.com")
    check = CookieSecurityCheck()
    
    # Test 1: Missing both
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = httpx.Response(200, headers=[("Set-Cookie", "session_id=12345; path=/")])
    findings = await check.run(target, mock_client)
    assert len(findings) == 2
    titles = [f.title for f in findings]
    assert "Insecure Cookie (Missing Secure Flag)" in titles
    assert "Insecure Cookie (Missing HttpOnly Flag)" in titles

    # Test 2: Secure and HttpOnly present
    mock_client.get.return_value = httpx.Response(200, headers=[("Set-Cookie", "session_id=12345; path=/; Secure; HttpOnly")])
    findings = await check.run(target, mock_client)
    assert len(findings) == 0

    # Test 3: Value contains keywords but attributes are missing
    mock_client.get.return_value = httpx.Response(200, headers=[("Set-Cookie", "my_secure_httponly_cookie=secure_httponly; path=/")])
    findings = await check.run(target, mock_client)
    assert len(findings) == 2

    # Test 4: Missing Secure only
    mock_client.get.return_value = httpx.Response(200, headers=[("Set-Cookie", "session_id=12345; path=/; HttpOnly")])
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Insecure Cookie (Missing Secure Flag)"

    # Test 5: Missing HttpOnly only
    mock_client.get.return_value = httpx.Response(200, headers=[("Set-Cookie", "session_id=12345; path=/; Secure")])
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Insecure Cookie (Missing HttpOnly Flag)"

    # Test 6: Multiple cookies with different attributes
    mock_client.get.return_value = httpx.Response(200, headers=[
        ("Set-Cookie", "good_cookie=1; Secure; HttpOnly"),
        ("Set-Cookie", "bad_cookie=2")
    ])
    findings = await check.run(target, mock_client)
    assert len(findings) == 2
    assert all("bad_cookie" in f.evidence for f in findings)


@pytest.mark.anyio
async def test_information_disclosure_check() -> None:
    target = Target(host="example.com")
    
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_response = httpx.Response(200, headers={
        "Server": "Apache/2.4.1",
        "X-Powered-By": "PHP/7.4.3"
    })
    mock_client.get.return_value = mock_response
    
    check = InformationDisclosureCheck()
    findings = await check.run(target, mock_client)
    
    assert len(findings) == 2
    
    # Test without revealing headers
    mock_response = httpx.Response(200, headers={})
    mock_client.get.return_value = mock_response
    
    findings = await check.run(target, mock_client)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_tls_check() -> None:
    target = Target(host="example.com")
    check = TLSCheck()
    
    # 1. HTTP -> HTTP absolute redirect (insecure)
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_insecure_http(url: str, **kwargs: typing.Any) -> httpx.Response:
        if url == "http://example.com":
            return httpx.Response(301, headers={"Location": "http://other.com"})
        return httpx.Response(200)
    mock_client.get.side_effect = side_effect_insecure_http
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Insecure HTTP Redirection"
    assert "http://other.com" in findings[0].evidence

    # 2. HTTP -> HTTPS absolute redirect (secure)
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_secure_https(url: str, **kwargs: typing.Any) -> httpx.Response:
        if url == "http://example.com":
            return httpx.Response(301, headers={"Location": "https://other.com"})
        return httpx.Response(200)
    mock_client.get.side_effect = side_effect_secure_https
    findings = await check.run(target, mock_client)
    assert len(findings) == 0

    # 3. Relative redirect (secure)
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_relative(url: str, **kwargs: typing.Any) -> httpx.Response:
        if url == "http://example.com":
            return httpx.Response(301, headers={"Location": "/login"})
        return httpx.Response(200)
    mock_client.get.side_effect = side_effect_relative
    findings = await check.run(target, mock_client)
    assert len(findings) == 0

    # 4. Missing Location header (insecure)
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_missing(url: str, **kwargs: typing.Any) -> httpx.Response:
        if url == "http://example.com":
            return httpx.Response(301, headers={})
        return httpx.Response(200)
    mock_client.get.side_effect = side_effect_missing
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Insecure HTTP Redirection"
    assert findings[0].evidence == "Location header missing"

    # 5. Cleartext HTTP 200
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_200(url: str, **kwargs: typing.Any) -> httpx.Response:
        return httpx.Response(200)
    mock_client.get.side_effect = side_effect_200
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Cleartext HTTP Supported"
    assert "Status: 200" in findings[0].evidence

    # 6. Cleartext HTTP 401
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_401(url: str, **kwargs: typing.Any) -> httpx.Response:
        return httpx.Response(401)
    mock_client.get.side_effect = side_effect_401
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Cleartext HTTP Supported"
    assert "Status: 401" in findings[0].evidence

    # 7. Cleartext HTTP 403
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_403(url: str, **kwargs: typing.Any) -> httpx.Response:
        return httpx.Response(403)
    mock_client.get.side_effect = side_effect_403
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Cleartext HTTP Supported"
    assert "Status: 403" in findings[0].evidence

    # 8. Cleartext HTTP 404
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    def side_effect_404(url: str, **kwargs: typing.Any) -> httpx.Response:
        return httpx.Response(404)
    mock_client.get.side_effect = side_effect_404
    findings = await check.run(target, mock_client)
    assert len(findings) == 1
    assert findings[0].title == "Cleartext HTTP Supported"
    assert "Status: 404" in findings[0].evidence


@pytest.mark.anyio
async def test_run_vuln_scan() -> None:
    target = Target(host="example.com")
    
    with patch("zeebountee.modules.vuln.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_response = httpx.Response(200, headers={"Server": "Nginx"})
        mock_client.get.return_value = mock_response
        MockClient.return_value.__aenter__.return_value = mock_client
        
        findings = await run_vuln_scan(target)
        
        assert len(findings) > 0
        titles = [f.title for f in findings]
        assert "Missing HSTS Header" in titles
        assert "Information Disclosure (Server Header)" in titles

@pytest.mark.anyio
async def test_run_vuln_scan_timeout_multiplier() -> None:
    target = Target(host="example.com")
    
    async def mock_wait_for_side_effect(coro, timeout=None, **kwargs):
        coro.close()
        return []

    with patch("zeebountee.modules.vuln.asyncio.wait_for", new_callable=AsyncMock, side_effect=mock_wait_for_side_effect) as mock_wait:
        await run_vuln_scan(target, timeout=2.0)
        
        # Check that it was called with timeout * 3 (6.0)
        assert mock_wait.call_count > 0
        for call_args in mock_wait.call_args_list:
            assert call_args[1]["timeout"] == 6.0


def test_vuln_cli_command() -> None:
    runner = CliRunner()
    
    with patch("zeebountee.modules.vuln.run_vuln_scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = [
            Finding(title="Test Vuln", description="Desc", severity=Severity.HIGH, target="example.com", evidence="None")
        ]
        
        result = runner.invoke(vuln_command, ["example.com"])
        assert result.exit_code == 0
        assert "Vulnerability Assessment:" in result.output
        assert "Test Vuln" in result.output
        assert "HIGH" in result.output
