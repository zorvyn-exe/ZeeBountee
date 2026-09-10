import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner
import httpx

from zeebountee.models import Target
from zeebountee.modules.web_discovery import check_endpoint, discover_web_command, run_web_discovery

@pytest.fixture
def target():
    return Target(host="example.com")

class MockStreamResponse:
    def __init__(self, status_code, headers=None, body=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def aiter_bytes(self, chunk_size=4096):
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i:i+chunk_size]


@pytest.mark.anyio
async def test_check_endpoint_200(target):
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/plain"}))
    
    result = await check_endpoint(mock_client, target, "/robots.txt", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert result.description == "FOUND/AVAILABLE"
    assert result.url == "https://example.com/robots.txt"

@pytest.mark.anyio
async def test_check_endpoint_200_soft_404(target):
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/html; charset=utf-8"}))
    
    result = await check_endpoint(mock_client, target, "/robots.txt", 5.0)
    
    assert result.found is False
    assert result.status_code == 200
    assert "Soft 404" in result.description
    assert "text/html" in result.description

@pytest.mark.anyio
async def test_check_endpoint_404(target):
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(404))
    
    result = await check_endpoint(mock_client, target, "/robots.txt", 5.0)
    
    assert result.found is False
    assert result.status_code == 404
    assert result.description == "NOT FOUND"

@pytest.mark.anyio
async def test_check_endpoint_redirect(target):
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(301, headers={"Location": "/new-robots.txt"}))
    
    result = await check_endpoint(mock_client, target, "/robots.txt", 5.0)
    
    assert result.found is True
    assert result.status_code == 301
    assert "REDIRECT" in result.description
    assert "/new-robots.txt" in result.description

@pytest.mark.anyio
async def test_check_endpoint_timeout(target):
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(side_effect=httpx.TimeoutException("Timeout"))
    
    result = await check_endpoint(mock_client, target, "/robots.txt", 5.0)
    
    assert result.found is False
    assert result.status_code is None
    assert "Timeout" in result.description

@pytest.mark.anyio
async def test_run_web_discovery(target):
    with patch("zeebountee.modules.web_discovery.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client_instance
        
        # Make it return 200 for all endpoints with text/plain to avoid soft 404 detection
        mock_client_instance.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/plain"}))
        
        results = await run_web_discovery(target, 5.0)
        
        assert len(results) == 3
        urls = [r.url for r in results]
        assert "https://example.com/robots.txt" in urls
        assert "https://example.com/sitemap.xml" in urls
        assert "https://example.com/.well-known/security.txt" in urls

def test_discover_web_command_cli():
    runner = CliRunner()
    
    with patch("zeebountee.modules.web_discovery.run_web_discovery") as mock_run:
        mock_run.return_value = []
        result = runner.invoke(discover_web_command, ["example.com"])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

@pytest.mark.anyio
async def test_check_endpoint_sitemap_urlset(target):
    xml_content = b'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://example.com/1</loc></url><url><loc>http://example.com/2</loc></url></urlset>'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "application/xml"}, body=xml_content))
    
    result = await check_endpoint(mock_client, target, "/sitemap.xml", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "urlset" in result.description
    assert "2 URLs" in result.description

@pytest.mark.anyio
async def test_check_endpoint_sitemap_sitemapindex(target):
    xml_content = b'<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>http://example.com/sitemap1.xml</loc></sitemap></sitemapindex>'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "application/xml"}, body=xml_content))
    
    result = await check_endpoint(mock_client, target, "/sitemap.xml", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "sitemapindex" in result.description
    assert "1 URLs" in result.description

@pytest.mark.anyio
async def test_check_endpoint_sitemap_malformed(target):
    xml_content = b'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://example.com/1</loc></url>'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "application/xml"}, body=xml_content))
    
    result = await check_endpoint(mock_client, target, "/sitemap.xml", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "urlset" in result.description
    assert "1 URLs" in result.description
    # Note: Even if malformed, since it's truncated or incomplete we expect it to report urlset, 1 URLs.
    # If the tag is not found at all, it would report XML Parse Failed.

@pytest.mark.anyio
async def test_check_endpoint_sitemap_malformed_no_tag(target):
    xml_content = b'Not XML content at all'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "application/xml"}, body=xml_content))
    
    result = await check_endpoint(mock_client, target, "/sitemap.xml", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "XML Parse Failed" in result.description

@pytest.mark.anyio
async def test_check_endpoint_sitemap_empty(target):
    xml_content = b''
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "application/xml"}, body=xml_content))
    
    result = await check_endpoint(mock_client, target, "/sitemap.xml", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "XML Parse Failed" in result.description

@pytest.mark.anyio
async def test_check_endpoint_sitemap_large_truncated(target):
    # Create a 40KB body
    xml_start = b'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    xml_mid = b'<url><loc>http://example.com/1</loc></url>' * 1000  # 43 bytes * 1000 = 43000 bytes
    xml_content = xml_start + xml_mid
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "application/xml"}, body=xml_content))
    
    result = await check_endpoint(mock_client, target, "/sitemap.xml", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "urlset" in result.description
    # Since we truncate at 32KB, loc_count will be less than 1000
    assert "URLs" in result.description

@pytest.mark.anyio
async def test_check_endpoint_security_txt_all_fields(target):
    txt_content = b'# Comments and blank lines should be ignored\n\nContact: mailto:security@example.com\ncontact: https://example.com/security\nPolicy: https://example.com/policy\nExpires: 2026-12-31T23:59:59Z\n'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/plain"}, body=txt_content))
    
    result = await check_endpoint(mock_client, target, "/.well-known/security.txt", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "2 Contact" in result.description
    assert "Policy" in result.description
    assert "Expires" in result.description

@pytest.mark.anyio
async def test_check_endpoint_security_txt_case_insensitive(target):
    txt_content = b'cOnTaCt: mailto:security@example.com\npOLiCy: https://example.com/policy\neXpIrEs: 2026-12-31T23:59:59Z\n'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/plain"}, body=txt_content))
    
    result = await check_endpoint(mock_client, target, "/.well-known/security.txt", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "1 Contact" in result.description
    assert "Policy" in result.description
    assert "Expires" in result.description

@pytest.mark.anyio
async def test_check_endpoint_security_txt_no_fields(target):
    txt_content = b'Just a regular file that is not security.txt but returns 200 text/plain\nSome text here\n'
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/plain"}, body=txt_content))
    
    result = await check_endpoint(mock_client, target, "/.well-known/security.txt", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert result.description == "FOUND/AVAILABLE"

@pytest.mark.anyio
async def test_check_endpoint_security_txt_large_truncated(target):
    # Create a 20KB body
    txt_start = b'Contact: mailto:sec@example.com\n'
    txt_mid = b'# Some long comment here to pad the file\n' * 1000
    txt_end = b'Policy: https://example.com/policy\n'
    txt_content = txt_start + txt_mid + txt_end
    
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=MockStreamResponse(200, headers={"Content-Type": "text/plain"}, body=txt_content))
    
    result = await check_endpoint(mock_client, target, "/.well-known/security.txt", 5.0)
    
    assert result.found is True
    assert result.status_code == 200
    assert "1 Contact" in result.description
    # Policy is at the end, so it will be truncated and not parsed (since it's beyond 16KB)
    assert "Policy" not in result.description
