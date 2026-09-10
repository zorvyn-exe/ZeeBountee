import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from click.testing import CliRunner

from zeebountee.models import Target
from zeebountee.modules.recon import check_liveness, recon_command


@pytest.mark.anyio
async def test_check_liveness_success() -> None:
    """Test that check_liveness properly parses and displays a successful HTTP response."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}
        mock_response.elapsed.total_seconds.return_value = 0.123
        mock_response.url = "https://example.com"
        mock_get.return_value = mock_response
        
        target = Target(host="example.com")
        result = await check_liveness(target)
        mock_get.assert_called_once_with("https://example.com", follow_redirects=True)
        assert result is not None
        assert result.status_code == 200

@pytest.mark.anyio
async def test_check_liveness_absolute_timeout() -> None:
    """Test that check_liveness cleanly handles asyncio.TimeoutError."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = asyncio.TimeoutError()
        target = Target(host="example.com")
        result = await check_liveness(target)
        mock_get.assert_called_once()
        assert result is None

@pytest.mark.anyio
async def test_check_liveness_connect_timeout() -> None:
    """Test that check_liveness cleanly handles httpx.ConnectTimeout."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectTimeout("Mocked Connect Timeout")
        target = Target(host="example.com")
        result = await check_liveness(target)
        mock_get.assert_called_once()
        assert result is None

@pytest.mark.anyio
async def test_check_liveness_read_timeout() -> None:
    """Test that check_liveness cleanly handles httpx.ReadTimeout."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ReadTimeout("Mocked Read Timeout")
        target = Target(host="example.com")
        result = await check_liveness(target)
        mock_get.assert_called_once()
        assert result is None

@pytest.mark.anyio
async def test_check_liveness_generic_network_error() -> None:
    """Test that check_liveness cleanly handles generic httpx.RequestError."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectError("Mocked Connect Error")
        target = Target(host="example.com")
        result = await check_liveness(target)
        mock_get.assert_called_once()
        assert result is None

@pytest.mark.anyio
async def test_check_liveness_timeout_multiplier() -> None:
    """Test that check_liveness uses timeout * 3 for absolute timeout."""
    async def mock_wait_for_side_effect(coro, timeout=None, **kwargs):
        coro.close()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        return mock_response

    with patch("zeebountee.modules.recon.asyncio.wait_for", new_callable=AsyncMock, side_effect=mock_wait_for_side_effect) as mock_wait:
        target = Target(host="example.com")
        await check_liveness(target, timeout=4.0)
        assert mock_wait.call_args[1]["timeout"] == 12.0

def test_recon_cli_command() -> None:
    """Test the synchronous Click CLI wrapper."""
    runner = CliRunner()
    def mock_run_fn(coro):
        coro.close()
        return None
        
    with patch("zeebountee.modules.recon.asyncio.run", side_effect=mock_run_fn) as mock_run:
        result = runner.invoke(recon_command, ["example.com", "--timeout", "3"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
