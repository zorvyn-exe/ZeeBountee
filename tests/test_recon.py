import pytest
import httpx
from unittest.mock import patch, AsyncMock, MagicMock
from click.testing import CliRunner
from zeebountee.modules.recon import check_liveness, recon_command

@pytest.mark.asyncio
async def test_check_liveness_success() -> None:
    """Test that check_liveness properly parses and displays a successful HTTP response."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}
        mock_response.elapsed.total_seconds.return_value = 0.123
        mock_response.url = "https://example.com"
        mock_get.return_value = mock_response
        
        await check_liveness("example.com")
        mock_get.assert_called_once_with("https://example.com", follow_redirects=True)

@pytest.mark.asyncio
async def test_check_liveness_timeout() -> None:
    """Test that check_liveness cleanly handles TimeoutExceptions."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.TimeoutException("Mocked Timeout")
        
        await check_liveness("example.com")
        mock_get.assert_called_once()

def test_recon_cli_command() -> None:
    """Test the synchronous Click CLI wrapper."""
    runner = CliRunner()
    with patch("zeebountee.modules.recon.asyncio.run") as mock_run:
        result = runner.invoke(recon_command, ["example.com", "--timeout", "3"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
