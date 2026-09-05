import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from click.testing import CliRunner
from zeebountee.modules.ports import scan_port, run_port_scan, ports_command, COMMON_PORTS

@pytest.mark.asyncio
async def test_scan_port_open() -> None:
    """Test that scan_port returns True when a connection is successfully established."""
    with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait_for:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_wait_for.return_value = (mock_reader, mock_writer)
        
        port, service, is_open = await scan_port("example.com", 80, 1.0)
        
        assert port == 80
        assert service == "HTTP"
        assert is_open is True
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()

@pytest.mark.asyncio
async def test_scan_port_closed() -> None:
    """Test that scan_port returns False when a connection is refused."""
    with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait_for:
        mock_wait_for.side_effect = ConnectionRefusedError()
        
        port, service, is_open = await scan_port("example.com", 80, 1.0)
        
        assert port == 80
        assert is_open is False

@pytest.mark.asyncio
async def test_run_port_scan() -> None:
    """Test the orchestration of scanning all common ports concurrently."""
    with patch("zeebountee.modules.ports.scan_port", new_callable=AsyncMock) as mock_scan:
        def side_effect(host: str, port: int, timeout: float):
            return port, "Service", port == 80
        mock_scan.side_effect = side_effect
        
        await run_port_scan("example.com", 1.0)
        assert mock_scan.call_count == len(COMMON_PORTS)

def test_ports_cli_command() -> None:
    """Test the synchronous Click CLI wrapper for the ports command."""
    runner = CliRunner()
    with patch("zeebountee.modules.ports.asyncio.run") as mock_run:
        result = runner.invoke(ports_command, ["example.com", "--timeout", "2.0"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
