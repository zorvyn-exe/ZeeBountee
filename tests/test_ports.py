import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from click.testing import CliRunner

@pytest.fixture
def anyio_backend():
    return "asyncio"

from zeebountee.models import PortResult, Target
from zeebountee.modules.ports import (
    COMMON_PORTS,
    ports_command,
    run_port_scan,
    scan_port,
)


@pytest.mark.anyio
@patch("zeebountee.modules.ports.asyncio.open_connection")
async def test_scan_port_open(mock_open: Mock) -> None:
    """Test that scan_port returns PortResult when a connection is successfully established and responds."""
    mock_reader = Mock()
    mock_reader.at_eof.return_value = False
    mock_writer = Mock()
    mock_writer.wait_closed = AsyncMock()
    
    async def dummy_open_connection(*args, **kwargs):
        return (mock_reader, mock_writer)
    
    mock_open.side_effect = dummy_open_connection
    
    sem = asyncio.Semaphore(1)
    result = await scan_port("example.com", 80, 1.0, sem)
    
    assert result is not None
    assert result.port == 80
    assert result.service == "HTTP"
    assert result.state == "OPEN"
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@pytest.mark.anyio
@patch("zeebountee.modules.ports.asyncio.open_connection")
async def test_scan_port_closed(mock_open: Mock) -> None:
    """Test that scan_port returns None when a connection is refused."""
    async def dummy_open_connection_fail(*args, **kwargs):
        raise ConnectionRefusedError()
        
    mock_open.side_effect = dummy_open_connection_fail
    
    sem = asyncio.Semaphore(1)
    result = await scan_port("example.com", 80, 1.0, sem)
    
    assert result is None

@pytest.mark.anyio
@patch("zeebountee.modules.ports.asyncio.open_connection")
async def test_scan_port_false_positive_proxy(mock_open: Mock) -> None:
    """Test that scan_port handles immediate EOF gracefully (proxy fast drops)."""
    mock_reader = Mock()
    mock_reader.at_eof.return_value = True
    mock_writer = Mock()
    mock_writer.wait_closed = AsyncMock()
    
    async def dummy_open_connection(*args, **kwargs):
        return (mock_reader, mock_writer)
    
    mock_open.side_effect = dummy_open_connection
    
    sem = asyncio.Semaphore(1)
    result = await scan_port("example.com", 80, 1.0, sem)
    
    assert result is None
    mock_writer.close.assert_called_once()

@pytest.mark.anyio
@patch("zeebountee.modules.ports.asyncio.open_connection")
async def test_scan_port_reset(mock_open: Mock) -> None:
    """Test that scan_port handles connection reset after handshake."""
    mock_reader = Mock()
    # Mock at_eof to raise an OSError simulating a connection reset when checked
    mock_reader.at_eof.side_effect = OSError("Connection reset by peer")
    mock_writer = Mock()
    mock_writer.wait_closed = AsyncMock()
    
    async def dummy_open_connection(*args, **kwargs):
        return (mock_reader, mock_writer)
    
    mock_open.side_effect = dummy_open_connection
    
    sem = asyncio.Semaphore(1)
    result = await scan_port("example.com", 80, 1.0, sem)
    
    assert result is None
    mock_writer.close.assert_called_once()

@pytest.mark.anyio
async def test_run_port_scan() -> None:
    """Test the orchestration of scanning all common ports concurrently."""
    with patch("zeebountee.modules.ports.scan_port", new_callable=AsyncMock) as mock_scan:
        def side_effect(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult | None:
            if port == 80:
                return PortResult(target=host, port=port, service="HTTP", state="OPEN")
            return None
            
        mock_scan.side_effect = side_effect
        
        target = Target(host="example.com")
        results = await run_port_scan(target, 1.0)
        assert mock_scan.call_count == len(COMMON_PORTS)
        assert len(results) == 1
        assert results[0].port == 80

def test_ports_cli_command() -> None:
    """Test the synchronous Click CLI wrapper for the ports command."""
    runner = CliRunner()
    def mock_run_fn(coro):
        coro.close()
        return []
        
    with patch("zeebountee.modules.ports.asyncio.run", side_effect=mock_run_fn) as mock_run:
        result = runner.invoke(ports_command, ["example.com", "--timeout", "2.0"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
