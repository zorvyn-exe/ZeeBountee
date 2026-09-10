import pytest
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner
from zeebountee.cli import scan_command
from zeebountee.models import EndpointResult, LivenessResult, ScanReport, Target


@pytest.fixture
def mock_liveness():
    with patch("zeebountee.cli.check_liveness", new_callable=AsyncMock) as m:
        m.return_value = LivenessResult(target="example.com", status_code=200, server="nginx")
        yield m


@pytest.fixture
def mock_ports():
    with patch("zeebountee.cli.run_port_scan", new_callable=AsyncMock) as m:
        m.return_value = []
        yield m


@pytest.fixture
def mock_discovery():
    with patch("zeebountee.cli.run_discovery", new_callable=AsyncMock) as m:
        m.return_value = []
        yield m


@pytest.fixture
def mock_vuln():
    with patch("zeebountee.cli.run_vuln_scan", new_callable=AsyncMock) as m:
        m.return_value = []
        yield m


@pytest.fixture
def mock_web_discovery():
    with patch("zeebountee.cli.run_web_discovery", new_callable=AsyncMock) as m:
        m.return_value = []
        yield m


@pytest.fixture
def mock_scope():
    with patch("zeebountee.cli.ScopeValidator.is_in_scope") as m:
        m.return_value = True
        yield m


def test_cascading_targets_behavior(mock_liveness, mock_ports, mock_discovery, mock_web_discovery, mock_vuln, mock_scope) -> None:
    """Test that discovered endpoints properly cascade to the vulnerability scanner based on specific rules."""
    runner = CliRunner()
    
    # Setup discovery results
    mock_discovery.return_value = [
        EndpointResult(target="example.com", endpoint="api.example.com", status_code=200),
        EndpointResult(target="example.com", endpoint="admin.example.com", status_code=200),
        EndpointResult(target="example.com", endpoint="API.EXAMPLE.COM", status_code=200),  # Duplicate case-insensitive
        EndpointResult(target="example.com", endpoint="outofscope.example.com", status_code=200),
    ]
    
    # Custom scope validator logic
    def scope_check(target: Target) -> bool:
        if target.host == "outofscope.example.com":
            return False
        return True
        
    mock_scope.side_effect = scope_check
    
    # Run the CLI
    result = runner.invoke(scan_command, ["example.com", "--format", "json"])
    
    assert result.exit_code == 0
    
    # vuln_scan should be called exactly 3 times:
    # 1. example.com (original)
    # 2. api.example.com (discovered, in-scope)
    # 3. admin.example.com (discovered, in-scope)
    assert mock_vuln.call_count == 3
    
    called_hosts = [call.args[0].host for call in mock_vuln.call_args_list]
    
    # Original target is always included
    assert "example.com" in called_hosts
    
    # In-scope discovered subdomain is passed
    assert "api.example.com" in called_hosts
    
    # Multiple valid discovered targets are all included
    assert "admin.example.com" in called_hosts
    
    # Duplicate discovered targets are scanned only once (API.EXAMPLE.COM ignored)
    assert "API.EXAMPLE.COM" not in called_hosts
    
    # Out-of-scope discovered subdomain is NOT passed
    assert "outofscope.example.com" not in called_hosts


def test_scan_report_preservation(mock_liveness, mock_ports, mock_discovery, mock_web_discovery, mock_vuln, mock_scope) -> None:
    """Test that the existing ScanReport structure remains intact after cascading targets."""
    runner = CliRunner()
    mock_discovery.return_value = [
        EndpointResult(target="example.com", endpoint="api.example.com", status_code=200)
    ]
    
    with patch("zeebountee.cli.ReportGenerator") as mock_report_gen:
        result = runner.invoke(scan_command, ["example.com", "--format", "json"])
        
        assert result.exit_code == 0
        mock_report_gen_instance = mock_report_gen.return_value
        
        # Verify generate_json was called with a ScanReport object
        assert mock_report_gen_instance.generate_json.call_count == 1
        
        report_arg = mock_report_gen_instance.generate_json.call_args.args[0]
        assert isinstance(report_arg, ScanReport)
        
        # Verify existing ScanReport structure properties are preserved
        assert report_arg.target.host == "example.com"
        assert len(report_arg.subdomains) == 1
        assert report_arg.subdomains[0].endpoint == "api.example.com"

def test_scan_default_output_path(mock_liveness, mock_ports, mock_discovery, mock_web_discovery, mock_vuln, mock_scope) -> None:
    """Test that the default report output location is inside the reports/ directory."""
    runner = CliRunner()
    
    with patch("zeebountee.cli.ReportGenerator") as mock_report_gen, \
         patch("os.path.exists", return_value=False):
        result = runner.invoke(scan_command, ["example.com"])
        
        assert result.exit_code == 0
        mock_report_gen_instance = mock_report_gen.return_value
        
        # Verify generate_html was called with the default reports/ path
        assert mock_report_gen_instance.generate_html.call_count == 1
        output_file_arg = mock_report_gen_instance.generate_html.call_args.args[1]
        assert output_file_arg == "reports/example.com_report.html"

def test_scan_default_output_path_increment(mock_liveness, mock_ports, mock_discovery, mock_web_discovery, mock_vuln, mock_scope) -> None:
    """Test that default report output auto-increments if file exists."""
    runner = CliRunner()
    
    with patch("zeebountee.cli.ReportGenerator") as mock_report_gen, \
         patch("os.path.exists") as mock_exists:
         
        mock_exists.side_effect = lambda x: x in [
            "reports/example.com_report.html",
            "reports/example.com_1_report.html"
        ]
        
        result = runner.invoke(scan_command, ["example.com"])
        
        assert result.exit_code == 0
        mock_report_gen_instance = mock_report_gen.return_value
        
        # Verify generate_html was called with the default reports/ path but incremented
        assert mock_report_gen_instance.generate_html.call_count == 1
        output_file_arg = mock_report_gen_instance.generate_html.call_args.args[1]
        assert output_file_arg == "reports/example.com_2_report.html"

def test_scan_explicit_output_path(mock_liveness, mock_ports, mock_discovery, mock_web_discovery, mock_vuln, mock_scope) -> None:
    """Test that an explicit output path is honored."""
    runner = CliRunner()
    
    with patch("zeebountee.cli.ReportGenerator") as mock_report_gen:
        result = runner.invoke(scan_command, ["example.com", "--output", "custom.html"])
        
        assert result.exit_code == 0
        mock_report_gen_instance = mock_report_gen.return_value
        
        # Verify generate_html was called with the custom path
        assert mock_report_gen_instance.generate_html.call_count == 1
        output_file_arg = mock_report_gen_instance.generate_html.call_args.args[1]
        assert output_file_arg == "custom.html"
