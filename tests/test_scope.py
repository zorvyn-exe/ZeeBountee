from zeebountee.models import ScopeConfig, Target
from zeebountee.scope import ScopeValidator


def test_scope_validator_empty_config() -> None:
    config = ScopeConfig()
    validator = ScopeValidator(config)
    
    assert validator.is_in_scope("example.com")
    assert validator.is_in_scope("https://example.com/test")
    assert validator.is_in_scope(Target(host="192.168.1.1"))

def test_scope_validator_allowed_domains() -> None:
    config = ScopeConfig(allowed_domains=["example.com", "test.com"])
    validator = ScopeValidator(config)
    
    # Exact match
    assert validator.is_in_scope("example.com")
    assert validator.is_in_scope("test.com")
    
    # Subdomain match
    assert validator.is_in_scope("api.example.com")
    assert validator.is_in_scope("sub.api.test.com")
    
    # Protocol parsing
    assert validator.is_in_scope("https://api.example.com/foo")
    
    # Out of scope
    assert not validator.is_in_scope("other.com")
    assert not validator.is_in_scope("notexample.com") # should not match just suffix without dot

def test_scope_validator_blocked_domains() -> None:
    config = ScopeConfig(
        allowed_domains=["example.com"],
        blocked_domains=["admin.example.com"]
    )
    validator = ScopeValidator(config)
    
    assert validator.is_in_scope("example.com")
    assert validator.is_in_scope("api.example.com")
    assert not validator.is_in_scope("admin.example.com")
    assert not validator.is_in_scope("super.admin.example.com")

def test_scope_validator_port_stripping() -> None:
    config = ScopeConfig(allowed_domains=["example.com"])
    validator = ScopeValidator(config)
    
    assert validator.is_in_scope("example.com:8080")
    assert validator.is_in_scope("http://api.example.com:443/")
