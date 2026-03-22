"""Unit tests for osintrecon.utils.validators."""

import pytest
from osintrecon.utils.validators import (
    is_valid_email,
    is_valid_domain,
    is_valid_ip,
    is_valid_username,
    is_valid_url,
    sanitize_input,
)


class TestIsValidEmail:
    def test_valid_emails(self):
        assert is_valid_email("user@example.com")
        assert is_valid_email("first.last@domain.org")
        assert is_valid_email("user+tag@sub.domain.co.uk")
        assert is_valid_email("test123@test.io")

    def test_invalid_emails(self):
        assert not is_valid_email("")
        assert not is_valid_email("notanemail")
        assert not is_valid_email("@domain.com")
        assert not is_valid_email("user@")
        assert not is_valid_email("user@.com")
        assert not is_valid_email("user@domain")
        assert not is_valid_email("user @domain.com")


class TestIsValidDomain:
    def test_valid_domains(self):
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.domain.org")
        assert is_valid_domain("my-site.co.uk")
        assert is_valid_domain("test123.io")

    def test_invalid_domains(self):
        assert not is_valid_domain("")
        assert not is_valid_domain("a" * 254)
        assert not is_valid_domain("-invalid.com")
        assert not is_valid_domain("invalid-.com")
        assert not is_valid_domain(".com")
        assert not is_valid_domain("just_a_word")


class TestIsValidIp:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("8.8.8.8")
        assert is_valid_ip("127.0.0.1")
        assert is_valid_ip("255.255.255.255")

    def test_valid_ipv6(self):
        assert is_valid_ip("::1")
        assert is_valid_ip("2001:db8::1")
        assert is_valid_ip("fe80::1")

    def test_invalid_ips(self):
        assert not is_valid_ip("")
        assert not is_valid_ip("999.999.999.999")
        assert not is_valid_ip("not.an.ip")
        assert not is_valid_ip("192.168.1")


class TestIsValidUsername:
    def test_valid_usernames(self):
        assert is_valid_username("johndoe")
        assert is_valid_username("john_doe")
        assert is_valid_username("john-doe")
        assert is_valid_username("john.doe")
        assert is_valid_username("user123")
        assert is_valid_username("abc")

    def test_invalid_usernames(self):
        assert not is_valid_username("")
        assert not is_valid_username("ab")  # too short
        assert not is_valid_username("a" * 40)  # too long
        assert not is_valid_username("user name")  # spaces
        assert not is_valid_username("user@name")  # special chars


class TestIsValidUrl:
    def test_valid_urls(self):
        assert is_valid_url("https://example.com")
        assert is_valid_url("http://test.org/path")
        assert is_valid_url("https://sub.domain.co.uk/page?q=1")

    def test_invalid_urls(self):
        assert not is_valid_url("")
        assert not is_valid_url("ftp://example.com")
        assert not is_valid_url("example.com")
        assert not is_valid_url("not a url")


class TestSanitizeInput:
    def test_removes_dangerous_chars(self):
        assert sanitize_input("test;rm -rf /") == "testrm -rf /"
        assert sanitize_input("test|cat /etc/passwd") == "testcat /etc/passwd"
        assert sanitize_input("test`whoami`") == "testwhoami"

    def test_preserves_safe_input(self):
        assert sanitize_input("johndoe") == "johndoe"
        assert sanitize_input("user@example.com") == "user@example.com"
        assert sanitize_input("  spaces  ") == "spaces"
