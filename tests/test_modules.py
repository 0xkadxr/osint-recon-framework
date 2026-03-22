"""Unit tests for OSINT modules."""

import pytest
import json
from pathlib import Path

from osintrecon.core.config import Config
from osintrecon.core.engine import ReconEngine, ReconResult
from osintrecon.core.report import ReportGenerator
from osintrecon.modules.username import UsernameModule
from osintrecon.modules.metadata import MetadataModule
from osintrecon.utils.formatters import truncate, table, format_size


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_values(self):
        cfg = Config()
        assert cfg.timeout == 15
        assert cfg.max_concurrent == 30
        assert cfg.retries == 2
        assert cfg.verbose is False

    def test_custom_values(self):
        cfg = Config(timeout=30, max_concurrent=50, verbose=True)
        assert cfg.timeout == 30
        assert cfg.max_concurrent == 50
        assert cfg.verbose is True

    def test_to_dict(self):
        cfg = Config()
        d = cfg.to_dict()
        assert isinstance(d, dict)
        assert "timeout" in d
        assert "max_concurrent" in d

    def test_save_and_load(self, tmp_path):
        cfg = Config(timeout=42, verbose=True)
        path = tmp_path / "config.json"
        cfg.save(path)
        loaded = Config.load(path)
        assert loaded.timeout == 42
        assert loaded.verbose is True


# ---------------------------------------------------------------------------
# ReconResult tests
# ---------------------------------------------------------------------------

class TestReconResult:
    def test_basic_result(self):
        r = ReconResult(target="test", target_type="username")
        assert r.target == "test"
        assert r.success_count == 0
        assert r.error_count == 0

    def test_to_dict(self):
        r = ReconResult(
            target="example.com",
            target_type="domain",
            findings={"dns": {"A": ["1.2.3.4"]}},
        )
        d = r.to_dict()
        assert d["target"] == "example.com"
        assert "dns" in d["findings"]


# ---------------------------------------------------------------------------
# Username module tests
# ---------------------------------------------------------------------------

class TestUsernameModule:
    def test_load_platforms(self):
        mod = UsernameModule()
        assert len(mod.platforms) > 40  # We have 50+ platforms

    def test_generate_variations(self):
        variations = UsernameModule.generate_variations("johndoe")
        assert "johndoe" in variations
        assert "johndoe123" in variations
        assert "thejohndoe" in variations
        assert len(variations) > 10

    def test_generate_variations_with_underscore(self):
        variations = UsernameModule.generate_variations("john_doe")
        assert "john_doe" in variations
        assert "john-doe" in variations
        assert "john.doe" in variations
        assert "johndoe" in variations

    def test_generate_variations_leet(self):
        variations = UsernameModule.generate_variations("hacker")
        assert "h4ck3r" in variations


# ---------------------------------------------------------------------------
# Metadata module tests
# ---------------------------------------------------------------------------

class TestMetadataModule:
    def test_gps_to_location(self):
        loc = MetadataModule.gps_to_location(48.8566, 2.3522)
        assert "48.856600 N" in loc
        assert "2.352200 E" in loc

    def test_gps_to_location_south_west(self):
        loc = MetadataModule.gps_to_location(-33.8688, -151.2093)
        assert "S" in loc
        assert "W" in loc

    def test_extract_nonexistent_file(self):
        mod = MetadataModule()
        with pytest.raises(FileNotFoundError):
            mod.extract("/nonexistent/file.jpg")


# ---------------------------------------------------------------------------
# Report generator tests
# ---------------------------------------------------------------------------

class TestReportGenerator:
    def _make_result(self) -> ReconResult:
        return ReconResult(
            target="testuser",
            target_type="username",
            modules_run=["username"],
            findings={"platforms": [{"name": "GitHub", "exists": True}]},
            started_at=1000.0,
            finished_at=1002.5,
            duration=2.5,
        )

    def test_json_report(self):
        gen = ReportGenerator(Config())
        text = gen.generate(self._make_result(), "json")
        data = json.loads(text)
        assert data["target"] == "testuser"

    def test_markdown_report(self):
        gen = ReportGenerator(Config())
        text = gen.generate(self._make_result(), "markdown")
        assert "# OSINT Recon Report" in text
        assert "testuser" in text

    def test_html_report(self):
        gen = ReportGenerator(Config())
        text = gen.generate(self._make_result(), "html")
        assert "<!DOCTYPE html>" in text
        assert "testuser" in text

    def test_invalid_format(self):
        gen = ReportGenerator(Config())
        with pytest.raises(ValueError, match="Unknown format"):
            gen.generate(self._make_result(), "xml")


# ---------------------------------------------------------------------------
# Formatter tests
# ---------------------------------------------------------------------------

class TestFormatters:
    def test_truncate(self):
        assert truncate("hello", 10) == "hello"
        assert truncate("hello world this is long", 10) == "hello w..."

    def test_table_empty(self):
        assert table([]) == "(no data)"

    def test_table_renders(self):
        rows = [{"name": "GitHub", "found": True}, {"name": "Reddit", "found": False}]
        result = table(rows)
        assert "GitHub" in result
        assert "Reddit" in result

    def test_format_size(self):
        assert format_size(500) == "500.0 B"
        assert format_size(1024) == "1.0 KB"
        assert format_size(1048576) == "1.0 MB"
