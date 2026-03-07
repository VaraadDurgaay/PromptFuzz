"""Tests for the Fuzzer orchestrator."""

from __future__ import annotations

import os

import pytest
import yaml

from promptfuzz.analyzer import AnalysisResult, DetectionStrategy, Vulnerability
from promptfuzz.attacks.loader import Attack, DetectionConfig
from promptfuzz.fuzzer import Fuzzer, FuzzResult


def _dummy_callable(message: str) -> str:
    """A simple callable target for testing."""
    return f"I cannot help with that: {message}"


def _make_attack(severity: str = "high") -> Attack:
    """Build a minimal Attack for use in fuzzer tests."""
    return Attack(
        id="JB-001",
        name="Test Jailbreak",
        category="jailbreak",
        severity=severity,
        description="Test.",
        prompt="Test prompt",
        detection=DetectionConfig(
            method="refusal",
            indicators=["I cannot"],
            success_if="refusal_absent",
        ),
        tags=["test"],
        remediation="Harden prompt.",
    )


def _make_vulnerability(severity: str = "high") -> Vulnerability:
    """Build a minimal Vulnerability for score tests."""
    attack = _make_attack(severity=severity)
    result = AnalysisResult(
        attack=attack,
        response="Sure, I'll help!",
        is_vulnerable=True,
        confidence=0.9,
        evidence="No refusal found.",
        strategy_used=DetectionStrategy.REFUSAL,
        elapsed_ms=10.0,
    )
    return Vulnerability(attack=attack, result=result)


class TestFuzzerInit:
    """Tests for Fuzzer initialisation."""

    def test_fuzzer_init_with_callable(self) -> None:
        """Fuzzer accepts a callable target."""
        fuzzer = Fuzzer(target=_dummy_callable, context="test bot")
        assert callable(fuzzer.target)
        assert fuzzer.context == "test bot"

    def test_fuzzer_init_with_url(self) -> None:
        """Fuzzer accepts a URL string target."""
        fuzzer = Fuzzer(target="https://api.example.com/chat")
        assert fuzzer.target == "https://api.example.com/chat"

    def test_fuzzer_defaults(self) -> None:
        """Fuzzer has correct default values."""
        fuzzer = Fuzzer(target=_dummy_callable)
        assert fuzzer.max_workers == 5
        assert fuzzer.timeout == 30.0
        assert fuzzer.verbose is False
        assert fuzzer.categories is None
        assert fuzzer.headers == {}


class TestFuzzerFromConfig:
    """Tests for Fuzzer.from_config classmethod."""

    def test_fuzzer_from_config(self, tmp_path: os.PathLike) -> None:
        """Fuzzer.from_config correctly parses a valid YAML file."""
        config = {
            "target": "https://api.example.com/chat",
            "context": "support bot",
            "categories": ["jailbreak"],
            "max_workers": 3,
            "timeout": 20,
        }
        config_path = str(tmp_path / "promptfuzz.yaml")
        with open(config_path, "w") as f:
            yaml.dump(config, f)

        fuzzer = Fuzzer.from_config(config_path)
        assert fuzzer.target == "https://api.example.com/chat"
        assert fuzzer.context == "support bot"
        assert fuzzer.categories == ["jailbreak"]
        assert fuzzer.max_workers == 3
        assert fuzzer.timeout == 20

    def test_fuzzer_from_config_missing_file(self) -> None:
        """Fuzzer.from_config raises FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            Fuzzer.from_config("/nonexistent/path/config.yaml")

    def test_fuzzer_from_config_missing_target(
        self, tmp_path: os.PathLike
    ) -> None:
        """Fuzzer.from_config raises ValueError when target is absent."""
        config_path = str(tmp_path / "bad.yaml")
        with open(config_path, "w") as f:
            yaml.dump({"context": "test"}, f)
        with pytest.raises(ValueError, match="target"):
            Fuzzer.from_config(config_path)


class TestFuzzResultScore:
    """Tests for FuzzResult score calculation."""

    def test_fuzz_result_score_calculation(self) -> None:
        """Score deducts correct weights per severity."""
        vulns = [
            _make_vulnerability("critical"),  # -25
            _make_vulnerability("high"),      # -10
            _make_vulnerability("medium"),    # -5
            _make_vulnerability("low"),       # -2
        ]
        score = Fuzzer._compute_score(vulns)
        expected = max(0, 100 - 25 - 10 - 5 - 2)
        assert score == expected

    def test_score_clamps_at_zero(self) -> None:
        """Score never goes below 0."""
        vulns = [_make_vulnerability("critical")] * 10
        score = Fuzzer._compute_score(vulns)
        assert score == 0

    def test_score_is_100_with_no_vulns(self) -> None:
        """Score is 100 when there are no vulnerabilities."""
        score = Fuzzer._compute_score([])
        assert score == 100


class TestFuzzResultReport:
    """Tests for FuzzResult output methods."""

    def test_fuzz_result_report_does_not_raise(self) -> None:
        """FuzzResult.report() runs without raising exceptions."""
        result = FuzzResult(
            target_description="test",
            context="test context",
            attacks_run=5,
            vulnerabilities=[],
            passed=[],
            errors=[],
            score=100,
            duration_seconds=0.5,
            timestamp="2026-03-07T00:00:00+00:00",
        )
        result.report()

    async def test_fuzzer_arun_with_callable(self) -> None:
        """Fuzzer.arun completes successfully with a callable target."""
        fuzzer = Fuzzer(
            target=_dummy_callable,
            categories=["edge_case"],
            max_workers=2,
            timeout=5.0,
        )
        result = await fuzzer.arun()
        assert isinstance(result, FuzzResult)
        assert result.attacks_run > 0
        assert isinstance(result.score, int)
        assert 0 <= result.score <= 100
