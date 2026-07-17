"""Tests for ModeController class."""

import pytest
from src.ctf_core.agents.mode_controller import (
    ModeController,
    ExecutionMode,
    BlockedState,
)


class TestModeController:
    """Test the ModeController class."""

    def test_initial_mode(self):
        """Test that initial mode is autonomous."""
        controller = ModeController()
        assert controller.get_mode() == ExecutionMode.AUTONOMOUS
        assert controller.is_autonomous() is True
        assert controller.is_interactive() is False
        assert controller.is_blocked() is False

    def test_switch_to_interactive(self):
        """Test switching to interactive mode."""
        controller = ModeController()
        result = controller.switch_to_interactive("test reason")
        
        assert result is True
        assert controller.get_mode() == ExecutionMode.INTERACTIVE
        assert controller.is_interactive() is True

    def test_switch_to_autonomous(self):
        """Test switching back to autonomous mode."""
        controller = ModeController()
        controller.switch_to_interactive()
        result = controller.switch_to_autonomous()
        
        assert result is True
        assert controller.get_mode() == ExecutionMode.AUTONOMOUS
        assert controller.is_autonomous() is True

    def test_already_in_interactive(self):
        """Test that switching to interactive when already in interactive returns True."""
        controller = ModeController()
        controller.switch_to_interactive()
        result = controller.switch_to_interactive()
        
        assert result is True

    def test_detect_captcha(self):
        """Test detection of captcha pattern."""
        controller = ModeController()
        output = "Please complete the captcha to continue"
        
        blocked = controller.detect_blocked_state(output)
        
        assert blocked is not None
        assert blocked.reason.startswith("Detected captcha")
        assert blocked.requires_input is True

    def test_detect_manual_download(self):
        """Test detection of manual download pattern."""
        controller = ModeController()
        output = "Please download the file manually from the website"
        
        blocked = controller.detect_blocked_state(output)
        
        assert blocked is not None
        assert blocked.reason.startswith("Detected manual_download")

    def test_detect_auth_required(self):
        """Test detection of authentication required pattern."""
        controller = ModeController()
        output = "Error 401: Login required to access this resource"
        
        blocked = controller.detect_blocked_state(output)
        
        assert blocked is not None
        assert blocked.reason.startswith("Detected auth_required")

    def test_detect_rate_limit(self):
        """Test detection of rate limit pattern."""
        controller = ModeController()
        output = "Error 429: Rate limit exceeded. Please try again later."
        
        blocked = controller.detect_blocked_state(output)
        
        assert blocked is not None
        assert blocked.reason.startswith("Detected rate_limit")

    def test_detect_human_judgment(self):
        """Test detection of human judgment pattern."""
        controller = ModeController()
        output = "Is this the correct exploit? Please confirm to proceed."
        
        blocked = controller.detect_blocked_state(output)
        
        assert blocked is not None
        assert blocked.reason.startswith("Detected human_judgment")

    def test_no_blocked_state(self):
        """Test that no blocked state is detected in normal output."""
        controller = ModeController()
        output = "Scan completed successfully. Found 5 open ports."
        
        blocked = controller.detect_blocked_state(output)
        
        assert blocked is None

    def test_clear_blocked_state(self):
        """Test clearing blocked state."""
        controller = ModeController()
        controller.detect_blocked_state("Please complete the captcha")
        
        assert controller.blocked_state is not None
        
        controller.clear_blocked_state()
        
        assert controller.blocked_state is None

    def test_get_status(self):
        """Test getting status."""
        controller = ModeController()
        status = controller.get_status()
        
        assert status["mode"] == "autonomous"
        assert status["is_blocked"] is False
        assert status["blocked_state"] is None

    def test_mode_history(self):
        """Test mode switching history."""
        controller = ModeController()
        
        controller.switch_to_interactive("test 1")
        controller.switch_to_autonomous("test 2")
        
        history = controller.get_mode_history()
        
        assert len(history) == 2
        assert history[0]["from_mode"] == "autonomous"
        assert history[0]["to_mode"] == "interactive"
        assert history[1]["from_mode"] == "interactive"
        assert history[1]["to_mode"] == "autonomous"


class TestBlockedState:
    """Test the BlockedState class."""

    def test_blocked_state_creation(self):
        """Test creating a BlockedState."""
        state = BlockedState(
            reason="Test reason",
            requires_input=True,
            suggested_action="Test action",
        )
        
        assert state.reason == "Test reason"
        assert state.requires_input is True
        assert state.suggested_action == "Test action"

    def test_blocked_state_default_suggestion(self):
        """Test default suggested action."""
        state = BlockedState(reason="Test reason")
        
        assert state.suggested_action == "Please provide the required information."
