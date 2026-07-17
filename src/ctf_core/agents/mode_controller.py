"""Mode controller for autonomous/interactive mode switching."""

import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Execution modes for the CTF toolkit."""
    AUTONOMOUS = "autonomous"
    INTERACTIVE = "interactive"
    BLOCKED = "blocked"


class BlockedState:
    """Represents a blocked state that requires user intervention."""
    
    def __init__(
        self,
        reason: str,
        requires_input: bool = True,
        suggested_action: Optional[str] = None,
    ):
        self.reason = reason
        self.requires_input = requires_input
        self.suggested_action = suggested_action or "Please provide the required information."
    
    def __repr__(self):
        return f"BlockedState(reason={self.reason!r}, requires_input={self.requires_input})"


class ModeController:
    """
    Manages execution mode switching between autonomous and interactive modes.
    
    The controller detects blocked states (captcha, manual download, human judgment)
    and can automatically switch to interactive mode when user input is required.
    """
    
    # Common blocked state patterns
    BLOCKED_PATTERNS = {
        "captcha": ["captcha", "verify you're human", "recaptcha", "hcaptcha"],
        "manual_download": ["download", "manually", "click to download"],
        "auth_required": ["login required", "authentication required", "unauthorized", "401"],
        "rate_limit": ["rate limit", "too many requests", "429"],
        "human_judgment": ["please confirm", "is this correct", "verify"],
    }
    
    def __init__(self):
        self.current_mode = ExecutionMode.AUTONOMOUS
        self.blocked_state: Optional[BlockedState] = None
        self.mode_history: list[dict] = []
    
    def get_mode(self) -> ExecutionMode:
        """Get the current execution mode."""
        return self.current_mode
    
    def is_autonomous(self) -> bool:
        """Check if running in autonomous mode."""
        return self.current_mode == ExecutionMode.AUTONOMOUS
    
    def is_interactive(self) -> bool:
        """Check if running in interactive mode."""
        return self.current_mode == ExecutionMode.INTERACTIVE
    
    def is_blocked(self) -> bool:
        """Check if the current state is blocked."""
        return self.current_mode == ExecutionMode.BLOCKED
    
    def detect_blocked_state(self, output: str) -> Optional[BlockedState]:
        """
        Detect if the output contains blocked state patterns.
        
        Args:
            output: The output from a tool execution
            
        Returns:
            BlockedState if a blocked pattern is detected, None otherwise
        """
        output_lower = output.lower()
        
        for category, patterns in self.BLOCKED_PATTERNS.items():
            for pattern in patterns:
                if pattern in output_lower:
                    blocked_state = BlockedState(
                        reason=f"Detected {category}: {pattern}",
                        requires_input=True,
                        suggested_action=self._get_suggested_action(category),
                    )
                    self.blocked_state = blocked_state
                    logger.warning(f"Blocked state detected: {category} - {pattern}")
                    return blocked_state
        
        return None
    
    def _get_suggested_action(self, category: str) -> str:
        """Get suggested action based on the blocked category."""
        suggestions = {
            "captcha": "Please solve the captcha and provide the verification code.",
            "manual_download": "Please download the file manually and provide the path.",
            "auth_required": "Please provide valid authentication credentials.",
            "rate_limit": "Please wait before retrying or provide an alternative approach.",
            "human_judgment": "Please review and confirm the next step.",
        }
        return suggestions.get(category, "Please provide the required information.")
    
    def switch_to_interactive(self, reason: Optional[str] = None) -> bool:
        """
        Switch to interactive mode.
        
        Args:
            reason: Optional reason for switching
            
        Returns:
            True if switch was successful
        """
        if self.current_mode == ExecutionMode.INTERACTIVE:
            logger.info("Already in interactive mode")
            return True
        
        old_mode = self.current_mode
        self.current_mode = ExecutionMode.INTERACTIVE
        
        self.mode_history.append({
            "from_mode": old_mode.value,
            "to_mode": self.current_mode.value,
            "reason": reason or "Manual switch to interactive mode",
        })
        
        logger.info(f"Switched from {old_mode.value} to {self.current_mode.value}")
        return True
    
    def switch_to_autonomous(self, reason: Optional[str] = None) -> bool:
        """
        Switch back to autonomous mode.
        
        Args:
            reason: Optional reason for switching
            
        Returns:
            True if switch was successful
        """
        if self.current_mode == ExecutionMode.AUTONOMOUS:
            logger.info("Already in autonomous mode")
            return True
        
        old_mode = self.current_mode
        self.current_mode = ExecutionMode.AUTONOMOUS
        
        self.mode_history.append({
            "from_mode": old_mode.value,
            "to_mode": self.current_mode.value,
            "reason": reason or "Manual switch to autonomous mode",
        })
        
        logger.info(f"Switched from {old_mode.value} to {self.current_mode.value}")
        return True
    
    def clear_blocked_state(self) -> None:
        """Clear the current blocked state."""
        self.blocked_state = None
        logger.info("Cleared blocked state")
    
    def get_status(self) -> dict:
        """Get the current status of the mode controller."""
        return {
            "mode": self.current_mode.value,
            "is_blocked": self.is_blocked(),
            "blocked_state": repr(self.blocked_state) if self.blocked_state else None,
            "mode_history_count": len(self.mode_history),
        }
    
    def get_mode_history(self, limit: int = 10) -> list[dict]:
        """Get recent mode switching history."""
        return self.mode_history[-limit:] if self.mode_history else []
