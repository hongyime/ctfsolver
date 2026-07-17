"""Flag pattern detector for automatic CTF flag capture."""

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FlagMatch:
    """Represents a flag match found in text."""
    flag: str
    pattern: str
    position: int


class FlagPatternDetector:
    """
    Detects CTF flags in text output after tool execution.
    
    Supports reliable CTF flag formats only. Bare hash / {word} / [word]
    patterns were removed (P0-005) because they matched every MD5 and log
    prefix and polluted the flags table:
    - flag{...}, CTF{...}, picoCTF{...}, HTB{...}, THM{...}, DUCTF{...}
    - UUID
    """
    
    # Common CTF flag patterns
    # Reliable CTF flag patterns only (P0-005). re.IGNORECASE is applied at
    # compile time, so case variants (FLAG{}, Flag{}, ctf{}) collapse into these.
    DEFAULT_PATTERNS = [
        (r"flag\{[^}]+\}", "flag{}"),
        (r"CTF\{[^}]+\}", "CTF{}"),
        (r"picoCTF\{[^}]+\}", "picoCTF{}"),
        (r"HTB\{[^}]+\}", "HTB{}"),
        (r"THM\{[^}]+\}", "THM{}"),
        (r"DUCTF\{[^}]+\}", "DUCTF{}"),
        # UUID (specific structure, low false-positive risk)
        (r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}", "uuid"),
    ]
    
    def __init__(self, custom_patterns: Optional[list[tuple[str, str]]] = None):
        """
        Initialize the flag detector.
        
        Args:
            custom_patterns: Optional list of (regex_pattern, name) tuples for custom patterns
        """
        self.patterns = list(self.DEFAULT_PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Compile regex patterns for efficiency
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), name)
            for pattern, name in self.patterns
        ]
        
        self._last_matches: list[FlagMatch] = []
    
    def detect(self, text: str) -> list[FlagMatch]:
        """
        Detect flag patterns in the given text.
        
        Args:
            text: Text to search for flags
            
        Returns:
            List of FlagMatch objects
        """
        matches = []
        
        for pattern, name in self._compiled_patterns:
            for match in pattern.finditer(text):
                flag_match = FlagMatch(
                    flag=match.group(),
                    pattern=name,
                    position=match.start()
                )
                matches.append(flag_match)
        
        # Remove duplicates based on flag content
        seen = set()
        unique_matches = []
        for match in matches:
            if match.flag not in seen:
                seen.add(match.flag)
                unique_matches.append(match)
        
        # Sort by position, then prefer longer matches first when overlaps start together
        unique_matches.sort(key=lambda x: (x.position, -len(x.flag)))
        
        # Filter out nested/overlapping matches - keep longer matches
        filtered_matches = []
        for match in unique_matches:
            is_nested = False
            for existing in filtered_matches:
                existing_end = existing.position + len(existing.flag)
                match_end = match.position + len(match.flag)
                if existing.position <= match.position and existing_end >= match_end:
                    is_nested = True
                    break
            if not is_nested:
                filtered_matches.append(match)
        
        self._last_matches = filtered_matches
        return filtered_matches
    
    def detect_first(self, text: str) -> Optional[FlagMatch]:
        """
        Detect the first flag pattern in the given text.
        
        Args:
            text: Text to search for flags
            
        Returns:
            First FlagMatch object, or None if no flags found
        """
        matches = self.detect(text)
        return matches[0] if matches else None
    
    def has_flags(self, text: str) -> bool:
        """
        Check if the text contains any flag patterns.
        
        Args:
            text: Text to check
            
        Returns:
            True if flags are found, False otherwise
        """
        return len(self.detect(text)) > 0
    
    def extract_flags(self, text: str) -> list[str]:
        """
        Extract just the flag strings from the text.
        
        Args:
            text: Text to search for flags
            
        Returns:
            List of flag strings
        """
        return [match.flag for match in self.detect(text)]
    
    def get_last_matches(self) -> list[FlagMatch]:
        """
        Get the flags found in the last detect() call.
        
        Returns:
            List of FlagMatch objects from last detection
        """
        return self._last_matches
    
    def format_matches(self, matches: Optional[list[FlagMatch]] = None) -> str:
        """
        Format flag matches as a readable string.
        
        Args:
            matches: List of FlagMatch objects. If None, uses last matches.
            
        Returns:
            Formatted string of flag matches
        """
        if matches is None:
            matches = self._last_matches
        
        if not matches:
            return "No flags found."
        
        lines = [f"Found {len(matches)} flag(s):"]
        for i, match in enumerate(matches, 1):
            lines.append(f"  {i}. {match.flag} (pattern: {match.pattern})")
        
        return "\n".join(lines)
    
    def add_pattern(self, pattern: str, name: str) -> None:
        """
        Add a custom flag pattern.
        
        Args:
            pattern: Regex pattern for the flag
            name: Name/description of the pattern
        """
        compiled = re.compile(pattern, re.IGNORECASE)
        self._compiled_patterns.append((compiled, name))
        self.patterns.append((pattern, name))
        logger.info(f"Added custom flag pattern: {name}")
    
    def __repr__(self):
        return f"FlagPatternDetector(patterns={len(self._compiled_patterns)})"
