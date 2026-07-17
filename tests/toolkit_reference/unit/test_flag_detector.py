"""Tests for FlagPatternDetector class."""

import pytest
from src.ctf_core.utils.flag_detector import FlagPatternDetector, FlagMatch


class TestFlagPatternDetector:
    """Test the FlagPatternDetector class."""

    def test_initialization(self):
        """Test that FlagPatternDetector initializes correctly."""
        detector = FlagPatternDetector()
        assert detector is not None
        assert len(detector._compiled_patterns) > 0

    def test_detect_ctf_flag(self):
        """Test detection of CTF{} flag."""
        detector = FlagPatternDetector()
        text = "The flag is CTF{this_is_the_flag}"
        matches = detector.detect(text)
        
        assert len(matches) > 0
        assert any("CTF{" in m.flag for m in matches)

    def test_detect_flag_lowercase(self):
        """Test detection of flag{} lowercase."""
        detector = FlagPatternDetector()
        text = "The flag is flag{this_is_the_flag}"
        matches = detector.detect(text)
        
        assert len(matches) > 0
        assert any("flag{" in m.flag for m in matches)

    def test_bare_alphanumeric_not_flagged(self):
        """P0-005: a bare 32-char alphanumeric string is NOT a flag (was noise)."""
        detector = FlagPatternDetector()
        text = "Flag: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        matches = detector.detect(text)
        assert matches == []

    def test_bare_md5_hex_not_flagged(self):
        """P0-005: a bare MD5/hex hash is NOT a flag (was the worst false positive)."""
        detector = FlagPatternDetector()
        text = "Hash: deadbeef1234567890abcdef12345678"
        matches = detector.detect(text)
        assert matches == []

    def test_log_prefixes_not_flagged(self):
        """P0-005: log prefixes like [INFO]/[DATA] and {open}/{tcp} tokens are not flags."""
        detector = FlagPatternDetector()
        text = "[INFO] starting\n[DATA] login: admin\nstatus {open} {tcp}"
        matches = detector.detect(text)
        assert matches == []

    def test_detect_competition_prefixes(self):
        """P0-005: real competition flag formats are detected."""
        detector = FlagPatternDetector()
        cases = ["picoCTF{abc_123}", "HTB{pwned_it}", "THM{room_done}", "DUCTF{down_under}"]
        for expected in cases:
            flags = detector.extract_flags(f"the flag is {expected} ok")
            assert expected in flags, f"{expected} not detected in {flags}"

    def test_detect_multiple_flags(self):
        """Test detection of multiple flags."""
        detector = FlagPatternDetector()
        text = "Flag 1: CTF{first} and Flag 2: CTF{second}"
        matches = detector.detect(text)
        
        assert len(matches) >= 2

    def test_detect_no_flags(self):
        """Test detection when no flags present."""
        detector = FlagPatternDetector()
        text = "This is just normal text without any flags."
        matches = detector.detect(text)
        
        assert len(matches) == 0

    def test_detect_first(self):
        """Test detect_first method."""
        detector = FlagPatternDetector()
        text = "First CTF{flag1} then CTF{flag2}"
        first = detector.detect_first(text)
        
        assert first is not None
        assert "CTF{" in first.flag

    def test_detect_first_no_match(self):
        """Test detect_first with no matches."""
        detector = FlagPatternDetector()
        text = "No flags here"
        first = detector.detect_first(text)
        
        assert first is None

    def test_has_flags(self):
        """Test has_flags method."""
        detector = FlagPatternDetector()
        assert detector.has_flags("CTF{flag}") is True
        assert detector.has_flags("No flags") is False

    def test_extract_flags(self):
        """Test extract_flags method."""
        detector = FlagPatternDetector()
        text = "The flag is CTF{secret_flag}"
        flags = detector.extract_flags(text)
        
        assert len(flags) > 0
        assert "CTF{secret_flag}" in flags

    def test_format_matches(self):
        """Test format_matches method."""
        detector = FlagPatternDetector()
        detector.detect("Flag: CTF{test_flag}")
        
        formatted = detector.format_matches()
        assert "CTF{" in formatted
        assert "flag" in formatted.lower()

    def test_format_matches_empty(self):
        """Test format_matches with no matches."""
        detector = FlagPatternDetector()
        formatted = detector.format_matches([])
        
        assert "No flags found" in formatted

    def test_get_last_matches(self):
        """Test get_last_matches method."""
        detector = FlagPatternDetector()
        text = "Flag: CTF{test}"
        detector.detect(text)
        
        last = detector.get_last_matches()
        assert len(last) > 0

    def test_add_custom_pattern(self):
        """Test adding custom pattern."""
        detector = FlagPatternDetector()
        initial_count = len(detector._compiled_patterns)
        
        detector.add_pattern(r"MYFLAG\{[^}]+\}", "myflag")
        
        assert len(detector._compiled_patterns) == initial_count + 1

    def test_custom_pattern_detection(self):
        """Test detection with custom pattern."""
        detector = FlagPatternDetector()
        detector.add_pattern(r"MYFLAG\{[^}]+\}", "myflag")
        
        text = "Flag: MYFLAG{custom_flag}"
        matches = detector.detect(text)
        
        assert any("MYFLAG{" in m.flag for m in matches)

    def test_position_tracking(self):
        """Test that positions are tracked correctly."""
        detector = FlagPatternDetector()
        text = "First CTF{word1} then CTF{word2}"
        matches = detector.detect(text)
        
        # May have more than 2 matches due to curly_braces pattern also matching
        assert len(matches) >= 2
        # First flag should come before second (CTF{} pattern)
        ctf_matches = [m for m in matches if m.pattern == "CTF{}"]
        assert len(ctf_matches) >= 2
        assert ctf_matches[0].position < ctf_matches[1].position

    def test_duplicates_removed(self):
        """Test that duplicate flags are removed."""
        detector = FlagPatternDetector()
        text = "CTF{flag} appears twice CTF{flag}"
        matches = detector.detect(text)
        
        # Should only have one match (duplicates removed)
        flags = [m.flag for m in matches]
        assert flags.count("CTF{flag}") == 1

    def test_repr(self):
        """Test __repr__ method."""
        detector = FlagPatternDetector()
        repr_str = repr(detector)
        
        assert "FlagPatternDetector" in repr_str
        assert "patterns=" in repr_str
