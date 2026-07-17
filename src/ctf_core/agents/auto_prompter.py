"""Auto-prompter agent for initial input analysis."""

import json
import re
from pathlib import Path
from typing import Optional


class CategorizationMetrics:
    """Track and report categorization accuracy metrics."""
    
    def __init__(self, metrics_file: Optional[str] = None):
        if metrics_file is None:
            metrics_file = "metrics/categorization.json"
        self.metrics_file = Path(metrics_file)
        self.metrics = self._load_metrics()
    
    def _load_metrics(self) -> dict:
        """Load metrics from file or initialize defaults."""
        if self.metrics_file.exists():
            try:
                with open(self.metrics_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {
            "total_predictions": 0,
            "correct_predictions": 0,
            "category_stats": {},
            "confidence_history": [],
        }
    
    def record_prediction(self, predicted_category: str, actual_category: Optional[str], confidence: float):
        """Record a prediction for accuracy tracking."""
        self.metrics["total_predictions"] += 1
        
        if actual_category:
            if predicted_category == actual_category:
                self.metrics["correct_predictions"] += 1
            
            # Track per-category stats
            if actual_category not in self.metrics["category_stats"]:
                self.metrics["category_stats"][actual_category] = {
                    "total": 0,
                    "correct": 0,
                }
            self.metrics["category_stats"][actual_category]["total"] += 1
            if predicted_category == actual_category:
                self.metrics["category_stats"][actual_category]["correct"] += 1
        
        # Track confidence history
        self.metrics["confidence_history"].append({
            "predicted": predicted_category,
            "actual": actual_category,
            "confidence": confidence,
        })
        
        # Keep only last 1000 entries
        if len(self.metrics["confidence_history"]) > 1000:
            self.metrics["confidence_history"] = self.metrics["confidence_history"][-1000:]
        
        self._save_metrics()
    
    def get_accuracy(self) -> dict:
        """Get current accuracy statistics."""
        total = self.metrics["total_predictions"]
        correct = self.metrics["correct_predictions"]
        
        accuracy = {
            "overall_accuracy": correct / total if total > 0 else 0.0,
            "total_predictions": total,
            "correct_predictions": correct,
            "category_accuracy": {},
            "avg_confidence": 0.0,
        }
        
        # Per-category accuracy
        for category, stats in self.metrics["category_stats"].items():
            accuracy["category_accuracy"][category] = {
                "accuracy": stats["correct"] / stats["total"] if stats["total"] > 0 else 0.0,
                "total": stats["total"],
                "correct": stats["correct"],
            }
        
        # Average confidence
        if self.metrics["confidence_history"]:
            accuracy["avg_confidence"] = sum(
                c["confidence"] for c in self.metrics["confidence_history"]
            ) / len(self.metrics["confidence_history"])
        
        return accuracy
    
    def _save_metrics(self):
        """Save metrics to file."""
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.metrics_file, "w") as f:
            json.dump(self.metrics, f, indent=2)


# CTF category patterns
CATEGORY_PATTERNS = {
    "web": [
        r'\bweb\s*(?:challenge|category)?\b',
        r'\b(sqli|sql\s*injection|xss|csrf|ssrf|lfi|rfi|xxe)\b',
        r'\bhttp[s]?://',
        r'\b(login|admin|dashboard)\b.*\bpage\b',
        r'\bwordpress|drupal|joomla\b',
    ],
    "pwn": [
        r'\bpwn\s*(?:challenge|category)?\b',
        r'\bbuffer\s*overflow\b',
        r'\b(binary|executable|elf|pe)\b',
        r'\b(port|listener|nc|netcat)\b',
        r'\b(rop|gadget|shellcode)\b',
    ],
    "re": [
        r'\bre(?:verse)?\s*(?:engineering|challenge)?\b',
        r'\b(binary|executable|disassemble|decompile)\b',
        r'\b(ghidra|ida|radare|r2)\b',
        r'\b(crackme|keygen)\b',
    ],
    "crypto": [
        r'\bcrypto(?:graphy)?\s*(?:challenge)?\b',
        r'\b(encrypt|decrypt|cipher|hash)\b',
        r'\b(rsa|aes|des|ecc)\b',
        r'\b(public\s*key|private\s*key)\b',
    ],
    "forensics": [
        r'\bforensic(?:s)?\s*(?:challenge)?\b',
        r'\b(memory\s*dump|pcap|disk\s*image)\b',
        r'\b(volatility|wireshark|exif)\b',
        r'\b(steganography|steg)\b',
    ],
    "recon": [
        r'\brecon(?:naissance)?\b',
        r'\b(scan|enumerate|discover)\b',
        r'\b(nmap|masscan|subdomain)\b',
        r'\b(target|ip\s*address)\b',
    ],
    "osint": [
        r'\bosint\b',
        r'\b(open\s*source|social\s*media|username)\b',
        r'\b(email|phone|address)\s*(?:lookup|search)\b',
    ],
    "exploitation": [
        r'\bexploit(?:ation)?\b',
        r'\b(metasploit|msf|reverse\s*shell)\b',
        r'\b(privilege\s*escalation|privesc)\b',
        r'\b(root|admin\s*access)\b',
    ],
}


class AutoPrompter:
    """Analyzes user input and identifies CTF category."""
    
    def __init__(self):
        self.compiled_patterns = {}
        for category, patterns in CATEGORY_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
        self.metrics = CategorizationMetrics()
    
    def analyze_input(self, user_input: str) -> dict:
        """
        Analyze user input to identify CTF category and extract key info.
        
        Args:
            user_input: Raw user input describing the challenge
            
        Returns:
            Dictionary with category, confidence, and extracted info
        """
        # Score each category
        scores = {}
        for category, patterns in self.compiled_patterns.items():
            score = 0
            for pattern in patterns:
                if pattern.search(user_input):
                    score += 1
            if score > 0:
                scores[category] = score
        
        # Determine primary category
        if scores:
            primary_category = max(scores, key=lambda k: scores[k])
            confidence = scores[primary_category] / len(self.compiled_patterns[primary_category])
        else:
            primary_category = "unknown"
            confidence = 0.0
        
        # Extract key information
        extracted = {
            "category": primary_category,
            "confidence": confidence,
            "all_scores": scores,
            "challenge_name": self._extract_challenge_name(user_input),
            "target_ip": self._extract_ip(user_input),
            "target_url": self._extract_url(user_input),
            "file_paths": self._extract_file_paths(user_input),
            "suspected_vuln": self._extract_vulnerability(user_input),
        }
        
        return extracted
    
    def _extract_challenge_name(self, text: str) -> Optional[str]:
        """Extract challenge name from quotes or brackets."""
        patterns = [
            r'["\']([^"\']+)["\']',
            r'\[([^\]]+)\]',
            r'called\s+(\w[\w\s-]+?)(?:\s*from|\s*in|\s*\.)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        return match.group(1) if match else None
    
    def _extract_url(self, text: str) -> Optional[str]:
        """Extract URL from text."""
        match = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
        return match.group(0) if match else None
    
    def _extract_file_paths(self, text: str) -> list[str]:
        """Extract file paths from text."""
        patterns = [
            r'(/\w[\w/.-]+)',  # Absolute Unix paths
            r'(\./[\w/.-]+)',   # Relative paths
            r'([\w.-]+\.(bin|elf|exe|pcap|raw|img|mem|dmp))',  # File extensions
        ]
        paths = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            paths.extend([m[0] if isinstance(m, tuple) else m for m in matches])
        return list(set(paths))
    
    def _extract_vulnerability(self, text: str) -> Optional[str]:
        """Extract suspected vulnerability type."""
        vuln_patterns = [
            r'\b(sqli|sql\s*injection)\b',
            r'\b(xss|cross\.?site\.?script)\b',
            r'\b(ssrf|server\.?side\.?request)\b',
            r'\b(lfi|local\s*file\s*inclusion)\b',
            r'\b(rfi|remote\s*file\s*inclusion)\b',
            r'\b(buffer\s*overflow)\b',
            r'\b(command\s*injection)\b',
            r'\b(path\s*traversal)\b',
        ]
        for pattern in vuln_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def generate_questions(self, analysis: dict) -> list[str]:
        """
        Generate clarifying questions for missing information.
        
        Args:
            analysis: Result from analyze_input
            
        Returns:
            List of questions to ask the user
        """
        questions = []
        
        if analysis["category"] == "unknown":
            questions.append("What type of CTF challenge is this? (web, pwn, crypto, forensics, etc.)")
        
        if not analysis["target_ip"] and not analysis["target_url"]:
            if analysis["category"] in ["web", "recon", "exploitation"]:
                questions.append("What is the target IP address or URL?")
        
        if analysis["category"] == "pwn" and not analysis["file_paths"]:
            questions.append("Do you have the binary file? Please provide the path or upload it.")
        
        if analysis["category"] == "forensics" and not analysis["file_paths"]:
            questions.append("What file(s) need to be analyzed? (memory dump, pcap, disk image, etc.)")
        
        return questions
    
    def record_accuracy(self, predicted_category: str, actual_category: Optional[str], confidence: float):
        """Record categorization accuracy for tracking."""
        self.metrics.record_prediction(predicted_category, actual_category, confidence)
    
    def get_metrics(self) -> dict:
        """Get current accuracy metrics."""
        return self.metrics.get_accuracy()
