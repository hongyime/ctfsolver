"""Planner agent for strategy and task delegation."""

from typing import Any, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class PathScore:
    """Score for an attack path."""
    path: dict
    score: float = 0.0
    factors: dict = field(default_factory=dict)


class Planner:
    """Maintains global state and decides strategy using scoring-based selection."""
    
    # Scoring weights for decision factors
    WEIGHTS = {
        "data_quality": 0.30,      # How much existing data supports this path
        "effort": 0.20,            # Time/resource efficiency
        "success_probability": 0.25,  # Likelihood of success based on indicators
        "impact": 0.15,            # Potential value of findings
        "dependencies": 0.10,      # Prerequisite completion
    }
    
    def __init__(self, db=None):
        self.current_state = {}
        self.decision_history = []
        self.executed_tasks = set()
        self.db = db
    
    async def analyze_state(
        self,
        challenge_info: dict,
        existing_data: dict,
    ) -> dict:
        """
        Analyze current state and decide on strategy using scoring framework.
        
        Args:
            challenge_info: Information from Auto-prompter
            existing_data: Data from database about the target
            
        Returns:
            Strategy decision with next steps
        """
        category = challenge_info.get("category", "unknown")
        
        # Build current understanding
        understanding = self._build_understanding(challenge_info, existing_data)
        
        # Identify possible paths based on category
        possible_paths = self._get_possible_paths(category, existing_data)
        
        # Score and select most promising path
        selected_path = self._select_path_scored(possible_paths, existing_data, challenge_info)
        
        # Justify choice
        justification = self._justify_selection(selected_path, existing_data, challenge_info)
        
        decision = {
            "understanding": understanding,
            "possible_paths": possible_paths,
            "selected_path": selected_path,
            "justification": justification,
            "next_tasks": selected_path.get("tasks", []),
        }
        
        self.decision_history.append(decision)

        if self.db is not None:
            try:
                await self.db.log_decision(
                    decision_path=category,
                    reasoning=justification,
                    confidence_scores=selected_path.get("scoring"),
                    selected_action=selected_path.get("name"),
                )
            except Exception as e:
                logger.warning(f"Failed to log planner decision: {e}")

        return decision
    
    def _build_understanding(
        self,
        challenge_info: dict,
        existing_data: dict,
    ) -> str:
        """Build current understanding of the challenge."""
        parts = []
        
        category = challenge_info.get("category", "unknown")
        parts.append(f"Challenge category: {category}")
        
        if challenge_info.get("challenge_name"):
            parts.append(f"Challenge name: {challenge_info['challenge_name']}")
        
        if challenge_info.get("target_ip"):
            parts.append(f"Target IP: {challenge_info['target_ip']}")
        
        if challenge_info.get("target_url"):
            parts.append(f"Target URL: {challenge_info['target_url']}")
        
        if challenge_info.get("suspected_vuln"):
            parts.append(f"Suspected vulnerability: {challenge_info['suspected_vuln']}")
        
        # Add existing data summary
        services = existing_data.get("services", [])
        if services:
            parts.append(f"Known services: {len(services)}")
        
        creds = existing_data.get("credentials", [])
        if creds:
            parts.append(f"Known credentials: {len(creds)}")
        
        return "\n".join(parts)
    
    def _get_possible_paths(
        self,
        category: str,
        existing_data: dict,
    ) -> list[dict]:
        """Get possible attack paths based on category."""
        paths = {
            "web": [
                {
                    "name": "Web Enumeration",
                    "description": "Discover web directories, technologies, and endpoints",
                    "tasks": [
                        {"tool": "feroxbuster", "target": "url", "args": ["-u", "{target_url}"]},
                        {"tool": "whatweb", "target": "url", "args": ["{target_url}"]},
                    ],
                },
                {
                    "name": "SQL Injection Testing",
                    "description": "Test for SQL injection vulnerabilities",
                    "tasks": [
                        {"tool": "sqlmap", "target": "url", "args": ["-u", "{target_url}", "--batch", "--dbs"]},
                    ],
                },
            ],
            "recon": [
                {
                    "name": "Network Scanning",
                    "description": "Scan target for open ports and services",
                    "tasks": [
                        {"tool": "nmap", "target": "ip", "args": ["-sV", "-sC", "-oX", "/workspace/nmap.xml", "{target_ip}"]},
                    ],
                },
                {
                    "name": "Subdomain Enumeration",
                    "description": "Discover subdomains for the target",
                    "tasks": [
                        {"tool": "amass", "target": "domain", "args": ["enum", "-d", "{domain}"]},
                    ],
                },
            ],
            "pwn": [
                {
                    "name": "Binary Analysis",
                    "description": "Analyze binary for vulnerabilities",
                    "tasks": [
                        {"tool": "checksec", "target": "file", "args": ["--file", "{file_path}"]},
                        {"tool": "strings", "target": "file", "args": ["{file_path}"]},
                    ],
                },
            ],
            "forensics": [
                {
                    "name": "File Analysis",
                    "description": "Analyze forensic artifacts",
                    "tasks": [
                        {"tool": "exiftool", "target": "file", "args": ["{file_path}"]},
                    ],
                },
            ],
            "crypto": [
                {
                    "name": "Cipher Analysis",
                    "description": "Identify and analyze encryption",
                    "tasks": [
                        {"tool": "openssl", "target": "file", "args": ["enc", "-d", "-in", "{file_path}"]},
                    ],
                },
            ],
        }
        
        return paths.get(category, [
            {"name": "General Reconnaissance", "description": "Gather initial information", "tasks": []}
        ])
    
    def _select_path_scored(
        self,
        possible_paths: list[dict],
        existing_data: dict,
        challenge_info: dict,
    ) -> dict:
        """Select the most promising attack path using weighted scoring."""
        if not possible_paths:
            return {"name": "No path selected", "tasks": []}
        
        scored_paths = []
        
        for path in possible_paths:
            # Calculate individual factor scores (0.0 to 1.0)
            data_quality = self._score_data_quality(path, existing_data)
            effort = self._score_effort(path)
            success_prob = self._score_success_probability(path, challenge_info, existing_data)
            impact = self._score_impact(path)
            dependencies = self._score_dependencies(path)
            
            # Calculate weighted total score
            total_score = (
                data_quality * self.WEIGHTS["data_quality"] +
                effort * self.WEIGHTS["effort"] +
                success_prob * self.WEIGHTS["success_probability"] +
                impact * self.WEIGHTS["impact"] +
                dependencies * self.WEIGHTS["dependencies"]
            )
            
            scored_paths.append(PathScore(
                path=path,
                score=total_score,
                factors={
                    "data_quality": data_quality,
                    "effort": effort,
                    "success_probability": success_prob,
                    "impact": impact,
                    "dependencies": dependencies,
                }
            ))
        
        # Select path with highest score
        best_path = max(scored_paths, key=lambda x: x.score)
        
        # Store scoring details for justification
        best_path.path["scoring"] = best_path.factors
        best_path.path["total_score"] = best_path.score
        
        return best_path.path
    
    def _score_data_quality(self, path: dict, existing_data: dict) -> float:
        """Score based on existing data quality (0.0-1.0)."""
        score = 0.5  # Base score
        
        services = existing_data.get("services", [])
        credentials = existing_data.get("credentials", [])
        targets = existing_data.get("targets", [])
        
        # More existing data = higher score
        if services:
            score += 0.2
        if credentials:
            score += 0.15
        if targets:
            score += 0.1
        
        # Path-specific data relevance
        path_name = path.get("name", "").lower()
        if "sql" in path_name and any(s.get("service_name", "").lower() in ["mysql", "postgresql", "mssql"] for s in services):
            score += 0.15
        if "web" in path_name and any(s.get("port") in [80, 443, 8080, 8443] for s in services):
            score += 0.1
        
        return min(score, 1.0)
    
    def _score_effort(self, path: dict) -> float:
        """Score based on effort required (lower effort = higher score)."""
        tasks = path.get("tasks", [])
        
        if not tasks:
            return 0.3  # Low score for no tasks
        
        # Fewer tasks = less effort = higher score
        task_count = len(tasks)
        if task_count <= 1:
            return 0.9
        elif task_count <= 2:
            return 0.7
        elif task_count <= 3:
            return 0.5
        else:
            return 0.3
    
    def _score_success_probability(
        self, 
        path: dict, 
        challenge_info: dict, 
        existing_data: dict,
    ) -> float:
        """Score based on probability of success (0.0-1.0)."""
        score = 0.5  # Base score
        
        suspected_vuln = challenge_info.get("suspected_vuln", "").lower()
        path_name = path.get("name", "").lower()
        
        # Match path to suspected vulnerability
        if suspected_vuln:
            if "sql" in suspected_vuln and "sql" in path_name:
                score += 0.3
            elif "xss" in suspected_vuln and "xss" in path_name:
                score += 0.3
            elif "buffer" in suspected_vuln and "binary" in path_name:
                score += 0.3
            elif "overflow" in suspected_vuln and "binary" in path_name:
                score += 0.3
            elif "lfi" in suspected_vuln and "inclusion" in path_name:
                score += 0.3
            elif "rce" in suspected_vuln and "injection" in path_name:
                score += 0.2
        
        # Confidence from auto-prompter
        confidence = challenge_info.get("confidence", 0.5)
        score += confidence * 0.2
        
        return min(score, 1.0)
    
    def _score_impact(self, path: dict) -> float:
        """Score based on potential impact (0.0-1.0)."""
        path_name = path.get("name", "").lower()
        
        # High impact paths
        high_impact = ["sql injection", "rce", "credential", "exploit"]
        medium_impact = ["directory", "enumeration", "scanning"]
        
        if any(keyword in path_name for keyword in high_impact):
            return 0.9
        elif any(keyword in path_name for keyword in medium_impact):
            return 0.6
        else:
            return 0.4
    
    def _score_dependencies(self, path: dict) -> float:
        """Score based on dependency completion (0.0-1.0)."""
        tasks = path.get("tasks", [])
        
        if not tasks:
            return 0.5
        
        # Check how many task dependencies are met
        completed = 0
        for task in tasks:
            task_key = f"{task.get('tool', '')}_{task.get('target', '')}"
            if task_key in self.executed_tasks:
                completed += 1
        
        if completed == 0:
            return 0.8  # No dependencies blocking
        else:
            return 0.5 + (completed / len(tasks)) * 0.5
    
    def _select_path(
        self,
        possible_paths: list[dict],
        existing_data: dict,
    ) -> dict:
        """Legacy method - delegates to scored selection."""
        return self._select_path_scored(possible_paths, existing_data, {})
    
    def _justify_selection(
        self,
        selected_path: dict,
        existing_data: dict,
        challenge_info: dict,
    ) -> str:
        """Generate justification for selected path with scoring details."""
        name = selected_path.get("name", "Unknown")
        desc = selected_path.get("description", "")
        
        services = existing_data.get("services", [])
        scoring = selected_path.get("scoring", {})
        total_score = selected_path.get("total_score", 0)
        
        # Build detailed justification
        parts = []
        parts.append(f"Selected '{name}': {desc}")
        parts.append(f"Overall score: {total_score:.2f}/1.00")
        
        if scoring:
            parts.append("Score breakdown:")
            for factor, value in scoring.items():
                parts.append(f"  - {factor}: {value:.2f}")
        
        if services:
            parts.append(f"Based on {len(services)} known services")
        
        if not services:
            parts.append("No prior reconnaissance data available - starting with initial enumeration")
        
        return "\n".join(parts)
    
    def format_response(self, decision: dict, findings: Optional[list] = None) -> str:
        """Format decision into structured response."""
        # Build findings content from executor results or fall back to path count
        if findings:
            findings_content = "\n".join(f"- {f}" for f in findings)
        else:
            n = len(decision.get("possible_paths", []))
            findings_content = f"Identified {n} possible attack paths (no tool results yet)"
        sections = [
            "[Current Understanding]",
            decision.get("understanding", ""),
            "",
            "[Action Taken]",
            f"Analyzed challenge and selected strategy: {decision.get('selected_path', {}).get('name', 'N/A')}",
            "",
            "[Reason]",
            decision.get("justification", ""),
            "",
            "[Findings]",
            findings_content,
            "",
            "[User Input Required]",
            decision.get("user_input_required", "No user input required at this time."),
            "",
            "[Next Steps]",
        ]
        
        for i, task in enumerate(decision.get("next_tasks", []), 1):
            sections.append(f"{i}. {task.get('tool', 'unknown')}: {task}")
        
        return "\n".join(sections)
