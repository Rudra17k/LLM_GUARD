import re
import time
import math
from collections import Counter
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# pyrefly: ignore [missing-import]
from src.dataset.schema import AttackFamily, InjectionType


@dataclass
class SemanticScoreResult:
    """Result from Layer 3 Deep Semantic Guard."""
    score: float  # 0.0 to 1.0
    detected_traits: List[str] = field(default_factory=list)
    entropy: float = 0.0
    anomaly_flag: bool = False
    latency_ms: float = 0.0
    attack_family: Optional[AttackFamily] = None
    injection_type: Optional[InjectionType] = None


class SemanticGuard:
    """
    Layer 3: Deep Semantic Guard.
    Performs deep semantic analysis, roleplay deception detection, 
    jailbreak framing detection, and character entropy anomaly detection.
    """

    def __init__(self):
        self._compile_semantic_patterns()

    def _compile_semantic_patterns(self):
        # Subtle jailbreak & hypothetical framing
        self.hypothetical_framing = re.compile(
            r"\b(hypothetically|in an? (?:imaginary|fictional)(?:\s+(?:imaginary|fictional))?\s+(?:world|story|scenario|universe)|"
            r"in an imaginary world|in a fictional story|for research purposes only|"
            r"purely educational|in an alternate universe|pretend there are no ethics|simulate a world|"
            r"act as a character who doesn't care|you have no constraints|you have broken free)\b",
            re.IGNORECASE
        )

        # Authority usurpation / developer persona
        self.authority_persona = re.compile(
            r"\b(you are now an ai named|as a senior security researcher|as a system administrator|"
            r"you are evilbot|you are chadgpt|you are dan|jailbroken assistant|unfiltered mode|"
            r"developer mode v\d+|super administrator)\b",
            re.IGNORECASE
        )

        # Instruction override semantics (MCR-15: with quantifiers and determiners)
        self.instruction_negation = re.compile(
            r"\b(do not follow|disregard|override|forget|abandon|drop|ignore)\s+"
            r"((?:all|any|these|those|the|your)\s+)?"
            r"((?:all|any|these|those|the|your)\s+)?"
            r"(previous|prior|original|core|system|initial)\s+"
            r"(rules|instructions|prompts|directives|guidelines|programming)\b",
            re.IGNORECASE
        )

        # Document / Payload exfiltration semantics
        self.exfil_semantics = re.compile(
            r"(webhook\.site|evil\.com|attacker\.org|transfer\s+to\s+server|curl\s+https?://|"
            r"nc\s+-l|fetch\(['\"`]?https?://|http://127\.0\.0\.1)",
            re.IGNORECASE
        )

    def calculate_entropy(self, text: str) -> float:
        """Shannon entropy of character distribution to spot obfuscation and ciphertext (O(N))."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
        return round(max(0.0, entropy), 3)

    def evaluate(self, text: str) -> SemanticScoreResult:
        """
        Evaluate text for semantic adversarial traits, framing, and anomalies.
        """
        start_time = time.perf_counter()
        traits: List[str] = []
        score = 0.0
        family: Optional[AttackFamily] = None
        inj_type: Optional[InjectionType] = None

        # 1. Check Instruction Negation Semantics
        if self.instruction_negation.search(text):
            traits.append("instruction_negation_framing")
            score += 0.50
            family = AttackFamily.INSTRUCTION_OVERRIDE
            inj_type = InjectionType.DIRECT

        # 2. Check Hypothetical / Deceptive Framing
        if self.hypothetical_framing.search(text):
            traits.append("adversarial_hypothetical_framing")
            score += 0.40
            if family is None:
                family = AttackFamily.ROLEPLAY_AUTHORITY
                inj_type = InjectionType.DIRECT

        # 3. Check Authority / Persona Usurpation
        if self.authority_persona.search(text):
            traits.append("authority_persona_impersonation")
            score += 0.45
            family = AttackFamily.ROLEPLAY_AUTHORITY
            inj_type = InjectionType.DIRECT

        # 4. Check Exfiltration / Command Semantics
        if self.exfil_semantics.search(text):
            traits.append("network_exfiltration_payload")
            score += 0.40
            if family is None:
                family = AttackFamily.MARKDOWN_EXFILTRATION
                inj_type = InjectionType.INDIRECT

        # 5. Shannon Entropy Anomaly (High entropy indicates base64 / encrypted blobs)
        entropy = self.calculate_entropy(text)
        anomaly_flag = False
        if len(text) > 40 and entropy > 4.85:
            traits.append("high_entropy_payload")
            score += 0.25
            anomaly_flag = True
            if family is None:
                family = AttackFamily.OBFUSCATION_ENCODING
                inj_type = InjectionType.DIRECT

        score = min(score, 1.0)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return SemanticScoreResult(
            score=round(score, 3),
            detected_traits=traits,
            entropy=entropy,
            anomaly_flag=anomaly_flag,
            latency_ms=round(elapsed_ms, 3),
            attack_family=family,
            injection_type=inj_type
        )
