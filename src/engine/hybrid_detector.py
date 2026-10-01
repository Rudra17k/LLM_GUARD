import os
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
import joblib

from src.dataset.schema import AttackFamily, InjectionType
from src.engine.rule_triage import RuleTriageEngine, RuleMatchResult
from src.engine.semantic_guard import SemanticGuard, SemanticScoreResult


@dataclass
class InspectionResult:
    """Complete inspection verdict for an incoming prompt."""
    verdict: str                  # "ALLOW", "BLOCK", "AUDIT"
    risk_score: float             # 0.0 to 1.0
    confidence: float             # 0.0 to 1.0
    threat_level: str             # "SAFE", "SUSPICIOUS", "CRITICAL"
    primary_layer: str            # "LAYER_1_RULES", "LAYER_2_ML", "LAYER_3_SEMANTIC"
    injection_type: str           # "benign", "direct", "indirect"
    attack_family: str            # specific taxonomy name
    total_latency_ms: float
    layer_latencies: Dict[str, float]
    signals: Dict[str, Any]       # granular details from each layer
    prompt_snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HybridPromptDetector:
    """
    Industry-Grade Hybrid Prompt Injection Detector.
    Orchestrates:
      - Layer 1: Sub-millisecond Rule & Delimiter Triage (O(n) Aho-Corasick)
      - Layer 2: Fast Statistical ML Classifier (TF-IDF + Calibrated Logistic Regression)
      - Layer 3: Contextual Semantic Guard (Roleplay, Framing, & Anomaly Analysis)
    """

    def __init__(self, model_path: str = "models/baseline_model.joblib"):
        self.rule_engine = RuleTriageEngine()
        self.semantic_guard = SemanticGuard()
        self.model_path = model_path
        self.ml_pipeline = None
        self._load_ml_pipeline()

    def _load_ml_pipeline(self):
        if os.path.exists(self.model_path):
            try:
                self.ml_pipeline = joblib.load(self.model_path)
            except Exception as e:
                print(f"⚠️ Warning: Could not load ML pipeline from {self.model_path}: {e}")
                self.ml_pipeline = None
        else:
            print(f"⚠️ Notice: ML model artifact not found at {self.model_path}.")

    def inspect(self, text: str) -> InspectionResult:
        """
        Inspect a prompt through the cascaded hybrid layers.
        """
        overall_start = time.perf_counter()
        latencies: Dict[str, float] = {}
        signals: Dict[str, Any] = {}

        if not text or not text.strip():
            return InspectionResult(
                verdict="ALLOW",
                risk_score=0.0,
                confidence=1.0,
                threat_level="SAFE",
                primary_layer="NONE",
                injection_type=InjectionType.BENIGN.value,
                attack_family=AttackFamily.BENIGN_GENERAL.value,
                total_latency_ms=0.01,
                layer_latencies={"l1": 0.0},
                signals={"empty_input": True},
                prompt_snippet=""
            )

        # -------------------------------------------------------------
        # STEP 1: LAYER 1 - SUB-MILLISECOND RULE TRIAGE (< 1ms)
        # -------------------------------------------------------------
        l1_result: RuleMatchResult = self.rule_engine.evaluate(text)
        latencies["l1_rules_ms"] = l1_result.latency_ms
        signals["l1_matched"] = l1_result.matched
        signals["l1_patterns"] = l1_result.matched_patterns

        # FAST-PATH SHORT CIRCUIT:
        # If Layer 1 caught a blatant attack with high confidence, block immediately!
        if l1_result.matched and l1_result.confidence >= 0.95:
            total_elapsed = (time.perf_counter() - overall_start) * 1000.0
            return InspectionResult(
                verdict="BLOCK",
                risk_score=round(l1_result.confidence, 3),
                confidence=round(l1_result.confidence, 3),
                threat_level="CRITICAL",
                primary_layer="LAYER_1_RULES",
                injection_type=l1_result.injection_type.value if l1_result.injection_type else "direct",
                attack_family=l1_result.attack_family.value if l1_result.attack_family else "instruction_override",
                total_latency_ms=round(total_elapsed, 3),
                layer_latencies=latencies,
                signals=signals,
                prompt_snippet=text[:120]
            )

        # -------------------------------------------------------------
        # STEP 2: LAYER 2 - STATISTICAL ML CLASSIFIER (~5ms)
        # -------------------------------------------------------------
        ml_prob = 0.0
        if self.ml_pipeline is not None:
            l2_start = time.perf_counter()
            probs = self.ml_pipeline.predict_proba([text])[0]
            ml_prob = float(probs[1])  # probability of injection (class 1)
            l2_latency = (time.perf_counter() - l2_start) * 1000.0
            latencies["l2_ml_ms"] = round(l2_latency, 3)
            signals["l2_attack_probability"] = round(ml_prob, 4)
        else:
            latencies["l2_ml_ms"] = 0.0
            signals["l2_attack_probability"] = 0.0

        # -------------------------------------------------------------
        # STEP 3: LAYER 3 - CONTEXTUAL SEMANTIC GUARD
        # -------------------------------------------------------------
        # Run Layer 3 if:
        # - ML probability is ambiguous (0.25 <= ml_prob <= 0.85)
        # - Or Layer 1 found suspicious patterns
        # - Or ML model is unavailable
        l3_result: Optional[SemanticScoreResult] = None
        should_run_l3 = (0.20 <= ml_prob <= 0.85) or l1_result.matched or (self.ml_pipeline is None)
        
        if should_run_l3:
            l3_result = self.semantic_guard.evaluate(text)
            latencies["l3_semantic_ms"] = l3_result.latency_ms
            signals["l3_traits"] = l3_result.detected_traits
            signals["l3_entropy"] = l3_result.entropy
            signals["l3_semantic_score"] = l3_result.score
        else:
            latencies["l3_semantic_ms"] = 0.0
            signals["l3_traits"] = []

        # -------------------------------------------------------------
        # STEP 4: DECISION & ARBITRATION ENGINE
        # -------------------------------------------------------------
        l3_score = l3_result.score if l3_result is not None else 0.0

        # Compute weighted risk score
        if self.ml_pipeline is not None:
            if should_run_l3 and l3_score > 0:
                # Hybrid fusion of ML and Semantic Guard
                combined_risk = (ml_prob * 0.60) + (l3_score * 0.40)
            else:
                combined_risk = ml_prob
        else:
            combined_risk = l3_score

        # Determine Primary Layer
        if l1_result.matched:
            primary_layer = "LAYER_1_RULES"
            inj_type = l1_result.injection_type.value if l1_result.injection_type else "direct"
            family = l1_result.attack_family.value if l1_result.attack_family else "instruction_override"
        elif l3_result is not None and l3_result.score >= 0.45:
            primary_layer = "LAYER_3_SEMANTIC"
            inj_type = l3_result.injection_type.value if l3_result.injection_type else "direct"
            family = l3_result.attack_family.value if l3_result.attack_family else "roleplay_authority"
        else:
            primary_layer = "LAYER_2_ML"
            if combined_risk >= 0.50:
                inj_type = "direct"
                family = "instruction_override"
            else:
                inj_type = "benign"
                family = "benign_general"

        # Determine Verdict & Threat Level
        if combined_risk >= 0.70 or (l1_result.matched and l1_result.confidence >= 0.90):
            verdict = "BLOCK"
            threat_level = "CRITICAL"
        elif combined_risk >= 0.50:
            verdict = "AUDIT"
            threat_level = "SUSPICIOUS"
        else:
            verdict = "ALLOW"
            threat_level = "SAFE"
            inj_type = "benign"
            family = "benign_general"

        total_elapsed = (time.perf_counter() - overall_start) * 1000.0

        return InspectionResult(
            verdict=verdict,
            risk_score=round(combined_risk, 3),
            confidence=round(max(combined_risk, 1.0 - combined_risk), 3),
            threat_level=threat_level,
            primary_layer=primary_layer,
            injection_type=inj_type,
            attack_family=family,
            total_latency_ms=round(total_elapsed, 3),
            layer_latencies=latencies,
            signals=signals,
            prompt_snippet=text[:120]
        )
