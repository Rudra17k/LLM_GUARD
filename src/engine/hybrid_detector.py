import os
import json
import time
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
import joblib

from src.dataset.schema import AttackFamily, InjectionType
from src.engine.rule_triage import RuleTriageEngine, RuleMatchResult
from src.engine.semantic_guard import SemanticGuard, SemanticScoreResult
from src.engine.normalizer import InputNormalizer


class ModelIntegrityError(Exception):
    """Raised when an ML model artifact fails cryptographic checksum verification (CWE-502)."""
    pass


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
    metadata: Dict[str, Any] = field(default_factory=dict)

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

    DEFAULT_MODEL_SHA256 = "cdae7cc94f9a8629b776e5c4a224abc0216b664db5d4f72169120b56b8f6ff25"

    def __init__(
        self,
        model_path: str = "models/baseline_model.joblib",
        expected_sha256: Optional[str] = None
    ):
        self.rule_engine = RuleTriageEngine()
        self.semantic_guard = SemanticGuard()
        self.model_path = model_path
        self.expected_sha256 = expected_sha256
        self.ml_pipeline = None
        self._load_ml_pipeline()

    @staticmethod
    def compute_sha256(filepath: str) -> str:
        """Computes SHA-256 hash of a file efficiently in 64KB chunks."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _get_expected_sha256(self) -> Optional[str]:
        if self.expected_sha256:
            return self.expected_sha256.lower().strip()

        env_hash = os.getenv("MODEL_SHA256")
        if env_hash:
            return env_hash.lower().strip()

        metrics_path = Path("models/baseline_metrics.json")
        if metrics_path.exists():
            try:
                with open(metrics_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "model_sha256" in data and data["model_sha256"]:
                        return data["model_sha256"].lower().strip()
            except Exception:
                pass

        return self.DEFAULT_MODEL_SHA256

    def _load_ml_pipeline(self):
        if not os.path.exists(self.model_path):
            print(f"⚠️ Notice: ML model artifact not found at {self.model_path}.")
            self.ml_pipeline = None
            return

        expected_hash = self._get_expected_sha256()
        if expected_hash:
            actual_hash = self.compute_sha256(self.model_path)
            if actual_hash != expected_hash:
                raise ModelIntegrityError(
                    f"🚨 Model integrity verification failed for '{self.model_path}'!\n"
                    f"Expected SHA-256: {expected_hash}\n"
                    f"Actual SHA-256:   {actual_hash}\n"
                    f"Refusing to deserialize unverified joblib/pickle binary (CWE-502)."
                )

        try:
            self.ml_pipeline = joblib.load(self.model_path)
        except Exception as e:
            print(f"⚠️ Warning: Could not load ML pipeline from {self.model_path}: {e}")
            self.ml_pipeline = None

    def inspect(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> InspectionResult:
        """
        Inspect a prompt through the cascaded hybrid layers.
        """
        meta = dict(metadata) if metadata else {}
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
                layer_latencies={"l1_rules_ms": 0.0},
                signals={"empty_input": True},
                prompt_snippet="",
                metadata=meta
            )

        # Pre-process & normalize text against evasions (homoglyphs, spacing, full-width, zero-width)
        norm_text = InputNormalizer.normalize(text)
        if norm_text != text:
            signals["normalized"] = True

        # -------------------------------------------------------------
        # STEP 1: LAYER 1 - SUB-MILLISECOND RULE TRIAGE (< 1ms)
        # -------------------------------------------------------------
        l1_result: RuleMatchResult = self.rule_engine.evaluate(norm_text)
        # Fallback check on raw text in case normalization altered special syntax
        if not l1_result.matched and norm_text != text:
            l1_raw = self.rule_engine.evaluate(text)
            if l1_raw.matched:
                l1_result = l1_raw

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
                prompt_snippet=text[:120],
                metadata=meta
            )

        # -------------------------------------------------------------
        # STEP 2: LAYER 2 - STATISTICAL ML CLASSIFIER (~5ms)
        # -------------------------------------------------------------
        ml_prob = 0.0
        if self.ml_pipeline is not None:
            l2_start = time.perf_counter()
            probs = self.ml_pipeline.predict_proba([norm_text])[0]
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
        # - ML probability is ambiguous or low (out-of-vocabulary evasion defense: ml_prob <= 0.85)
        # - Or Layer 1 found suspicious patterns
        # - Or ML model is unavailable
        l3_result: Optional[SemanticScoreResult] = None
        should_run_l3 = (ml_prob <= 0.85) or l1_result.matched or (self.ml_pipeline is None)
        
        if should_run_l3:
            l3_result = self.semantic_guard.evaluate(norm_text)
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
                # Non-diluting ensemble: an anomaly detection in L3 can reinforce,
                # but MUST NOT dilute a high-confidence ML detection.
                blended = (ml_prob * 0.60) + (l3_score * 0.40)
                combined_risk = max(ml_prob, l3_score, blended)
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
            prompt_snippet=text[:120],
            metadata=meta
        )

    def inspect_batch(
        self,
        texts: List[str],
        metadata: Optional[List[Optional[Dict[str, Any]]]] = None
    ) -> List[InspectionResult]:
        """
        Inspect multiple prompts with vectorized batch ML inference (MCR-12).
        Short-circuits blatant Layer 1 attacks and vectorizes remaining
        prompts across Scikit-Learn in a single batch pass for high throughput.
        """
        if not texts:
            return []

        results: List[Optional[InspectionResult]] = [None] * len(texts)
        remaining_indices: List[int] = []
        l1_results: List[Optional[RuleMatchResult]] = [None] * len(texts)
        start_times: List[float] = []

        for i, text in enumerate(texts):
            meta_i = dict(metadata[i]) if (metadata and i < len(metadata) and metadata[i]) else {}
            start_times.append(time.perf_counter())
            if not text or not text.strip():
                results[i] = InspectionResult(
                    verdict="ALLOW",
                    risk_score=0.0,
                    confidence=1.0,
                    threat_level="SAFE",
                    primary_layer="NONE",
                    injection_type=InjectionType.BENIGN.value,
                    attack_family=AttackFamily.BENIGN_GENERAL.value,
                    total_latency_ms=0.01,
                    layer_latencies={"l1_rules_ms": 0.0},
                    signals={"empty_input": True},
                    prompt_snippet="",
                    metadata=meta_i
                )
                continue

            norm = InputNormalizer.normalize(text)

            # Step 1: L1 Rule Triage
            l1_res = self.rule_engine.evaluate(norm)
            if not l1_res.matched and norm != text:
                l1_raw = self.rule_engine.evaluate(text)
                if l1_raw.matched:
                    l1_res = l1_raw
            l1_results[i] = l1_res

            # Fast path short circuit
            if l1_res.matched and l1_res.confidence >= 0.95:
                elapsed = (time.perf_counter() - start_times[i]) * 1000.0
                signals = {
                    "l1_matched": True,
                    "l1_patterns": l1_res.matched_patterns
                }
                if norm != text:
                    signals["normalized"] = True
                results[i] = InspectionResult(
                    verdict="BLOCK",
                    risk_score=round(l1_res.confidence, 3),
                    confidence=round(l1_res.confidence, 3),
                    threat_level="CRITICAL",
                    primary_layer="LAYER_1_RULES",
                    injection_type=l1_res.injection_type.value if l1_res.injection_type else "direct",
                    attack_family=l1_res.attack_family.value if l1_res.attack_family else "instruction_override",
                    total_latency_ms=round(elapsed, 3),
                    layer_latencies={"l1_rules_ms": l1_res.latency_ms},
                    signals=signals,
                    prompt_snippet=text[:120],
                    metadata=meta_i
                )
            else:
                remaining_indices.append(i)

        if not remaining_indices:
            return [r for r in results if r is not None]

        # Step 2: Batch Vectorized ML Inference
        candidate_norms = [InputNormalizer.normalize(texts[idx]) for idx in remaining_indices]
        batch_ml_probs = [0.0] * len(remaining_indices)
        batch_ml_latency = 0.0

        if self.ml_pipeline is not None and candidate_norms:
            ml_batch_start = time.perf_counter()
            probs_matrix = self.ml_pipeline.predict_proba(candidate_norms)
            batch_ml_latency = (time.perf_counter() - ml_batch_start) * 1000.0 / len(candidate_norms)
            batch_ml_probs = [float(row[1]) for row in probs_matrix]

        # Step 3 & 4: L3 Semantic Guard & Arbitration for each remaining candidate
        for k, idx in enumerate(remaining_indices):
            orig_text = texts[idx]
            norm_text = candidate_norms[k]
            ml_prob = batch_ml_probs[k]
            l1_res = l1_results[idx]

            latencies = {
                "l1_rules_ms": l1_res.latency_ms if l1_res else 0.0,
                "l2_ml_ms": round(batch_ml_latency, 3)
            }
            signals = {
                "l1_matched": l1_res.matched if l1_res else False,
                "l1_patterns": l1_res.matched_patterns if l1_res else [],
                "l2_attack_probability": round(ml_prob, 4)
            }
            if norm_text != orig_text:
                signals["normalized"] = True

            # Step 3: Layer 3
            should_run_l3 = (ml_prob <= 0.85) or (l1_res.matched if l1_res else False) or (self.ml_pipeline is None)
            l3_result = None
            if should_run_l3:
                l3_result = self.semantic_guard.evaluate(norm_text)
                latencies["l3_semantic_ms"] = l3_result.latency_ms
                signals["l3_traits"] = l3_result.detected_traits
                signals["l3_entropy"] = l3_result.entropy
                signals["l3_semantic_score"] = l3_result.score
            else:
                latencies["l3_semantic_ms"] = 0.0
                signals["l3_traits"] = []

            # Step 4: Arbitration
            l3_score = l3_result.score if l3_result is not None else 0.0
            if self.ml_pipeline is not None:
                if should_run_l3 and l3_score > 0:
                    blended = (ml_prob * 0.60) + (l3_score * 0.40)
                    combined_risk = max(ml_prob, l3_score, blended)
                else:
                    combined_risk = ml_prob
            else:
                combined_risk = l3_score

            # Primary Layer selection
            if l1_res and l1_res.matched:
                primary_layer = "LAYER_1_RULES"
                inj_type = l1_res.injection_type.value if l1_res.injection_type else "direct"
                family = l1_res.attack_family.value if l1_res.attack_family else "instruction_override"
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

            if combined_risk >= 0.70 or (l1_res and l1_res.matched and l1_res.confidence >= 0.90):
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

            total_elapsed = (time.perf_counter() - start_times[idx]) * 1000.0
            meta_idx = dict(metadata[idx]) if (metadata and idx < len(metadata) and metadata[idx]) else {}

            results[idx] = InspectionResult(
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
                prompt_snippet=orig_text[:120],
                metadata=meta_idx
            )

        return [r for r in results if r is not None]
