import sys
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.engine.hybrid_detector import HybridPromptDetector


def main():
    parser = argparse.ArgumentParser(description="PID_cys: Hybrid Prompt Injection Detection CLI")
    parser.add_argument("prompt", type=str, help="Prompt text to inspect")
    parser.add_argument("--json", action="store_true", help="Output full JSON telemetry")

    args = parser.parse_args()

    detector = HybridPromptDetector()
    result = detector.inspect(args.prompt)

    if args.json:
        import json
        print(json.dumps(result.to_dict(), indent=2))
        if result.verdict == "BLOCK":
            sys.exit(1)
        return

    print("=" * 60)
    print("🛡️  PID_cys Prompt Inspection Result")
    print("=" * 60)
    if result.verdict == "BLOCK":
        print(f"🚨 Verdict:        BLOCKED (Prompt Injection Detected)")
    elif result.verdict == "AUDIT":
        print(f"⚠️  Verdict:        AUDIT (Suspicious Context)")
    else:
        print(f"🟢 Verdict:        ALLOWED (Safe Prompt)")

    print(f"Threat Level:   {result.threat_level}")
    print(f"Risk Score:     {result.risk_score * 100:.1f}%")
    print(f"Confidence:     {result.confidence * 100:.1f}%")
    print(f"Primary Layer:  {result.primary_layer}")
    print(f"Attack Family:  {result.attack_family}")
    print(f"Injection Type: {result.injection_type}")
    print(f"Total Latency:  {result.total_latency_ms:.3f} ms")
    print("-" * 60)
    print(f"Layer Latencies: {result.layer_latencies}")
    print("=" * 60)

    if result.verdict == "BLOCK":
        sys.exit(1)


if __name__ == "__main__":
    main()
