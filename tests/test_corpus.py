from pathlib import Path
import json
from src.dataset.schema import PromptSample


def test_processed_files_exist():
    train_file = Path("data/processed/train.jsonl")
    val_file = Path("data/processed/val.jsonl")
    test_file = Path("data/processed/test.jsonl")

    assert train_file.exists(), "train.jsonl must exist"
    assert val_file.exists(), "val.jsonl must exist"
    assert test_file.exists(), "test.jsonl must exist"


def test_processed_samples_valid_schema():
    for split_name in ["train", "val", "test"]:
        path = Path(f"data/processed/{split_name}.jsonl")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = json.loads(line.strip())
                sample = PromptSample(**raw)
                assert sample.id.startswith("sample-")
                assert sample.label in (0, 1)
                assert sample.text.strip() != ""
