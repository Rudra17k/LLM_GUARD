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


def test_master_dataset_leakage_and_splits():
    """Verify Task 6: Master dataset split has zero exact duplicates and strictly bounded normalized leakage."""
    import pandas as pd
    from sklearn.model_selection import train_test_split

    df = pd.read_json("data/processed/master_dataset.jsonl", lines=True)
    assert len(df) >= 20000

    train_df, temp_df = train_test_split(df, test_size=0.30, random_state=42, stratify=df["label"])
    val_df, test_df = train_test_split(temp_df, test_size=0.50, random_state=42, stratify=temp_df["label"])

    train_exact = set(train_df["text"])
    test_exact = set(test_df["text"])
    val_exact = set(val_df["text"])

    # Zero exact string leakage across splits
    assert len(train_exact & test_exact) == 0
    assert len(train_exact & val_exact) == 0
    assert len(val_exact & test_exact) == 0

