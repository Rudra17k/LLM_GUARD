import pandas as pd

print("⏳ Loading all datasets...")

# -------------------------------------------------------------
# 1. ARCHIVE-2: v3update20001 (Main large dataset)
# -------------------------------------------------------------
df_v3 = pd.read_csv("data/processed/archive-2/v3update20001.csv")
df_v3["label"] = df_v3["label"].map({"benign": 0, "injection": 1})
df_v3_clean = df_v3[["text", "label"]]
print(f"Loaded v3update20001: {len(df_v3_clean)} rows")

# -------------------------------------------------------------
# 2. ARCHIVE-2: prompt_injection_detection_dataset & update1357
# -------------------------------------------------------------
df_p1 = pd.read_csv("data/processed/archive-2/prompt_injection_detection_dataset.csv")
df_p1["label"] = df_p1["label"].map({"benign": 0, "injection": 1})
df_p1_clean = df_p1[["text", "label"]]

df_u1357 = pd.read_csv("data/processed/archive-2/update1357.csv")
df_u1357["label"] = df_u1357["label"].map({"benign": 0, "injection": 1})
df_u1357_clean = df_u1357[["text", "label"]]
print(f"Loaded other archive-2 files: {len(df_p1_clean) + len(df_u1357_clean)} rows")

# -------------------------------------------------------------
# 3. ARCHIVE-3: CommandInjection
# -------------------------------------------------------------
path_cmd = "data/processed/archive-3/PromptInjection-to-CommandInjection - CommandInjection.csv"
df_cmd = pd.read_csv(path_cmd)
df_cmd_clean = df_cmd.rename(columns={"Prompt": "text", "Label": "label"})[["text", "label"]]
print(f"Loaded CommandInjection: {len(df_cmd_clean)} rows")

# -------------------------------------------------------------
# 4. ARCHIVE-3: harmful_behaviors (All are attacks, label = 1)
# -------------------------------------------------------------
df_hb = pd.read_csv("data/processed/archive-3/harmful_behaviors.csv")
df_hb_clean = pd.DataFrame({"text": df_hb["goal"], "label": 1})
print(f"Loaded harmful_behaviors: {len(df_hb_clean)} rows")

# -------------------------------------------------------------
# 5. ARCHIVE-3: transfer_expriment_behaviors (All attacks, label = 1)
# -------------------------------------------------------------
path_trans = "data/processed/archive-3/transfer_expriment_behaviors.csv"
with open(path_trans, "r", encoding="utf-8", errors="ignore") as f:
    trans_lines = [line.strip() for line in f if line.strip()]

df_trans = pd.DataFrame({"text": trans_lines, "label": 1})
print(f"Loaded transfer_behaviors: {len(df_trans)} rows")

# -------------------------------------------------------------
# 7. CURATED CORPUS: train, val, test JSONLs
# -------------------------------------------------------------
df_curated_train = pd.read_json("data/processed/train.jsonl", lines=True)[["text", "label"]]
df_curated_val   = pd.read_json("data/processed/val.jsonl", lines=True)[["text", "label"]]
df_curated_test  = pd.read_json("data/processed/test.jsonl", lines=True)[["text", "label"]]
print(f"Loaded curated corpus splits: {len(df_curated_train) + len(df_curated_val) + len(df_curated_test)} rows")



# -------------------------------------------------------------
# 6. ORIGINAL: 500-sample JSONL
# -------------------------------------------------------------
df_orig = pd.read_json("data/processed/Prompt_INJECTION_And_Benign_DATASET.jsonl", lines=True)
df_orig["label"] = df_orig["label"].map({"benign": 0, "malicious": 1})
df_orig_clean = df_orig.rename(columns={"prompt": "text"})[["text", "label"]]
print(f"Loaded original JSONL: {len(df_orig_clean)} rows")

# -------------------------------------------------------------
# 7. MERGE EVERYTHING & DEDUPLICATE
# -------------------------------------------------------------
all_dfs = [
    df_v3_clean,
    df_p1_clean,
    df_u1357_clean,
    df_cmd_clean,
    df_hb_clean,
    df_trans,
    df_orig_clean,
    df_curated_train,
    df_curated_val,
    df_curated_test
]

master_df = pd.concat(all_dfs, ignore_index=True)

# Clean up
master_df = master_df.dropna(subset=["text"])
master_df["text"] = master_df["text"].astype(str).str.strip()
master_df = master_df[master_df["text"] != ""]  # remove empty strings
master_df = master_df.drop_duplicates(subset=["text"])  # remove identical prompts
master_df["label"] = master_df["label"].astype(int)

# -------------------------------------------------------------
# 8. SAVE TO DISK
# -------------------------------------------------------------
output_path = "data/processed/master_dataset.jsonl"
master_df.to_json(output_path, orient="records", lines=True)

print("\n================ MASTER DATASET SAVED ================")
print(f"Saved to: {output_path}")
print(f"Total Unique Prompts: {len(master_df)}")
print("\nClass Distribution:")
print(master_df["label"].value_counts())
