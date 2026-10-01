import pandas as pd 
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

# 1. Load the Master Dataset (23,821 prompts!)
data_path = "data/processed/master_dataset.jsonl"
print(f"Loading data from: {data_path}")
df = pd.read_json(data_path, lines=True)

print("\n--- MASTER DATASET SUMMARY ---")
print(f"Total samples: {len(df)}")
print("Class breakdown (0 = Safe, 1 = Attack):")
print(df["label"].value_counts())

# 2. Stratified split (70% train, 15% validation, 15% test)
train_df, temp_df = train_test_split(
    df, 
    test_size=0.30, 
    random_state=42, 
    stratify=df["label"]
)

val_df, test_df = train_test_split(
    temp_df, 
    test_size=0.50, 
    random_state=42, 
    stratify=temp_df["label"]
)

print("\n--- SPLIT SIZES ---")
print(f"Training set:   {len(train_df)} samples")
print(f"Validation set: {len(val_df)} samples")
print(f"Test set:       {len(test_df)} samples")

# 3. Vectorization (TF-IDF)
print("\n⏳ 1. Converting text to numbers (TF-IDF Vectorization)...")
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=20000,       # increased to 20,000 to cover all new datasets!
    sublinear_tf=True
)

X_train = vectorizer.fit_transform(train_df["text"])
y_train = train_df["label"]

X_val = vectorizer.transform(val_df["text"])
y_val = val_df["label"]

X_test = vectorizer.transform(test_df["text"])
y_test = test_df["label"]

# 4. Train the Model
print("⏳ 2. Training Logistic Regression model (with balanced weights)...")
model = LogisticRegression(
    class_weight="balanced", 
    max_iter=1000, 
    random_state=42
)
model.fit(X_train, y_train)
print("✅ Training complete!")

# 5. Evaluate on Validation Set
print("\n⏳ 3. Testing on the Validation Set (Practice Exam)...")
val_preds = model.predict(X_val)

print("\n--- VALIDATION PERFORMANCE REPORT ---")
print(classification_report(y_val, val_preds, target_names=["Safe (0)", "Attack (1)"]))

cm = confusion_matrix(y_val, val_preds)
print("Confusion Matrix:")
print(f"  Safely Allowed: {cm[0][0]}  |  False Alarms: {cm[0][1]}")
print(f"  Missed Attacks: {cm[1][0]}  |  Caught Attacks: {cm[1][1]}")

