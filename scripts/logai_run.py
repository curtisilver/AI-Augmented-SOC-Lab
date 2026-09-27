"""
LogAI anomaly detection run — AI-Augmented SOC Project, Task 1
Input: LogAI-Test.csv (500-row export from Splunk, Windows Security event logs)

Pipeline: CSV -> Preprocessor -> LogParser (Drain) -> LogVectorizer (TF-IDF)
          -> FeatureExtractor (1-min time buckets) -> AnomalyDetector (One-Class SVM, nu=0.1)

Runs in an isolated Conda environment on Python 3.10 (LogAI's gensim dependency
does not build against Python 3.14).
"""

import pandas as pd
from logai.preprocess.preprocessor import Preprocessor, PreprocessorConfig
from logai.information_extraction.log_parser import LogParser, LogParserConfig
from logai.information_extraction.log_vectorizer import LogVectorizer, VectorizerConfig
from logai.information_extraction.feature_extractor import FeatureExtractor, FeatureExtractorConfig
from logai.algorithms.anomaly_detection_algo.one_class_svm import OneClassSVMParams
from logai.analysis.anomaly_detector import AnomalyDetector, AnomalyDetectionConfig

# --- Load the Splunk CSV export ---
print("Loading CSV...")
df = pd.read_csv("LogAI-Test.csv")
print(f"Loaded {len(df)} rows")

# LogAI works on the raw log message text plus a timestamp
logrecord_df = pd.DataFrame()
logrecord_df["logline"] = df["_raw"].astype(str)
logrecord_df["timestamp"] = pd.to_datetime(df["_time"], errors="coerce", utc=True)
logrecord_df = logrecord_df.dropna(subset=["timestamp"])
print(f"{len(logrecord_df)} rows have valid timestamps")

t_min, t_max = logrecord_df["timestamp"].min(), logrecord_df["timestamp"].max()
print(f"Timestamp span: {t_max - t_min} (min={t_min}, max={t_max})")

# --- Preprocess: strip variable tokens (IDs, hex values) ---
preprocessor = Preprocessor(PreprocessorConfig())
preprocessed_loglines, _ = preprocessor.clean_log(logrecord_df["logline"])

# --- Parse loglines into templates (Drain algorithm) ---
print("Parsing log templates...")
parser = LogParser(LogParserConfig())
parsed_result = parser.parse(preprocessed_loglines)

# --- Vectorize templates: text must become numeric before aggregation ---
print("Vectorizing parsed log templates (TF-IDF)...")
vectorizer = LogVectorizer(VectorizerConfig(algo_name="tfidf"))
vectorizer.fit(parsed_result["parsed_logline"])
log_vectors = vectorizer.transform(parsed_result["parsed_logline"])

# --- Feature extraction: aggregate into time buckets ---
# 15min collapsed the ~10-minute sample into 2 buckets; 1min gives 11 usable buckets.
BUCKET = "1min"
print(f"Extracting features (bucket size={BUCKET})...")
feature_extractor = FeatureExtractor(FeatureExtractorConfig(group_by_time=BUCKET))
_, feature_vector = feature_extractor.convert_to_feature_vector(
    log_vectors, attributes=pd.DataFrame(), timestamps=logrecord_df["timestamp"]
)
print(f"Number of time buckets: {len(feature_vector)}")

# Keep timestamps aside for labelling; sklearn needs purely numeric input
timestamps = feature_vector["timestamp"]
feature_numeric = feature_vector.drop(columns=["timestamp"])

# --- Anomaly detection ---
# Default nu=0.5 flagged ~45% of buckets (a sensitivity artefact, not a signal).
# nu=0.1 targets ~10% anomalies. LogAI's factory requires the typed params object.
print("Running anomaly detection (One-Class SVM)...")
svm_params = OneClassSVMParams(nu=0.1)
ad_config = AnomalyDetectionConfig(algo_name="one_class_svm", algo_params=svm_params)
anomaly_detector = AnomalyDetector(ad_config)
anomaly_detector.fit(feature_numeric)
results = anomaly_detector.predict(feature_numeric)

print("\n=== ANOMALY DETECTION RESULTS ===")
print(results.head())
print(results.iloc[:, 0].value_counts())

flagged = timestamps[results.iloc[:, 0] == 1]
print(f"\n{len(flagged)} time-bucket(s) flagged as anomalous:")
print(flagged.to_frame())

print("\nDone.")
