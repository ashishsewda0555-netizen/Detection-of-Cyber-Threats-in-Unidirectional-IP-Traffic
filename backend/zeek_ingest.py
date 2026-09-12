#!/usr/bin/env python3
"""
zeek_ingest.py — Network Traffic Ingestion from Zeek conn.log (JSON)

Replaces packet-level Scapy sniffing with flow-level Zeek log ingestion.
Parses the 5-tuple, extracts payload byte metrics, derives TCP flag counts
from the Zeek `history` column, computes temporal flow_rate via 5-second
windowing on the `ts` column, and outputs zeek_features_v2.csv.

Features extracted:
  5-tuple metadata:
    - id.orig_h, id.resp_h, id.orig_p, id.resp_p, proto

  Byte metrics:
    - orig_bytes, resp_bytes
    - exfiltration_ratio: orig_bytes / (resp_bytes + 1)

  TCP flag features (from Zeek `history` column):
    - syn_flag_count: occurrences of 'S' or 's' in history string
    - ack_flag_count: occurrences of 'A' or 'a' in history string
    - syn_ack_ratio: syn_flag_count / (ack_flag_count + 1)

  Temporal features (from Zeek `ts` timestamp column):
    - flow_rate: number of connections in the same 5-second window
"""

import argparse
import logging
import math
import os
import sys
import time
from typing import Optional

import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Required 5-tuple flow columns
FIVE_TUPLE_COLS = [
    "id.orig_h",
    "id.resp_h",
    "id.orig_p",
    "id.resp_p",
    "proto",
]

# Required byte metrics
BYTE_COLS = [
    "orig_bytes",
    "resp_bytes",
]

# Engineered features
ENGINEERED_COLS = [
    "exfiltration_ratio",
    "syn_flag_count",
    "ack_flag_count",
    "syn_ack_ratio",
    "flow_rate",
]

FINAL_COLUMNS = FIVE_TUPLE_COLS + BYTE_COLS + ENGINEERED_COLS

# Window size for flow_rate calculation
WINDOW_SECONDS = 5


def count_flags(history: str, flag_chars: str) -> int:
    """Count occurrences of specific flag characters in a Zeek history string.

    Zeek history strings encode TCP state transitions:
      S = SYN sent by originator
      s = SYN sent by responder (SYN-ACK)
      A = ACK sent by originator
      a = ACK sent by responder
      H = SYN-ACK sent by originator
      h = SYN-ACK sent by responder
      D = data sent by originator
      d = data sent by responder
      F = FIN sent by originator
      f = FIN sent by responder
      R = RST sent by originator
      r = RST sent by responder
    """
    if not isinstance(history, str):
        return 0
    return sum(1 for c in history if c in flag_chars)


def parse_zeek_conn_log(
    log_path: str = "conn.log",
    output_csv: Optional[str] = "zeek_features_v2.csv",
) -> pd.DataFrame:
    """Parse a Zeek conn.log JSON file and extract flow features.

    Extracts the 5-tuple, byte metrics, TCP flag counts from the `history`
    column, exfiltration_ratio, and windowed flow_rate from the `ts` column.

    Parameters
    ----------
    log_path : str
        Path to the Zeek conn.log JSON file. Defaults to 'conn.log'.
    output_csv : Optional[str]
        Path to save the resulting CSV file. If None, CSV is not written.
        Defaults to 'zeek_features_v2.csv'.

    Returns
    -------
    pd.DataFrame
        Parsed DataFrame containing the 5-tuple, byte counts, flag counts,
        exfiltration_ratio, syn_ack_ratio, and flow_rate.
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Zeek log file not found: {log_path}")

    file_size_mb = os.path.getsize(log_path) / (1024 * 1024)
    logger.info(f"Reading Zeek conn.log from '{log_path}' ({file_size_mb:.2f} MB)...")

    start_time = time.time()

    # Read JSON lines into DataFrame
    try:
        df = pd.read_json(log_path, lines=True)
    except Exception as e:
        logger.error(f"Failed to parse JSON lines from {log_path}: {e}")
        raise

    logger.info(f"Loaded {len(df):,} records in {time.time() - start_time:.2f} seconds.")

    # Handle nested 'id' field if present instead of flattened keys
    if "id" in df.columns and not all(col in df.columns for col in FIVE_TUPLE_COLS):
        logger.info("Unnesting 'id' record dictionary...")
        id_df = pd.json_normalize(df["id"]).add_prefix("id.")
        for col in ["id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p"]:
            if col in id_df.columns:
                df[col] = id_df[col]

    # Validate presence of required columns
    missing_5tuple = [col for col in FIVE_TUPLE_COLS if col not in df.columns]
    if missing_5tuple:
        raise KeyError(f"Missing 5-tuple columns in {log_path}: {missing_5tuple}")

    # Ensure byte columns exist (create with 0 if missing)
    for col in BYTE_COLS:
        if col not in df.columns:
            logger.warning(f"Column '{col}' not found in log; initializing with 0.")
            df[col] = 0

    # ── Build feature DataFrame ──────────────────────────────────────

    features_df = df[FIVE_TUPLE_COLS + BYTE_COLS].copy()

    # Clean byte columns: coerce non-numeric (null / '-' / None) to 0
    features_df["orig_bytes"] = (
        pd.to_numeric(features_df["orig_bytes"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )
    features_df["resp_bytes"] = (
        pd.to_numeric(features_df["resp_bytes"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )

    # Ensure port numbers are integers
    features_df["id.orig_p"] = (
        pd.to_numeric(features_df["id.orig_p"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )
    features_df["id.resp_p"] = (
        pd.to_numeric(features_df["id.resp_p"], errors="coerce")
        .fillna(0)
        .astype("int64")
    )

    # ── Exfiltration ratio ───────────────────────────────────────────

    logger.info("Calculating exfiltration_ratio: orig_bytes / (resp_bytes + 1)...")
    features_df["exfiltration_ratio"] = features_df["orig_bytes"] / (
        features_df["resp_bytes"] + 1.0
    )

    # ── TCP Flag Features from `history` column ──────────────────────

    if "history" in df.columns:
        logger.info("Parsing Zeek 'history' column for TCP flag counts...")
        # 'S' and 's' represent SYN packets (originator and responder)
        features_df["syn_flag_count"] = df["history"].apply(
            lambda h: count_flags(h, "Ss")
        )
        # 'A' and 'a' represent ACK packets (originator and responder)
        features_df["ack_flag_count"] = df["history"].apply(
            lambda h: count_flags(h, "Aa")
        )
    else:
        logger.warning(
            "Column 'history' not found in conn.log. "
            "TCP flag features will be initialized with 0. "
            "This severely degrades SYN flood detection."
        )
        features_df["syn_flag_count"] = 0
        features_df["ack_flag_count"] = 0

    # syn_ack_ratio: high ratio = SYN flood (many SYNs, few ACKs)
    features_df["syn_ack_ratio"] = features_df["syn_flag_count"] / (
        features_df["ack_flag_count"] + 1.0
    )

    # ── Temporal Flow Rate from `ts` column ──────────────────────────

    if "ts" in df.columns:
        logger.info(
            f"Computing flow_rate using {WINDOW_SECONDS}-second time windows "
            f"from 'ts' column..."
        )
        # Convert ts to numeric (Zeek timestamps are epoch floats)
        ts_numeric = pd.to_numeric(df["ts"], errors="coerce")

        if ts_numeric.isna().all():
            # Try parsing as datetime strings
            try:
                ts_dt = pd.to_datetime(df["ts"], errors="coerce")
                ts_numeric = ts_dt.astype("int64") / 1e9  # nanoseconds to seconds
            except Exception:
                logger.warning("Could not parse 'ts' as datetime. flow_rate = 0.")
                ts_numeric = pd.Series(0, index=df.index)

        # Assign each flow to a 5-second bucket
        ts_min = ts_numeric.min()
        bucket_ids = ((ts_numeric - ts_min) // WINDOW_SECONDS).fillna(0).astype("int64")

        # Count flows per bucket, then map back to each row
        bucket_counts = bucket_ids.value_counts()
        features_df["flow_rate"] = bucket_ids.map(bucket_counts).fillna(1).astype("int64")

        logger.info(
            f"  {bucket_counts.shape[0]} time buckets created. "
            f"flow_rate range: [{features_df['flow_rate'].min()}, "
            f"{features_df['flow_rate'].max()}]"
        )
    else:
        logger.warning(
            "Column 'ts' not found in conn.log. "
            "flow_rate will be initialized with 1. "
            "This severely degrades volumetric attack detection."
        )
        features_df["flow_rate"] = 1

    # ── Reorder and output ───────────────────────────────────────────

    features_df = features_df[FINAL_COLUMNS]

    # Save to CSV if specified
    if output_csv:
        logger.info(f"Saving {len(features_df):,} flows to '{output_csv}'...")
        save_start = time.time()
        features_df.to_csv(output_csv, index=False)
        output_size_mb = os.path.getsize(output_csv) / (1024 * 1024)
        logger.info(
            f"Successfully saved '{output_csv}' ({output_size_mb:.2f} MB) in "
            f"{time.time() - save_start:.2f} seconds."
        )

    return features_df


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Ingest Zeek conn.log JSON, extract 5-tuple, byte features, "
            "TCP flag counts from history, windowed flow_rate from ts, "
            "and compute exfiltration ratio."
        ),
    )
    parser.add_argument(
        "-i", "--input",
        dest="input_log",
        default="conn.log",
        help="Path to Zeek conn.log JSON file (default: conn.log)",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_csv",
        default="zeek_features_v2.csv",
        help="Path to output CSV file (default: zeek_features_v2.csv)",
    )
    args = parser.parse_args()

    try:
        df = parse_zeek_conn_log(log_path=args.input_log, output_csv=args.output_csv)
        print("\n--- Parsed Features Sample (First 5 Rows) ---")
        print(df.head())
        print(f"\nTotal Records Processed: {len(df):,}")
        print(f"Features Generated: {list(df.columns)}")
        print(f"\n--- Feature Statistics ---")
        print(df[ENGINEERED_COLS].describe().round(3))
    except Exception as e:
        logger.error(f"Error during ingestion: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
