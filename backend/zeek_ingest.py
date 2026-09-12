#!/usr/bin/env python3
"""
zeek_ingest.py — Network Traffic Ingestion from Zeek conn.log (JSON)

Replaces packet-level Scapy sniffing with flow-level Zeek log ingestion.
Parses the 5-tuple flow characteristics, extracts payload byte metrics,
computes the exfiltration ratio, and saves the output features to CSV.

Features extracted:
  - id.orig_h: Source IP address
  - id.resp_h: Destination IP address
  - id.orig_p: Source port number
  - id.resp_p: Destination port number
  - proto: Transport layer protocol (e.g. tcp, udp, icmp)
  - orig_bytes: Originator payload bytes
  - resp_bytes: Responder payload bytes
  - exfiltration_ratio: orig_bytes / (resp_bytes + 1)
"""

import argparse
import logging
import os
import sys
import time
from typing import Optional

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

FINAL_COLUMNS = FIVE_TUPLE_COLS + BYTE_COLS + ["exfiltration_ratio"]


def parse_zeek_conn_log(
    log_path: str = "conn.log",
    output_csv: Optional[str] = "zeek_features.csv",
) -> pd.DataFrame:
    """Parse a Zeek conn.log JSON file and extract flow features.

    Parameters
    ----------
    log_path : str
        Path to the Zeek conn.log JSON file. Defaults to 'conn.log'.
    output_csv : Optional[str]
        Path to save the resulting CSV file. If None, CSV is not written.
        Defaults to 'zeek_features.csv'.

    Returns
    -------
    pd.DataFrame
        Parsed DataFrame containing the 5-tuple, byte counts, and
        exfiltration_ratio.
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

    # Extract relevant columns
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

    # Ensure port numbers are integers where possible
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

    # Calculate exfiltration_ratio = orig_bytes / (resp_bytes + 1)
    logger.info("Calculating exfiltration_ratio: orig_bytes / (resp_bytes + 1)...")
    features_df["exfiltration_ratio"] = features_df["orig_bytes"] / (
        features_df["resp_bytes"] + 1.0
    )

    # Reorder columns explicitly
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
        description="Ingest Zeek conn.log JSON, extract 5-tuple and byte features, and compute exfiltration ratio."
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="input_log",
        default="conn.log",
        help="Path to Zeek conn.log JSON file (default: conn.log)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_csv",
        default="zeek_features.csv",
        help="Path to output CSV file (default: zeek_features.csv)",
    )
    args = parser.parse_args()

    try:
        df = parse_zeek_conn_log(log_path=args.input_log, output_csv=args.output_csv)
        print("\n--- Parsed Features Sample (First 5 Rows) ---")
        print(df.head())
        print(f"\nTotal Records Processed: {len(df):,}")
        print(f"Features Generated: {list(df.columns)}")
    except Exception as e:
        logger.error(f"Error during ingestion: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
