#!/usr/bin/env python3
"""
FastAPI server for AI-IDS
Now supports:
 - File upload detection (/predict)
 - Live traffic capture using Scapy (start/stop)
 - Live status endpoint for frontend
"""

import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import tempfile
import os
import sys
import time
import pandas as pd
import numpy as np
import json

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from inference.live_predict import run_pipeline
from inference.live_capture_loop import start_capture, stop_capture, is_running, get_last_capture   # NEW IMPORT

app = FastAPI(
    title="AI_IDS Inference API",
    description="Network Intrusion Detection System with Binary, Multiclass & Anomaly Detection + Live Capture",
    version="3.0"
)

# ============================
# CORS CONFIG
# ============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("live/uploads")
OUTPUT_DIR = Path("live")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================
# HEALTH CHECK
# ============================
@app.get("/")
async def root():
    return {
        "status": "running",
        "service": "AI_IDS API",
        "endpoints": {
            "predict": "/predict",
            "start_live": "/start_live",
            "stop_live": "/stop_live",
            "live_status": "/live_status"
        }
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}

# ============================
# FILE UPLOAD PREDICTION
# ============================
@app.post("/predict")
async def predict(file: UploadFile = File(...)):

    print(f"\n[API] Received: {file.filename}")

    suffix = Path(file.filename).suffix.lower()
    is_pcap = suffix in [".pcap", ".pcapng"]
    is_csv = suffix == ".csv"

    if not (is_pcap or is_csv):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Upload .pcap/.pcapng/.csv only."
        )

    # ================================
    # SAVE FILE TO live/uploads/
    # ================================
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    save_path = UPLOAD_DIR / file.filename

    # If file with same name exists → append timestamp
    if save_path.exists():
        timestamp = int(time.time())
        save_path = UPLOAD_DIR / f"{timestamp}_{file.filename}"

    # Save the uploaded file permanently
    with open(save_path, "wb") as f_out:
        shutil.copyfileobj(file.file, f_out)

    file_size = save_path.stat().st_size

    # ================================
    # RUN PIPELINE
    # ================================
    out_csv = OUTPUT_DIR / f"predictions_{int(time.time())}.csv"

    try:
        df_out = run_pipeline(str(save_path), str(out_csv), is_pcap=is_pcap)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")

    # ================================
    # PREPARE RESPONSE
    # ================================
    label_counts = df_out["Label"].value_counts().to_dict()
    attack_types = (
        df_out[df_out["Label"] == "ATTACK"]["Attack_Type"].value_counts().to_dict()
        if "Attack_Type" in df_out.columns else {}
    )

    response = {
        "status": "success",
        "uploaded_file_path": str(save_path),
        "file_type": "pcap" if is_pcap else "csv",
        "filename": Path(save_path).name,
        "file_size_bytes": file_size,
        "total_flows": len(df_out),
        "summary": label_counts,
        "attack_types": attack_types,
        "download_csv": str(out_csv),
        "data_preview": df_out.head(10).to_dict(orient="records"),
        "all_flows": df_out.to_dict(orient="records")
    }

    return JSONResponse(content=response)

# ============================
# LEGACY ENDPOINTS
# ============================
@app.post("/predict_pcap")
async def predict_pcap(file: UploadFile = File(...)):
    return await predict(file)

@app.post("/analyze_pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Alias for /predict endpoint."""
    return await predict(file)

# ============================
# DOWNLOAD CSV
# ============================
@app.get("/download/{filename}")
async def download_csv(filename: str):
    file_path = OUTPUT_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(path=file_path, media_type="text/csv", filename=filename)

# ===========================================================
# 🔥 LIVE CAPTURE ENDPOINTS — NEW
# ===========================================================

@app.post("/start_live")
async def start_live():
    """Start background live packet capture."""
    start_capture()
    return {"status": "live_capture_started"}

@app.post("/stop_live")
async def stop_live():
    """Stop live capture."""
    stop_capture()
    return {"status": "live_capture_stopped"}

def replace_nan_with_none(obj):
    """Recursively replace NaN values with None for JSON serialization."""
    if isinstance(obj, dict):
        return {k: replace_nan_with_none(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_nan_with_none(item) for item in obj]
    elif isinstance(obj, (float, np.floating)):
        if pd.isna(obj) or np.isnan(obj):
            return None
        return obj
    elif isinstance(obj, (int, np.integer)):
        return int(obj)
    else:
        return obj

@app.get("/live_status")
async def live_status():
    """Return latest live IDS results with running state."""
    running = is_running()
    last_capture = get_last_capture()
    csv_path = OUTPUT_DIR / "live_predictions.csv"

    if not csv_path.exists():
        return {
            "running": running,
            "last_capture": last_capture,
            "flows": 0,
            "summary": {"BENIGN": 0, "ANOMALY": 0, "ATTACK": 0},
            "attack_types": {},
            "all_flows": []
        }

    df = pd.read_csv(csv_path)
    
    # Replace NaN values in dataframe with None for JSON serialization
    df = df.replace({np.nan: None, pd.NA: None})
    
    summary = df["Label"].value_counts().to_dict()
    
    # Ensure all keys exist
    result_summary = {
        "BENIGN": int(summary.get("BENIGN", 0)) if summary.get("BENIGN") is not None else 0,
        "ANOMALY": int(summary.get("ANOMALY", 0)) if summary.get("ANOMALY") is not None else 0,
        "ATTACK": int(summary.get("ATTACK", 0)) if summary.get("ATTACK") is not None else 0
    }

    # Get attack types breakdown
    attack_types = {}
    if "Attack_Type" in df.columns:
        attack_df = df[df["Label"] == "ATTACK"]
        if not attack_df.empty:
            attack_counts = attack_df["Attack_Type"].value_counts().to_dict()
            attack_types = {str(k): int(v) for k, v in attack_counts.items() if pd.notna(k) and pd.notna(v)}

    # Convert all flows to records and clean NaN values
    all_flows = df.replace({np.nan: None, pd.NA: None}).to_dict(orient="records")
    # Clean the records to ensure no NaN values remain
    all_flows = replace_nan_with_none(all_flows)

    response = {
        "running": running,
        "last_capture": last_capture,
        "flows": int(len(df)),
        "summary": result_summary,
        "attack_types": attack_types,
        "all_flows": all_flows
    }
    
    return response

# ===========================================================
# RUN SERVER
# ===========================================================
if __name__ == "__main__":
    print("=" * 70)
    print("AI_IDS FASTAPI SERVER (LIVE MODE ENABLED)")
    print("=" * 70)

    uvicorn.run(
        "api.api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
