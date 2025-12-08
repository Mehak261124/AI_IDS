import threading
import time
from scapy.all import sniff, wrpcap
from inference.live_predict import run_pipeline
import pandas as pd
import os
from datetime import datetime

running = False
loop_thread = None
last_capture_file = None


def capture_once(duration=10):
    """Capture packets for fixed time & run IDS."""
    global running
    if not running:
        return None

    # Capture packets
    packets = sniff(timeout=duration)
    if len(packets) == 0 or not running:
        return None

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pcap_path = f"live/capture_{timestamp}.pcap"
    global last_capture_file
    last_capture_file = f"capture_{timestamp}.pcap"

    # Save packets with unique filename
    wrpcap(pcap_path, packets)

    # Check again before running heavy pipeline
    if not running:
        return None

    df = run_pipeline(pcap_path, "live/live_predictions.csv", is_pcap=True)
    return df

def background_loop():
    """Continuously capture flows until stopped."""
    global running
    running = True

    while running:
        df = capture_once(10)

        # Check flag again so loop breaks IMMEDIATELY
        if not running:
            break

        time.sleep(1)  # small gap to prevent CPU overload


def start_capture():
    global running, loop_thread

    if running:
        return  # Already running

    running = True
    loop_thread = threading.Thread(target=background_loop, daemon=True)
    loop_thread.start()
    return True


def stop_capture():
    global running, loop_thread
    running = False

    # OPTIONAL but clean: wait for thread to finish
    if loop_thread is not None and loop_thread.is_alive():
        loop_thread.join(timeout=1)

    return True

def is_running():
    """Check if capture is currently running."""
    return running

def get_last_capture():
    """Get the filename of the last capture file."""
    global last_capture_file
    return last_capture_file if last_capture_file else None
