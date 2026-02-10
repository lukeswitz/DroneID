#!/usr/bin/env python3
"""
fpv_receiver.py
cemaxecuter 2025

Connects to AntSDR, monitors for FPV drone detection events,
processes the detection information, and publishes it via ZMQ.

Usage:
    python3 fpv_receiver.py [--debug] [--log-file LOG_FILE]

Options:
    -d, --debug     Enable debug output to console
    -l, --log-file  Path to save logs (default: no file logging)

Default Behavior:
    - Prints only warnings and errors to the console if --debug is not specified.
    - Publishes the processed FPV detection data on tcp://127.0.0.1:4220 by default.
"""

import socket
import re
import json
import logging
import zmq
import time
import argparse
from datetime import datetime

# Hardcoded configuration
ANTSDR_IP = "172.31.100.2"
ANTSDR_PORT = 41030
ZMQ_PUB_IP = "127.0.0.1"
ZMQ_PUB_PORT = 4220  # Port to serve FPV receiver data

# Detection pattern to match various drone detection formats
DETECTION_PATTERN = r"\[INFO\].*?\+(.*?)\(([^)]+)\)\+([\d.-]+)\+([-\d.]+)"

def parse_args():
    """
    Parses command-line arguments.
    Returns an object with 'debug' and 'log_file' options.
    """
    parser = argparse.ArgumentParser(description="FPV Receiver: Monitor and publish drone detection events.")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug messages and logging output.")
    parser.add_argument("-l", "--log-file", 
                        help="Path to log file for storing all log messages.")
    return parser.parse_args()

def setup_logging(debug: bool, log_file: str = None):
    """
    Configures logging to console and optionally to a file.
    Debug mode shows more verbose logs on console, otherwise only warnings and errors.
    If log_file is specified, all logs are written to the file regardless of debug setting.

    Args:
        debug (bool): If True, set console log level to DEBUG. Else, WARNING.
        log_file (str, optional): Path to a log file. If provided, all logs are written here.
    """
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture all logs
    root_logger.handlers = []  # Clear existing handlers
    
    # Format for all handlers
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    
    # Console handler - level depends on debug flag
    console_level = logging.DEBUG if debug else logging.WARNING
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler - always DEBUG level if enabled
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='a')  # Append mode
            file_handler.setLevel(logging.DEBUG)  # All logs go to file
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            logging.info(f"Log file initialized: {log_file}")
        except (PermissionError, FileNotFoundError) as e:
            logging.error(f"Failed to create log file at {log_file}: {e}")
            logging.warning("Continuing with console logging only")

def iso_timestamp_now() -> str:
    """Return current UTC time as an ISO8601 string with 'Z' suffix."""
    return time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())

def parse_detection_info(line: str) -> dict:
    """
    Parse a drone detection log line.
    Flexibly extracts information using regex pattern matching.
    """
    match = re.search(DETECTION_PATTERN, line)
    if not match:
        return {}
    
    try:
        # Extract basic information - be flexible with the format
        model_info = match.group(1).strip()
        bandwidth = match.group(2).strip()
        frequency = float(match.group(3).strip())
        signal_strength = float(match.group(4).strip())
        
        # Determine the manufacturer from the model info
        if "DJI" in line:
            manufacturer = "DJI"
        else:
            manufacturer = "Unknown"
        
        return {
            "timestamp": iso_timestamp_now(),
            "manufacturer": manufacturer,
            "model": model_info,
            "bandwidth": bandwidth,
            "frequency_mhz": frequency,
            "signal_strength_dbm": signal_strength
        }
    except (ValueError, IndexError) as e:
        logging.error(f"Failed to parse detection info: {e}, line: {line}")
        return {}

def format_as_zmq_json(parsed_data: dict) -> list:
    """
    Formats the parsed data into a ZMQ-compatible list of messages.
    """
    if not parsed_data:
        return []  # Empty list if parsing failed
    
    message_list = []
    
    # Create FPV Detection Message
    fpv_detection_message = {
        "FPV Detection": {
            "timestamp": parsed_data["timestamp"],
            "manufacturer": parsed_data["manufacturer"],
            "device_type": parsed_data["model"],
            "frequency": parsed_data["frequency_mhz"],
            "bandwidth": parsed_data["bandwidth"],
            "signal_strength": parsed_data["signal_strength_dbm"],
            "detection_source": "AntSDR"
        }
    }
    message_list.append(fpv_detection_message)
    
    return message_list

def send_zmq_message(zmq_pub_socket: zmq.Socket, message_list: list):
    """
    Sends the ZMQ JSON-formatted message.
    Logs debug info if in debug mode.

    Args:
        zmq_pub_socket (zmq.Socket): The PUB socket to publish to.
        message_list (list): The list of message dictionaries to convert to JSON.
    """
    try:
        json_message = json.dumps(message_list)
        zmq_pub_socket.send_string(json_message)
        logging.debug(f"Sent JSON via ZMQ: {json_message}")
    except Exception as e:
        logging.error(f"Failed to send JSON via ZMQ: {e}")

def tcp_client():
    """
    Connects to AntSDR via TCP, monitors for FPV detection events,
    and publishes the processed data as a ZMQ stream.
    """
    context = zmq.Context()
    zmq_pub_socket = context.socket(zmq.PUB)  # Regular PUB socket
    zmq_pub_socket.bind(f"tcp://{ZMQ_PUB_IP}:{ZMQ_PUB_PORT}")
    logging.info(f"ZMQ PUB socket bound to tcp://{ZMQ_PUB_IP}:{ZMQ_PUB_PORT}")

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((ANTSDR_IP, ANTSDR_PORT))
                logging.info(f"Connected to AntSDR at {ANTSDR_IP}:{ANTSDR_PORT}")

                buffer = ""
                while True:
                    # Read data from socket
                    data = client_socket.recv(1024)
                    if not data:
                        logging.warning("Connection closed by AntSDR.")
                        break
                    
                    # Decode and add to buffer
                    buffer += data.decode('utf-8', errors='replace')
                    
                    # Process complete lines
                    lines = buffer.split('\n')
                    # Keep the last partial line in the buffer
                    buffer = lines.pop(-1) if lines else ""
                    
                    for line in lines:
                        if "[INFO]" in line and "+" in line:
                            logging.debug(f"Potential detection entry: {line}")
                            parsed_data = parse_detection_info(line)
                            if parsed_data:
                                zmq_message_list = format_as_zmq_json(parsed_data)
                                if zmq_message_list:
                                    send_zmq_message(zmq_pub_socket, zmq_message_list)

        except (ConnectionRefusedError, socket.error) as e:
            logging.error(f"Connection error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
            continue
        except Exception as e:
            logging.error(f"Unexpected error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
            continue

def main():
    args = parse_args()
    setup_logging(args.debug, args.log_file)
    
    # Log startup information
    logging.info("FPV Drone Detection Receiver starting up")
    logging.info(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    logging.info(f"Log file: {args.log_file if args.log_file else 'None'}")
    
    tcp_client()

if __name__ == "__main__":
    main()