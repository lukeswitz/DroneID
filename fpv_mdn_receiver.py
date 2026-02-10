#!/usr/bin/env python3
"""
MIT License

Copyright (c) 2025 Cemaxecuter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

"""
fpv_mdn_receiver.py

Connects to a specified serial port, receives JSON-like messages from an FPV detection sensor,
enriches them with GPS data from gpsd, and publishes via a ZMQ PUB socket for compatibility
with zmq_decoder.py.

Usage:
    python3 fpv_mdn_receiver.py --serial /dev/ttyACM0 --baud 115200 --zmq-port 4222 --stationary --debug
    python3 fpv_mdn_receiver.py --debug --log-file /var/log/fpv_receiver.log

Options:
    --serial              Path to the serial device (default: /dev/ACM0)
    --baud                Baud rate for serial communication (default: 115200)
    --zmq-port            ZMQ port to publish messages on (default: 4222)
    --stationary          If true, read GPS location only once at startup
                          (assumes the hardware is stationary).
    --debug               Enable debug output to console.
    --log-file            Path to save logs (default: no file logging)
    --tx-power            Transmission power in dBm (default: 27.8)
    --path-loss-exponent  Path loss exponent for distance estimation (default: 2.7)
    --adv-address         Advertising address for ZMQ decoder (default: 0x8e89bed6)
    --gpsd-host           GPSD host address (default: 127.0.0.1)
    --gpsd-port           GPSD port (default: 2947)
"""

import json
import logging
import math
import time
import argparse
import serial
import zmq
from gps3 import gps3
import sys
import signal
from datetime import datetime

# Defaults - all configurable via command line
DEFAULT_SERIAL_PORT = "/dev/ttyACM0"
DEFAULT_BAUD_RATE = 115200
DEFAULT_ZMQ_PORT = 4222
DEFAULT_GPSD_HOST = "127.0.0.1"
DEFAULT_GPSD_PORT = 2947
DEFAULT_TX_POWER_DBM = 27.8  
DEFAULT_PATH_LOSS_EXPONENT = 2.7
DEFAULT_ADV_ADDRESS = 0x8e89bed6
RECONNECT_DELAY = 5  # seconds

# Global cache to store detections 
detection_cache = {}

def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="FPV MDN Receiver: Reads JSON from serial, adds GPS, publishes via ZMQ."
    )
    parser.add_argument("--serial", default=DEFAULT_SERIAL_PORT,
                        help="Serial port to connect to.")
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD_RATE,
                        help="Baud rate for serial communication.")
    parser.add_argument("--zmq-port", type=int, default=DEFAULT_ZMQ_PORT,
                        help="ZMQ port to publish messages on.")
    parser.add_argument("--stationary", action="store_true",
                        help="If set, read GPS once at startup (assumes hardware is stationary).")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging.")
    parser.add_argument("--log-file", 
                        help="Path to log file for storing all log messages.")
    parser.add_argument("--tx-power", type=float, default=DEFAULT_TX_POWER_DBM,
                        help="Transmission power in dBm for distance estimation.")
    parser.add_argument("--path-loss-exponent", type=float, default=DEFAULT_PATH_LOSS_EXPONENT,
                        help="Path loss exponent for distance estimation.")
    parser.add_argument("--adv-address", type=lambda x: int(x, 0), default=DEFAULT_ADV_ADDRESS,
                        help="Advertising address for ZMQ decoder (in hex, e.g., 0x8e89bed6).")
    parser.add_argument("--gpsd-host", default=DEFAULT_GPSD_HOST,
                        help="GPSD host address.")
    parser.add_argument("--gpsd-port", type=int, default=DEFAULT_GPSD_PORT,
                        help="GPSD port.")
    return parser.parse_args()

def setup_logging(debug: bool, log_file: str = None):
    """
    Configures logging to console and optionally to a file.
    Debug mode shows more verbose logs on console, otherwise only warnings and errors.
    If log_file is specified, all logs are written to the file regardless of debug setting.
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

def init_gps_connection(host, port):
    """Initializes a persistent gpsd connection (socket + data_stream)."""
    gps_socket = gps3.GPSDSocket()
    data_stream = gps3.DataStream()
    try:
        gps_socket.connect(host=host, port=port)
        gps_socket.watch()
        logging.info("GPS connection established.")
    except Exception as e:
        logging.error("Failed to initialize GPS connection: %s", e)
        gps_socket, data_stream = None, None
    return gps_socket, data_stream

def get_gps_location(gps_socket, data_stream):
    """Fetches GPS coordinates from an already-connected gpsd socket (non-blocking)."""
    try:
        new_data = gps_socket.next()
        if new_data:
            data_stream.unpack(new_data)
            lat = data_stream.TPV.get('lat', 0.0)
            lon = data_stream.TPV.get('lon', 0.0)
            return lat, lon
    except Exception as e:
        logging.error("Error getting GPS location: %s", e)
    return 0.0, 0.0

def read_serial(serial_port, baud_rate):
    """Continuously attempts to connect and read from the serial port."""
    while True:
        try:
            with serial.Serial(serial_port, baud_rate, timeout=1) as ser:
                logging.info("Connected to %s at %d baud.", serial_port, baud_rate)
                while True:
                    line = ser.readline().decode("utf-8", errors="replace").strip()
                    if line:
                        logging.debug("Raw data: %s", line)
                        yield line
        except serial.SerialException as e:
            logging.error("Serial connection error: %s. Reconnecting in %d seconds...", e, RECONNECT_DELAY)
            time.sleep(RECONNECT_DELAY)
        except Exception as e:
            logging.exception("Unexpected error while reading serial port: %s", e)
            time.sleep(RECONNECT_DELAY)

def estimate_distance(rssi, freq, tx_power_dbm, path_loss_exponent):
    """
    Estimates distance based on RSSI and frequency using the log-distance path loss model.
    All parameters are configurable.
    
    Args:
      rssi (float): Received Signal Strength Indicator in dBm
      freq (float): Frequency in Hz
      tx_power_dbm (float): Transmission power in dBm
      path_loss_exponent (float): Path loss exponent for the environment
      
    Returns:
      float: Estimated distance in meters, or None if calculation is not possible
    """
    try:
      # Validate inputs
      if freq <= 0:
        logging.warning("Invalid frequency value: %s Hz", freq)
        return None
      
      freq_mhz = freq
      if freq_mhz <= 0:
        logging.warning("Invalid frequency in MHz: %s", freq_mhz)
        return None
      
      # Calculate distance using the log-distance path loss model
      path_loss = tx_power_dbm - rssi
      free_space_loss = 20 * math.log10(freq_mhz) - 27.55
      distance_m = 10 ** ((path_loss - free_space_loss) / (10 * path_loss_exponent))
      
      # Sanity check on the result
      if distance_m < 0 or math.isinf(distance_m) or math.isnan(distance_m):
        logging.warning("Invalid distance calculation result: %s meters", distance_m)
        return None
      
      return distance_m
    
    except ValueError as e:
      logging.warning("Math domain error in distance calculation: %s", e)
      return None
    except Exception as e:
      logging.error("Error calculating distance: %s", e)
      return None
    

def format_for_zmq_decoder(processed_msg, adv_address):
  """
  Format the message to be compatible with zmq_decoder's expected input format.
  For each detection, creates a properly formatted message that zmq_decoder can process.
  The advertising address is configurable.
  """
  formatted_msg = {
    "AUX_ADV_IND": {
      "rssi": processed_msg.get("rssi", 0),
      "aa": adv_address,
      "time": iso_timestamp_now()
    },
    "aext": {
      "AdvA": f"{processed_msg.get('source_inst', '')}-{processed_msg.get('source_node', '')} random"
    }
  }
  
  # Add drone detection specific data for both NEW CONTACT LOCK and LOCK UPDATE
  if processed_msg.get("message_type") == "nodeAlert" and ("NEW CONTACT LOCK" in processed_msg.get("status", "") or 
                              "LOCK UPDATE" in processed_msg.get("status", "")):
    # Example OpenDroneID header
    formatted_msg["AdvData"] = "020116faff0d01" 
  
    # Add GPS coordinates if available
    if "gps_lat" in processed_msg and "gps_lon" in processed_msg:
      formatted_msg["location"] = {
        "lat": processed_msg["gps_lat"],
        "lon": processed_msg["gps_lon"]
      }
      
    # Add additional data if available
    if "distance_m" in processed_msg and processed_msg["distance_m"] is not None:
      formatted_msg["distance"] = processed_msg["distance_m"]
      
    # Add frequency data
    if "freq" in processed_msg and processed_msg["freq"] is not None:
      formatted_msg["frequency"] = processed_msg["freq"]
      
  return formatted_msg
def process_fpv_message(data):
    """
    Process an FPV MDN message based on the format in the documentation:
    Format: {"from":{"inst":"XX","node":"XXXX"},"to":{"inst":"XX","node":"XXXX"},"msg":{...}}
    """
    try:
        # Extract message components based on the documented format
        from_info = data.get("from", {})
        to_info = data.get("to", {})
        msg_info = data.get("msg", {})
        
        if not from_info or not msg_info:
            logging.warning("Incomplete message format received")
            return {}
        
        source_inst = from_info.get("inst", "")
        source_node = from_info.get("node", "")
        
        # Extract message fields based on documented format
        msg_type = msg_info.get("type", "")
        msg_time = msg_info.get("time", 0)
        msg_freq = msg_info.get("freq", 0)
        msg_rssi = msg_info.get("rssi", 0)
        msg_stat = msg_info.get("stat", "")
        
        # Process command messages
        if msg_type == "nodeCmd":
            cmd = msg_info.get("cmd", "")
            var = msg_info.get("var", "")
            data_val = msg_info.get("data", 0)
            logging.debug(f"Command message: {cmd}, var: {var}, data: {data_val}")
        
        processed = {
            "source_inst": source_inst,
            "source_node": source_node,
            "message_type": msg_type,
            "time": msg_time,
            "rssi": msg_rssi,
            "freq": msg_freq,
            "status": msg_stat,
            "var": msg_info.get("var", ""),
            "data": msg_info.get("data", 0)
        }

        return processed
    except Exception as e:
        logging.error("Error processing FPV message: %s", e)
        return {}

def signal_handler(sig, frame):
    logging.info("Signal %s received, exiting...", sig)
    sys.exit(0)

def main():
    args = parse_args()
    setup_logging(args.debug, args.log_file)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Log startup information
    logging.info("FPV MDN Receiver starting up")
    logging.info(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    logging.info(f"Log file: {args.log_file if args.log_file else 'None'}")

    # Initialize GPS connection and cache location if stationary
    gps_socket, data_stream = None, None
    lat_cache, lon_cache = 0.0, 0.0

    if not args.stationary:
        gps_socket, data_stream = init_gps_connection(args.gpsd_host, args.gpsd_port)
    else:
        gps_socket, data_stream = init_gps_connection(args.gpsd_host, args.gpsd_port)
        if gps_socket and data_stream:
            lat_cache, lon_cache = get_gps_location(gps_socket, data_stream)
            gps_socket.close()
            gps_socket, data_stream = None, None
        else:
            logging.error("GPS initialization failed in stationary mode. Using default coordinates.")

    # Setup ZMQ PUB socket for compatibility with zmq_decoder
    context = zmq.Context()
    zmq_socket = context.socket(zmq.PUB)
    zmq_socket.setsockopt(zmq.SNDHWM, 1000)  # High-water mark for buffering
    zmq_socket.setsockopt(zmq.LINGER, 0)      # Ensure clean socket shutdown
    zmq_endpoint = f"tcp://0.0.0.0:{args.zmq_port}"
    try:
        zmq_socket.bind(zmq_endpoint)
        logging.info("ZMQ PUB socket bound to %s", zmq_endpoint)
    except zmq.ZMQError as e:
        logging.error("Failed to bind ZMQ socket: %s", e)
        sys.exit(1)

    try:
        # Process and publish messages continuously from the serial port.
        for line in read_serial(args.serial, args.baud):
            try:
                raw_data = json.loads(line)
            except json.JSONDecodeError:
                logging.warning("Failed to parse JSON: %s", line)
                continue

            # Use the specific message parser based on the documented format
            processed_msg = process_fpv_message(raw_data)
            if not processed_msg:
                continue

            # Handle message types and log details
            message_type = processed_msg.get("message_type", "")
            status = processed_msg.get("status", "")
            
            if message_type == "nodeMsg":
                if "NODE_START" in status:
                    logging.info("Boot message received from node %s (inst %s): %s",
                                 processed_msg["source_node"], processed_msg["source_inst"], status)
                elif "CALIBRATION COMPLETE" in status:
                    logging.info("Calibration complete from node %s (inst %s): %s",
                                 processed_msg["source_node"], processed_msg["source_inst"], status)
                else:
                    logging.debug("nodeMsg from node %s (inst %s): %s",
                                  processed_msg["source_node"], processed_msg["source_inst"], status)
            elif message_type == "nodeAlert":
                if "NEW CONTACT LOCK" in status:
                    logging.warning("New FPV Drone detected from node %s (inst %s)!",
                                    processed_msg["source_node"], processed_msg["source_inst"])
                elif "LOCK UPDATE" in status:
                    logging.info("Lock update from node %s (inst %s).",
                                 processed_msg["source_node"], processed_msg["source_inst"])
                elif "LOST CONTACT LOCK" in status:
                    logging.warning("Lost contact lock from node %s (inst %s).",
                                    processed_msg["source_node"], processed_msg["source_inst"])
                else:
                    logging.debug("nodeAlert from node %s (inst %s): %s",
                                  processed_msg["source_node"], processed_msg["source_inst"], status)
                if processed_msg.get("rssi") is not None:
                    logging.debug("RSSI: %s, Frequency: %s",
                                  processed_msg.get("rssi"), processed_msg.get("freq"))
            elif message_type == "nodeCmd":
                logging.debug("Command message received for node %s (inst %s): var=%s, data=%s",
                              processed_msg["source_node"], processed_msg["source_inst"],
                              processed_msg.get("var"), processed_msg.get("data"))

            # Update GPS location if applicable
            if not args.stationary and gps_socket and data_stream:
                current_lat, current_lon = get_gps_location(gps_socket, data_stream)
                lat, lon = current_lat, current_lon
            else:
                lat, lon = lat_cache, lon_cache

            # Attach GPS coordinates to the processed message
            processed_msg["gps_lat"] = lat
            processed_msg["gps_lon"] = lon

            # Calculate distance estimation if applicable
            if processed_msg.get("rssi") is not None and processed_msg.get("freq") is not None:
                processed_msg["distance_m"] = estimate_distance(
                    processed_msg["rssi"], 
                    processed_msg["freq"], 
                    args.tx_power, 
                    args.path_loss_exponent
                )

            # Format message to be compatible with zmq_decoder expectations
            zmq_formatted_msg = format_for_zmq_decoder(processed_msg, args.adv_address)

            # Also prepare a drone detection message for FPV detections using values from the message
            if message_type == "nodeAlert":
              source_key = f"{processed_msg['source_inst']}-{processed_msg['source_node']}"
              
              # Initialize or update detection data
              if source_key not in detection_cache or "NEW CONTACT LOCK" in status:
                # New detection - create full data structure
                detection_cache[source_key] = {
                  "timestamp": iso_timestamp_now(),
                  "manufacturer": processed_msg.get("source_inst", ""),
                  "device_type": f"FPV{processed_msg.get('freq', 0):.1f}MHz",
                  "frequency": processed_msg.get("freq", 0),
                  "bandwidth": processed_msg.get("var", ""),
                  "signal_strength": processed_msg.get("rssi", 0),
                  "detection_source": source_key
                }
              else:
                # Update only changed fields
                detection_cache[source_key]["timestamp"] = iso_timestamp_now()
                detection_cache[source_key]["signal_strength"] = processed_msg.get("rssi", 0)
                
                if processed_msg.get("freq") is not None:
                  detection_cache[source_key]["frequency"] = processed_msg.get("freq")
                  detection_cache[source_key]["device_type"] = f"FPV{processed_msg.get('freq', 0):.1f}MHz"
                  
              # Always update these fields
              detection_cache[source_key]["status"] = status
              
              # Update distance if available
              if processed_msg.get("distance_m") is not None:
                detection_cache[source_key]["estimated_distance"] = processed_msg["distance_m"]
                
              # Update GPS if available
              if lat != 0.0 or lon != 0.0:
                detection_cache[source_key]["sensor_lat"] = lat
                detection_cache[source_key]["sensor_lon"] = lon
                
              # Create and publish the detection message
              detection_messages = [{"FPV Detection": detection_cache[source_key]}]
              zmq_socket.send_string(json.dumps(detection_messages))
              logging.debug("Published drone detection message: %s", json.dumps(detection_messages))
              
              # Clean up cache if contact is lost
              if "LOST CONTACT LOCK" in status:
                detection_cache.pop(source_key, None)
                
            # Publish the original message in zmq_decoder compatible format
            try:
                json_message = json.dumps(zmq_formatted_msg)
                zmq_socket.send_string(json_message)
                logging.debug("Published ZMQ message: %s", json_message)
            except Exception as e:
                logging.error("Error publishing message via ZMQ: %s", e)
                
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received. Shutting down...")
    except Exception as e:
        logging.exception("Unexpected error in main loop: %s", e)
    finally:
        # Clean up and close resources gracefully
        try:
            zmq_socket.close(0)
            context.term()
            logging.info("ZMQ socket and context terminated.")
        except Exception as e:
            logging.error("Error during ZMQ cleanup: %s", e)
        if gps_socket:
            try:
                gps_socket.close()
            except Exception as e:
                logging.error("Error closing GPS socket: %s", e)
        logging.info("Shutdown complete.")

if __name__ == "__main__":
    main()
  