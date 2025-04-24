#!/usr/bin/env python3
# (c) 2024 B.Kerler
import json
import sys
import time
import zmq
import argparse
import serial
from threading import Thread
from OpenDroneID.decoder import decode_ble, decode
from OpenDroneID.utils import structhelper_io

verbose = False  # Global variable to control verbosity
stop = False


def log(*msg):
    """Logs messages to stderr if verbose is enabled."""
    global verbose
    if verbose:
        s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"{s}:", *msg, end="\n", file=sys.stderr)


def zmq_thread(pub_socket):
    """Handles ZMQ subscriber notifications."""
    global stop
    try:
        while not stop:
            try:
                # Use recv_multipart to handle potential multi-part messages
                # from XPUB_VERBOSE, though typically it's single part.
                event_parts = pub_socket.recv_multipart()
                if not event_parts:
                    continue
                event = event_parts[0]
                if verbose:
                    # Subscription messages have the topic in the second part
                    topic = event_parts[1] if len(event_parts) > 1 else b""
                    if event[0] == 1:
                        log("New subscriber for topic:", topic.decode(errors="ignore"))
                    elif event[0] == 0:
                        log("Unsubscribed from topic:", topic.decode(errors="ignore"))
            except zmq.error.ContextTerminated:
                break
            except Exception as e:
                log("ZMQ Thread Error:", e)
    except zmq.error.ContextTerminated:
        pass


def decoder_thread(socket, pub):
    """Handles Bluetooth/Wi-Fi OpenDroneID messages and FPV messages."""
    global stop
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    try:
        while not stop:
            socks = dict(poller.poll(3000))  # Poll every 3 seconds
            if socket in socks and socks[socket] == zmq.POLLIN:
                try:
                    # Receive as bytes first
                    data_bytes = socket.recv()
                    if not data_bytes:
                        continue
                    # Decode to string for JSON parsing
                    data_str = data_bytes.decode("utf-8")
                except zmq.error.ZMQError as e:
                    if verbose:
                        log("Receive Error:", e)
                    continue
                except UnicodeDecodeError as e:
                    if verbose:
                        log("Unicode Decode Error:", e, "Data:", data_bytes[:100]) # Log partial data
                    continue
                
                if data_str:
                    try:
                        dc = json.loads(data_str)
                    except json.JSONDecodeError as e:
                        if verbose:
                            log("JSON Decode Error:", e, "Data:", data_str[:200]) # Log partial data
                        continue
                    
                    if verbose:
                        # Use try-except for cleaner verbose logging in case dc is not dict/list
                        try:
                            log("ZMQ Data Received:", json.dumps(dc, indent=2))
                        except TypeError:
                            log("ZMQ Data Received (raw):", data_str)
                            
                    # Check for the specific FPV Detection message format first
                    # Format: [{"FPV Detection": {...}}]
                    is_fpv_detection = False
                    
                    # Handle array format for FPV Detection
                    if isinstance(dc, list) and len(dc) > 0 and isinstance(dc[0], dict) and "FPV Detection" in dc[0]:
                        is_fpv_detection = True
                        log("Received FPV Detection message structure.")
                        if pub:
                            pub.send_string(data_str)
                            log("Forwarded FPV Detection message via ZMQ PUB.")
                        continue # Skip OpenDroneID processing
                    
                    # Handle direct FPV Update format
                    if isinstance(dc, dict) and "AUX_ADV_IND" in dc and "aext" in dc:
                        aext = dc.get("aext", {})
                        if "AdvA" in aext and "-" in aext["AdvA"] and "random" in aext["AdvA"]:
                            is_fpv_detection = True
                            log("Received FPV Update message structure.")
                            if pub:
                                pub.send_string(data_str)
                                log("Forwarded FPV Update message via ZMQ PUB.")
                            continue # Skip OpenDroneID processing
                        
                    # Process potential OpenDroneID Bluetooth/Wi-Fi data only if not FPV
                    if not is_fpv_detection:
                        process_decoded_data(dc, pub)
                        
    except zmq.error.ContextTerminated:
        pass
    except Exception as e:
        if verbose:
            log("Decoder Thread Error:", e)


def uart_listener(uart_device, pub):
    global stop, verbose
    buffer = ""
    decoder = json.JSONDecoder()
    while not stop:
        try:
            with serial.Serial(uart_device, baudrate=115200, timeout=1) as ser:
                log(f"UART connected to {uart_device}")
                while not stop:
                    if ser.in_waiting > 0:
                        try:
                            data_bytes = ser.read(ser.in_waiting)
                            data = data_bytes.decode("utf-8", errors="replace")
                            buffer += data
                            
                            while True:
                                # Find start of potential JSON object
                                start_idx = buffer.find('{')
                                if start_idx == -1:
                                    # No JSON found, trim buffer if too large
                                    if len(buffer) > 4096:
                                        buffer = ""
                                    break
                                
                                # Attempt to parse from start position
                                try:
                                    obj, end_idx = decoder.raw_decode(buffer[start_idx:])
                                    full_idx = start_idx + end_idx
                                    
                                    # Validate Basic ID structure
                                    if isinstance(obj, dict) and "Basic ID" in obj:
                                        if pub:
                                            pub.send_string(json.dumps(obj))
                                        if verbose:
                                            log(f"UART Forwarded: {json.dumps(obj)}")
                                            
                                    # Remove processed data from buffer
                                    buffer = buffer[full_idx:]
                                    
                                    # Check if more data remains
                                    if not buffer.strip():
                                        break
                                    
                                except json.JSONDecodeError as e:
                                    # Handle incomplete JSON at end of buffer
                                    if e.msg == "Unterminated string starting at":
                                        # Preserve the unterminated string
                                        buffer = buffer[start_idx:]
                                    else:
                                        # Skip invalid JSON prefix
                                        buffer = buffer[start_idx+1:]
                                    break
                                except Exception as e:
                                    log(f"UART Processing Error: {e}")
                                    buffer = buffer[start_idx+1:]
                                    break
                                
                            # Prevent buffer overflow
                            if len(buffer) > 65536:
                                buffer = buffer[-32768:]
                                
                        except serial.SerialException as e:
                            log(f"UART Read/Serial Error: {e}")
                            buffer = ""
                            break
                        except Exception as e:
                            log(f"UART Processing Unexpected Error: {e}")
                            buffer = ""
                    else:
                        time.sleep(0.1)
                        
        except serial.SerialException as e:
            log(f"Failed to open UART {uart_device}: {e}. Retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            log(f"Unexpected UART Error: {e}. Retrying in 5s...")
            time.sleep(5)
            
            

def dji_listener(dji_url, pub):
    """Subscribes to DJI Receiver and forwards data as-is."""
    global stop
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all messages
    # Set linger to 0 to avoid blocking on close
    socket.setsockopt(zmq.LINGER, 0)
    # Set reconnect interval
    socket.setsockopt(zmq.RECONNECT_IVL, 1000) # ms
    socket.setsockopt(zmq.RECONNECT_IVL_MAX, 5000) # ms

    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    while not stop:
        try:
            log(f"Attempting to connect to DJI Receiver at {dji_url}")
            socket.connect(f"tcp://{dji_url}")
            log(f"Connected to DJI Receiver at {dji_url}")

            while not stop:
                socks = dict(poller.poll(3000))  # Poll every 3 seconds
                if socket in socks and socks[socket] == zmq.POLLIN:
                    try:
                        data = socket.recv_string()
                        if pub:
                            pub.send_string(data)  # Forward raw DJI data
                        if verbose:
                            log(f"DJI Data Forwarded: {data[:200]}...") # Log partial data
                    except zmq.ZMQError as e:
                        log(f"DJI ZMQ Receive Error: {e}")
                        # If error is EAGAIN, just continue polling
                        if e.errno == zmq.EAGAIN:
                            continue
                        else:
                            # For other errors, maybe break to reconnect
                            log(f"Breaking DJI inner loop due to ZMQ error: {e}")
                            break
                    except Exception as e:
                         log(f"DJI processing error: {e}")
                         continue # Continue loop on other errors
                # Check stop flag periodically even if no messages
                if stop: break

        except zmq.error.ZMQError as e:
            log(f"Error connecting/binding DJI Receiver at {dji_url}: {e}")
            # Wait before retrying connection
            for _ in range(5):
                 if stop: break
                 time.sleep(1)
        except Exception as e:
            log(f"Unexpected error in DJI listener setup: {e}")
            for _ in range(5):
                 if stop: break
                 time.sleep(1)
        finally:
            # Ensure disconnection before attempting reconnection
            try:
                socket.disconnect(f"tcp://{dji_url}")
                log(f"Disconnected from DJI Receiver at {dji_url}")
            except zmq.ZMQError as e:
                 # Ignore errors during disconnect, e.g., if already disconnected
                 pass
            # Wait a bit before retrying the connection in the outer loop
            if not stop:
                time.sleep(RECONNECT_DELAY) # Use a defined delay

    # Final cleanup
    log("Closing DJI listener socket.")
    socket.close()
    # context.term() # Context termination is handled in main


def process_decoded_data(dc, pub):
    """Processes and forwards various types of decoded data."""
    processed = False
    
    # FPV Detection Processing
    if "FPV Detection" in dc:
        try:
            fpv_data = dc["FPV Detection"]
            fpv_json = json.dumps({
                "FPV Detection": {
                    "timestamp": fpv_data.get("timestamp", ""),
                    "manufacturer": fpv_data.get("manufacturer", ""),
                    "device_type": fpv_data.get("device_type", ""),
                    "frequency": fpv_data.get("frequency", ""),
                    "bandwidth": fpv_data.get("bandwidth", ""),
                    "signal_strength": fpv_data.get("signal_strength", 0.0),
                    "detection_source": fpv_data.get("detection_source", "")
                }
            })
            
            if pub:
                pub.send_string(fpv_json)
            if verbose:
                print("FPV Detection:\n-------------------------")
                print(fpv_json)
                print()
            sys.stdout.flush()
            processed = True
        except Exception as e:
            log("FPV Detection Processing Error:", e)
            
    # Bluetooth Open Drone ID Processing
    if "AUX_ADV_IND" in dc or "ADV_EXT_IND" in dc:
        try:
            # Handle messages with or without AdvData
            if "AdvData" in dc and dc["AdvData"]:
                try:
                    advdata = bytearray(bytes.fromhex(dc["AdvData"]))
                    if advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[4] == 0x0D:
                        if verbose:
                            print("Open Drone ID BT4/BT5\n-------------------------\n")
                        json_data = decode_ble(advdata)
                except ValueError:
                    # If AdvData can't be decoded, create a minimal message
                    json_data = json.dumps([{
                        "Basic ID": {
                            "MAC": dc.get("aext", {}).get("AdvA", "Unknown").split()[0],
                            "RSSI": dc.get("AUX_ADV_IND", {}).get("rssi", 0) or dc.get("ADV_EXT_IND", {}).get("rssi", 0)
                        }
                    }])
            else:
                # Create a minimal message for messages without AdvData
                json_data = json.dumps([{
                    "Basic ID": {
                        "MAC": dc.get("aext", {}).get("AdvA", "Unknown").split()[0],
                        "RSSI": dc.get("AUX_ADV_IND", {}).get("rssi", 0) or dc.get("ADV_EXT_IND", {}).get("rssi", 0),
                        "did": dc.get("aext", {}).get("AdvDataInfo", {}).get("did"),
                        "sid": dc.get("aext", {}).get("AdvDataInfo", {}).get("sid")
                    }
                }])
                
            # Enhance JSON with additional information
            try:
                json_obj = json.loads(json_data)
                if isinstance(json_obj, list) and len(json_obj) > 0:
                    for msg in json_obj:
                        if "Basic ID" in msg:
                            # Add additional context from message
                            if "aext" in dc and "AdvA" in dc["aext"]:
                                msg["Basic ID"]["MAC"] = dc["aext"]["AdvA"].split()[0]
                            if "AUX_ADV_IND" in dc:
                                msg["Basic ID"]["RSSI"] = dc["AUX_ADV_IND"]["rssi"]
                            elif "ADV_EXT_IND" in dc:
                                msg["Basic ID"]["RSSI"] = dc["ADV_EXT_IND"]["rssi"]
                json_data = json.dumps(json_obj)
            except json.JSONDecodeError:
                pass
                
            if pub:
                pub.send_string(json_data)
            if verbose:
                print(json_data)
                print()
            sys.stdout.flush()
            processed = True
        except Exception as e:
            log("Bluetooth Message Processing Error:", e)
            
    # Wi-Fi Open Drone ID Processing
    if "DroneID" in dc:
        for mac, field in dc["DroneID"].items():
            try:
                if verbose:
                    print("Open Drone ID WIFI\n-------------------------\n")
                    
                if "AUX_ADV_IND" in dc:
                    field["RSSI"] = dc["AUX_ADV_IND"]["rssi"]
                    
                if "AdvData" in field:
                    try:
                        fields = decode(structhelper_io(bytes.fromhex(field["AdvData"])))
                        for field_decoded in fields:
                            field_decoded["MAC"] = mac
                            
                            if "AUX_ADV_IND" in dc:
                                field_decoded["RSSI"] = dc["AUX_ADV_IND"]["rssi"]
                                
                            json_data = json.dumps(field_decoded)
                            if pub:
                                pub.send_string(json_data)
                            if verbose:
                                print(json_data)
                    except Exception as e:
                        log("Decoding Error:", e)
                else:
                    try:
                        field["MAC"] = mac
                        json_data = json.dumps(field)
                        if pub:
                            pub.send_string(json_data)
                        if verbose:
                            print(json_data)
                    except Exception as e:
                        log("JSON Dump Error:", e)
                        
                if verbose:
                    print()
                sys.stdout.flush()
                processed = True
            except Exception as e:
                log("Wi-Fi Message Processing Error:", e)
                
    # Log if no known message type was processed
    if not processed and verbose:
        log("Received message not matching known structures:", list(dc.keys()))
        
    return processed

def main():
    global stop, verbose, RECONNECT_DELAY # Make RECONNECT_DELAY accessible if needed elsewhere
    RECONNECT_DELAY = 5 # Define reconnect delay seconds

    info = "ZMQ decoder for BLE4/5 + WIFI + DJI ZMQ clients + FPV (c) B.Kerler 2024"
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable ZMQ PUB output")
    aparse.add_argument("-v", "--verbose", action="store_true", help="Print decoded messages and logs")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4224", help="Define ZMQ PUB server bind address (e.g., 0.0.0.0:4224)")
    aparse.add_argument("--zmqclients", default="127.0.0.1:4222,127.0.0.1:4223", help="Define Bluetooth/Wi-Fi/FPV ZMQ client endpoints (comma-separated)")
    aparse.add_argument("--uart", help="UART device for pre-decoded ESP32 data (e.g., /dev/ttyACM0)")
    aparse.add_argument("--dji", help="DJI receiver ZMQ endpoint (e.g., 127.0.0.1:4221)")
    args = aparse.parse_args()

    verbose = args.verbose

    # Initialize a single ZMQ context
    sctx = zmq.Context()
    pub = None
    zthread = None
    uart_thread = None
    dji_thread = None
    subs = [] # List to hold decoder threads

    if args.zmq:
        try:
            pub = sctx.socket(zmq.XPUB)
            # Enable verbose mode on XPUB to see subscriptions
            pub.setsockopt(zmq.XPUB_VERBOSE, 1)
            # Set LINGER to 0 for clean shutdown
            pub.setsockopt(zmq.LINGER, 0)
            purl = f"tcp://{args.zmqsetting}"
            pub.bind(purl)
            log(f"ZMQ PUB socket bound to {purl}")

            zthread = Thread(target=zmq_thread, args=(pub,), daemon=True, name="zmq_xpub_monitor")
            zthread.start()
        except zmq.ZMQError as e:
            log(f"Error setting up ZMQ PUB socket on {args.zmqsetting}: {e}")
            # Decide if you want to exit or continue without PUB
            log("Continuing without ZMQ PUB output.")
            pub = None
            zthread = None
        except Exception as e:
             log(f"Unexpected error setting up ZMQ PUB: {e}")
             pub = None
             zthread = None

    # Set up UART listener
    if args.uart:
        uart_thread = Thread(target=uart_listener, args=(args.uart, pub), daemon=True, name=f"uart-{args.uart}")
        uart_thread.start()
        log(f"Started UART listener thread for {args.uart}")

    # Set up DJI listener
    if args.dji:
        dji_thread = Thread(target=dji_listener, args=(args.dji, pub), daemon=True, name=f"dji-{args.dji}")
        dji_thread.start()
        log(f"Started DJI listener thread for {args.dji}")

    # Set up ZMQ client listeners (for BT/Wi-Fi/FPV)
    clients = args.zmqclients.split(",")
    for client in clients:
        client = client.strip() # Remove potential whitespace
        if not client: continue # Skip empty client strings

        url = f"tcp://{client}"
        try:
            sub = sctx.socket(zmq.SUB)
            # *** CHANGE: Subscribe to ALL messages ***
            sub.setsockopt(zmq.SUBSCRIBE, b"")
            # Set LINGER to 0
            sub.setsockopt(zmq.LINGER, 0)
             # Set reconnect interval
            sub.setsockopt(zmq.RECONNECT_IVL, 1000) # ms
            sub.setsockopt(zmq.RECONNECT_IVL_MAX, 5000) # ms

            sub.connect(url)
            log(f"Attempting to connect SUB socket to {url}")

            dthread = Thread(target=decoder_thread, args=(sub, pub), daemon=True, name=f"decoder-{client}")
            dthread.start()
            subs.append({"thread": dthread, "socket": sub, "url": url}) # Store socket for cleanup
            log(f"Started decoder thread for {url}")

        except zmq.error.ZMQError as e:
            log(f"Failed to connect SUB socket to {url}: {e}")
            # Clean up socket if connection failed
            if 'sub' in locals() and sub:
                sub.close()
        except Exception as e:
             log(f"Unexpected error setting up decoder for {url}: {e}")
             if 'sub' in locals() and sub:
                sub.close()


    log("Main thread running. Press Ctrl+C to stop.")
    try:
        # Keep main thread alive while daemon threads run
        while True:
            # Optional: Check thread health periodically
            all_threads = [zthread, uart_thread, dji_thread] + [s['thread'] for s in subs]
            alive_threads = [t.is_alive() for t in all_threads if t is not None]
            if not all(alive_threads) and any(alive_threads): # If some but not all died unexpectedly
                 log("Warning: One or more background threads have stopped.")
                 # You could add logic here to try and restart threads if desired
            if not any(alive_threads) and len(all_threads) > 0:
                 log("All background threads have stopped. Exiting.")
                 break # Exit main loop if all threads are gone

            time.sleep(5) # Check every 5 seconds

    except KeyboardInterrupt:
        log("Interrupt received, shutting down...")
    finally:
        log("Setting stop flag...")
        stop = True # Signal threads to stop

        log("Closing ZMQ sockets...")
        # Close SUB sockets first
        for sub_info in subs:
            log(f"Closing SUB socket for {sub_info['url']}...")
            sub_info["socket"].close()
        # Close PUB socket
        if pub:
            log("Closing PUB socket...")
            pub.close()

        log("Terminating ZMQ context...")
        sctx.term() # Terminate context after closing sockets

        log("Joining threads...")
        # Join threads after context termination
        if zthread:
            log("Joining ZMQ monitor thread...")
            zthread.join(timeout=2)
        if uart_thread:
            log("Joining UART thread...")
            uart_thread.join(timeout=2)
        if dji_thread:
            log("Joining DJI thread...")
            dji_thread.join(timeout=2)
        for i, sub_info in enumerate(subs):
            log(f"Joining decoder thread {i+1}...")
            sub_info["thread"].join(timeout=2)

        # Check if threads are still alive after join timeout
        all_threads = [zthread, uart_thread, dji_thread] + [s['thread'] for s in subs]
        for t in all_threads:
            if t is not None and t.is_alive():
                log(f"Warning: Thread {t.name} did not exit cleanly.")

        log("Shutdown complete.")

if __name__ == "__main__":
    main()
    