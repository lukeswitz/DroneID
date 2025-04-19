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
    """Processes and forwards the decoded Bluetooth/Wi-Fi data."""
    # Ensure dc is a dictionary before proceeding with key checks
    if not isinstance(dc, dict):
        if verbose:
            log(f"Skipping processing, data is not a dictionary: {type(dc)}")
        return

    processed = False # Flag to track if any data was processed

    # --- Bluetooth OpenDroneID Processing ---
    if "AUX_ADV_IND" in dc:
        aux_adv_ind = dc.get("AUX_ADV_IND", {})
        # Check for the specific OpenDroneID Bluetooth advertising address (aa)
        # Make sure aa exists and is an integer before comparing
        if isinstance(aux_adv_ind.get("aa"), int) and aux_adv_ind["aa"] == 0x8e89bed6:
            if "AdvData" in dc:
                try:
                    advdata_hex = dc["AdvData"]
                    # Ensure AdvData is not empty or None
                    if not advdata_hex:
                         raise ValueError("AdvData is empty")
                    advdata = bytearray(bytes.fromhex(advdata_hex))
                    # ODID Service UUID check (0x16 = Service Data, 0xFFFA = ODID UUID, 0x0D = ODID AD Type)
                    if len(advdata) > 4 and advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[4] == 0x0D:
                        if verbose:
                            log("Processing Open Drone ID BT4/BT5...")
                        # Decode the BLE payload
                        decoded_list = decode_ble(advdata) # Returns a list of messages

                        # Add MAC Address and RSSI from the wrapper JSON
                        mac_address = None
                        rssi = aux_adv_ind.get("rssi") # Get RSSI safely

                        # Extract MAC from aext if available
                        aext = dc.get("aext", {})
                        if "AdvA" in aext:
                            # Take the first part of "XX:XX:XX:XX:XX:XX random"
                            mac_address = aext["AdvA"].split()[0]

                        # Add MAC and RSSI to each decoded message part
                        processed_messages = []
                        for msg_part in decoded_list:
                            if mac_address:
                                # Add MAC to Basic ID if present, otherwise add directly
                                if "Basic ID" in msg_part:
                                    msg_part["Basic ID"]["MAC"] = mac_address
                                else:
                                     msg_part["MAC"] = mac_address # Add top-level MAC if no BasicID
                            if rssi is not None:
                                 # Add RSSI to Basic ID if present, otherwise add directly
                                if "Basic ID" in msg_part:
                                    msg_part["Basic ID"]["RSSI"] = rssi
                                else:
                                     msg_part["RSSI"] = rssi # Add top-level RSSI if no BasicID
                            processed_messages.append(msg_part)

                        # Publish the potentially modified list as a single JSON string
                        if pub and processed_messages:
                            json_data = json.dumps(processed_messages)
                            pub.send_string(json_data)
                            if verbose:
                                log("Published BT ODID:", json_data)
                        processed = True # Mark as processed

                except ValueError as e:
                    log(f"AdvData Decode/Format Error (BT): {e}, Data: {dc.get('AdvData')}")
                except Exception as e:
                    log(f"Unexpected Error Processing BT ODID: {e}")

    # --- Wi-Fi OpenDroneID Processing ---
    elif "DroneID" in dc:
        drone_id_data = dc.get("DroneID", {})
        if isinstance(drone_id_data, dict): # Ensure it's a dictionary
            for mac, field in drone_id_data.items():
                 if isinstance(field, dict): # Ensure field is a dictionary
                    if verbose:
                        log(f"Processing Open Drone ID WIFI for MAC: {mac}...")

                    # Add RSSI if available in the wrapper JSON
                    rssi = None
                    if "AUX_ADV_IND" in dc and isinstance(dc["AUX_ADV_IND"], dict):
                        rssi = dc["AUX_ADV_IND"].get("rssi")

                    if "AdvData" in field:
                        try:
                            advdata_hex = field["AdvData"]
                            if not advdata_hex:
                                raise ValueError("AdvData is empty")
                            # Decode Wi-Fi payload (expects bytes)
                            decoded_fields = decode(structhelper_io(bytes.fromhex(advdata_hex)))

                            # Add MAC and RSSI to each decoded message part
                            for field_decoded in decoded_fields:
                                if isinstance(field_decoded, dict): # Ensure it's a dict
                                    field_decoded["MAC"] = mac
                                    if rssi is not None:
                                        field_decoded["RSSI"] = rssi
                                    # Publish each decoded part individually
                                    if pub:
                                        json_data = json.dumps(field_decoded)
                                        pub.send_string(json_data)
                                        if verbose:
                                            log("Published Wi-Fi ODID Part:", json_data)
                                else:
                                     log(f"Decoded Wi-Fi field is not a dict: {field_decoded}")
                            processed = True # Mark as processed

                        except ValueError as e:
                            log(f"AdvData Decode/Format Error (Wi-Fi): {e}, Data: {field.get('AdvData')}")
                        except Exception as e:
                            log(f"Decoding Error (Wi-Fi): {e}")
                    else:
                        # Handle cases where DroneID message might not have AdvData
                        # but contains other useful info (less common for standard ODID)
                        try:
                            field["MAC"] = mac
                            if rssi is not None:
                                field["RSSI"] = rssi
                            if pub:
                                json_data = json.dumps(field)
                                pub.send_string(json_data)
                                if verbose:
                                    log("Published Wi-Fi Direct Field:", json_data)
                            processed = True # Mark as processed
                        except Exception as e:
                            log(f"JSON Dump Error (Wi-Fi Direct Field): {e}")
                 else:
                     log(f"Field for MAC {mac} is not a dictionary: {field}")
        else:
             log(f"DroneID data is not a dictionary: {drone_id_data}")

    # Log if a message was received but not processed by ODID logic
    if not processed and verbose and "AUX_ADV_IND" not in dc and "DroneID" not in dc:
         log(f"Received message not matching known ODID structures: {list(dc.keys())}")


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
    