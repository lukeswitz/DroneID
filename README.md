# OpenDroneID receiver and spoofer

## Installation
```bash
git clone https://github.com/alphafox02/DroneID.git
cd DroneID
git submodule init
git submodule update
./setup.sh
```

## Run

### 1. Bluetooth receiver (using Sonoff Dongle)
1. Run 
```bash
./bluetooth_receiver.sh -b 2000000 -s /dev/ttyUSB0 --zmqsetting 127.0.0.1:4222 -v
```
```
Argument description:
---------------------
-b is Baudrate (only use 2000000 for newer Sonoff devices, otherwise leave away)
-s is the serial port of the bluetooth dongle
--zmqsetting zmq server addr is 127.0.0.1 with Port 4222
-v Print received messages
```

#### For spoofing messages
```bash
./bluetooth_spoof.py -s /dev/ttyUSB0 -b 2000000
```
Edit drone.json for data to spoof

### 2. Wifi receiver (using Wifi card in monitoring mode)
#### For pcap replay
```
./wifi_receiver.py --pcap examples/odid_wifi_sample.pcap -z --zmqsetting 127.0.0.1:4223
```

#### Using a wifi interface
```
./wifi_receiver.py --interface wlan0 -z --zmqsetting 127.0.0.1:4223
```

### 3. DJI DroneID Receiver (using AntSDR)
```bash
python3 dji_receiver.py --debug --log-file /var/log/dji_receiver.log
```
```
Argument description:
---------------------
-d, --debug     Enable debug output to console
-l, --log-file  Path to save logs (default: no file logging)
```
Features:
- Connects to AntSDR at 172.31.100.2:41030
- Publishes DJI DroneID data on tcp://127.0.0.1:4221
- Includes GPS fallback using WarDragon monitor data
- Auto-validates and sanitizes drone position data

### 4. FPV Detection Receivers

#### 4a. FPV MDN Receiver (Serial-based FPV detection with GPS)
```bash
python3 fpv_mdn_receiver.py --serial /dev/ttyACM0 --baud 115200 --zmq-port 4222 --debug
```
```
Argument description:
---------------------
--serial              Serial port (default: /dev/ttyACM0)
--baud                Baud rate (default: 115200)
--zmq-port            ZMQ publish port (default: 4222)
--stationary          Read GPS once at startup (assumes stationary sensor)
--debug               Enable debug output
--log-file            Path to save logs
--tx-power            Transmission power in dBm (default: 27.8)
--path-loss-exponent  Path loss exponent for distance estimation (default: 2.7)
--gpsd-host           GPSD host (default: 127.0.0.1)
--gpsd-port           GPSD port (default: 2947)
```
Features:
- Processes MDN FPV detection sensor data
- GPS integration (stationary or mobile mode)
- RSSI-based distance estimation
- Detection caching and tracking
- Handles boot, calibration, and contact lock messages
- Publishes to ZMQ in format compatible with zmq_decoder

#### 4b. FPV AntSDR Receiver (AntSDR-based FPV detection)
```bash
python3 fpv_receive.py --debug --log-file /var/log/fpv_receiver.log
```
```
Argument description:
---------------------
-d, --debug     Enable debug output to console
-l, --log-file  Path to save logs (default: no file logging)
```
Features:
- Connects to AntSDR at 172.31.100.2:41030
- Monitors FPV drone detection events
- Parses log-based detection format
- Publishes on tcp://127.0.0.1:4220

### 5. Decode and spawn zmq server (Enhanced with FPV support)
```bash
./zmq_decoder.py -z --zmqsetting 127.0.0.1:4224 --zmqclients 127.0.0.1:4222,127.0.0.1:4223 --dji 127.0.0.1:4221 -v
```
```
Argument description:
---------------------
-z               Spawn a zmq server (optional)
--zmqsetting     ZMQ server addr (default: 127.0.0.1:4224)
--zmqclients     Listen to BT/Wi-Fi/FPV receivers (comma-separated)
--dji            DJI receiver endpoint (e.g., 127.0.0.1:4221)
--uart           UART device for pre-decoded ESP32 data (e.g., /dev/ttyACM0)
-v               Print decoded messages (optional)
```
**Enhanced Features:**
- **FPV Detection Support** - Handles FPV drone detection messages
- **Multi-format Detection** - Processes BT, Wi-Fi, DJI, and FPV formats
- **Improved Error Handling** - Better reconnection logic for UART
- **Universal Subscription** - Subscribes to all message types automatically
- **Enhanced BLE Support** - Handles both AUX_ADV_IND and ADV_EXT_IND

## What's New in This Fork

This fork extends the original alphafox02/DroneID with comprehensive FPV detection capabilities:

### New Features
1. **FPV Detection System** 🆕
   - Two FPV receiver implementations (serial MDN sensor & AntSDR)
   - GPS-integrated distance estimation
   - Real-time detection tracking and caching
   - Compatible with existing OpenDroneID infrastructure

2. **Enhanced ZMQ Decoder** 🔧
   - Multi-format message handling (BT/Wi-Fi/DJI/FPV)
   - Better UART reconnection logic
   - Support for ADV_EXT_IND (in addition to AUX_ADV_IND)
   - List-based WiFi output for consistency

3. **Improved DJI Receiver** 🔧
   - File logging support
   - GPS fallback using WarDragon monitor
   - Enhanced data validation
   - Better error handling

### Integration Example
Complete multi-source drone detection setup:
```bash
# Terminal 1: Bluetooth receiver
./bluetooth_receiver.sh -b 2000000 -s /dev/ttyUSB0 --zmqsetting 127.0.0.1:4222 -v

# Terminal 2: WiFi receiver
./wifi_receiver.py --interface wlan0 -z --zmqsetting 127.0.0.1:4223

# Terminal 3: FPV MDN receiver (if available)
python3 fpv_mdn_receiver.py --serial /dev/ttyACM0 --zmq-port 4225 --debug

# Terminal 4: DJI receiver (if available)
python3 dji_receiver.py --debug

# Terminal 5: Unified decoder (combines all sources)
./zmq_decoder.py -z --zmqsetting 127.0.0.1:4224 \
  --zmqclients 127.0.0.1:4222,127.0.0.1:4223,127.0.0.1:4225 \
  --dji 127.0.0.1:4221 -v
```
