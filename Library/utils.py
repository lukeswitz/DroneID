from getpass import getpass

import pwinput
import os
import sys
import socket as pysock
import subprocess
from pathlib import Path
from scapy.all import *
from subprocess import Popen, PIPE
sudopw = None

# State file to track the active monitor interface
INTERFACE_STATE_FILE = Path("/run/wifi_receiver_interface")

def _have_raw_caps() -> bool:
    """
    Return True if current process can open an AF_PACKET raw socket.
    This is a practical probe that usually indicates CAP_NET_RAW (and, in your unit, CAP_NET_ADMIN too).
    """
    try:
        s = pysock.socket(pysock.AF_PACKET, pysock.SOCK_RAW, 0)
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        # Treat other errors as non-fatal for this probe.
        return True

def cexec(command, pipe='', check=False):
    """
    Execute a command and return stdout.

    Args:
        command: Command to execute as list
        pipe: Input to send to stdin
        check: If True, raise RuntimeError on non-zero exit code

    Returns:
        stdout as string

    Raises:
        RuntimeError: If check=True and command fails
    """
    p = Popen(command, stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
    stdout_data, stderr_data = p.communicate(input=pipe)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed (exit {p.returncode}): {' '.join(command)}\nstderr: {stderr_data}")
    return stdout_data


def save_interface_state(interface: str):
    """Save the active interface name to state file for service restarts."""
    try:
        INTERFACE_STATE_FILE.write_text(interface)
    except Exception as e:
        print(f"Warning: Could not save interface state: {e}")


def load_interface_state() -> str | None:
    """Load the previously used interface name from state file."""
    try:
        if INTERFACE_STATE_FILE.exists():
            return INTERFACE_STATE_FILE.read_text().strip()
    except Exception:
        pass
    return None


def clear_interface_state():
    """Remove the interface state file."""
    try:
        if INTERFACE_STATE_FILE.exists():
            INTERFACE_STATE_FILE.unlink()
    except Exception:
        pass


def kill_interfering_processes(interface: str):
    """
    Stop processes from interfering with monitor mode on a SPECIFIC interface.
    Unlike 'airmon-ng check kill', this only affects the target interface,
    leaving NetworkManager and other interfaces (Ethernet, onboard WiFi) intact.

    Args:
        interface: The WiFi interface name to unmanage (e.g., 'wlx9cefd5feeabc')
    """
    print(f"Unmanaging interface {interface} from NetworkManager...")

    # Tell NetworkManager to stop managing this specific interface
    # This is much safer than killing NetworkManager entirely
    result = subprocess.run(
        ["nmcli", "device", "set", interface, "managed", "no"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        print(f"NetworkManager will no longer manage {interface}")
    else:
        # nmcli might fail if NM isn't running or interface isn't known - that's OK
        print(f"Note: nmcli returned {result.returncode} (may be fine if NM doesn't manage this interface)")

    # Kill any wpa_supplicant processes specifically for this interface
    # Use pkill with -f to match the interface name in the command line
    subprocess.run(
        ["sudo", "pkill", "-f", f"wpa_supplicant.*{interface}"],
        capture_output=True, timeout=5
    )

    # Kill any dhclient processes specifically for this interface
    subprocess.run(
        ["sudo", "pkill", "-f", f"dhclient.*{interface}"],
        capture_output=True, timeout=5
    )


def disable_power_save(interface: str) -> bool:
    """
    Disable power save mode on the WiFi interface.
    Returns True if successful or not applicable.
    """
    try:
        # Try iw first (preferred)
        result = subprocess.run(
            ["sudo", "iw", "dev", interface, "set", "power_save", "off"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(f"Power save disabled on {interface}")
            return True

        # Fallback to iwconfig
        result = subprocess.run(
            ["sudo", "iwconfig", interface, "power", "off"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(f"Power save disabled on {interface} (via iwconfig)")
            return True

        # Not all interfaces support power save control - that's OK
        print(f"Note: Could not disable power save on {interface} (may not be supported)")
        return True

    except Exception as e:
        print(f"Warning: Error disabling power save: {e}")
        return True  # Non-fatal


def check_monitor_mode(interface: str) -> bool:
    """
    Check if the interface is still in monitor mode.
    Returns True if in monitor mode, False otherwise.
    """
    try:
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True, text=True, timeout=5
        )
        return "Mode:Monitor" in result.stdout
    except Exception:
        return False


def recover_monitor_mode(interface: str) -> bool:
    """
    Attempt to recover monitor mode on an interface that has dropped out.
    Returns True if recovery successful.
    """
    print(f"Attempting to recover monitor mode on {interface}...")
    try:
        # Kill interfering processes for this specific interface only
        kill_interfering_processes(interface)

        # Bring interface down
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"],
                      capture_output=True, timeout=5)

        # Set monitor mode
        subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"],
                      capture_output=True, timeout=5)

        # Bring interface up
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"],
                      capture_output=True, timeout=5)

        # Disable power save
        disable_power_save(interface)

        # Verify
        if check_monitor_mode(interface):
            print(f"Successfully recovered monitor mode on {interface}")
            return True
        else:
            print(f"Failed to recover monitor mode on {interface}")
            return False

    except Exception as e:
        print(f"Error during monitor mode recovery: {e}")
        return False

def sudo(command):
    """
    Run privileged commands.

    Behavior:
      - If running as root -> run directly (no sudo).
      - If NON-interactive (systemd, pipes, cron):
          * If we have caps -> run directly (no prompt).
          * Else -> run directly (fail fast; no prompt).
      - If interactive TTY (human at a shell):
          * Always prompt once and run via sudo -S.
            (Restores your old "ask for password" behavior.)
    """
    global sudopw
    euid = os.geteuid()

    # Root: no sudo needed
    if euid == 0:
        return cexec(list(command))

    # Non-interactive (e.g., systemd): never prompt
    if not sys.stdin.isatty():
        # If process has caps, direct works; otherwise it will fail fast (logged)
        return cexec(list(command))

    # Interactive TTY: prompt once and use sudo -S
    if sudopw is None and 'SUDO_UID' not in os.environ:
        try:
            sudopw = pwinput.pwinput('Enter your sudo password: ')
        except Exception:
            sudopw = getpass('Enter your sudo password: ')

    if sudopw:
        return cexec(["sudo", "-S", *list(command)], pipe=sudopw)
    else:
        # If user refused a password, attempt direct (likely to fail), but don't hang
        return cexec(list(command))

def channel_hopping(interface):
    try:
        # List to store the channel number and Association Response packet
        result = []

        # Loop through channels 1 to 14
        for channel in range(1, 15):
            # Set the channel using Scapy's set_channel() function
            sudo(["iwconfig",interface,"channel",channel])

            # Sniff for Association Response packets on the current channel
            packets = sniff(filter="subtype 0x01", timeout=5)

            # Check if any Association Response packets were captured
            if packets:
                # Add the channel number and the first Association Response packet to the result list
                result.append((channel, packets[0]))

        return result

    except ImportError:
        raise ImportError("Scapy library is not installed.")

def search_interfaces():
    l = get_if_list()
    idict = IFACES.data
    interfaces = []
    for item in l:
        name = idict[item].name
        desc = idict[item].description
        if "wifi" in name.lower() or name[:2] == "wl":
            interfaces.append(name)
    return interfaces

def enable_monitor_mode(i2d, interface):
    """
    Enable monitor mode on the specified interface.

    This function:
    1. Kills interfering processes (NetworkManager, wpa_supplicant)
    2. Unblocks rfkill
    3. Sets monitor mode via iwconfig
    4. Disables power save to prevent random disconnects
    5. Saves interface state for recovery after restarts

    Returns True if successful, False otherwise.
    """
    res = True
    info = cexec(["iw", i2d[interface][0], "info"])
    if "* monitor" not in info:
        print(f"Interface {interface} doesn't support monitoring mode :(")
        exit(1)

    # Kill interfering processes first - this is critical for stability
    # This stops NetworkManager and wpa_supplicant from fighting us for THIS interface only
    kill_interfering_processes(interface)

    sudo(["rfkill", "unblock", "all"])

    if i2d[interface][1] != "monitor":
        print("Trying to enable monitoring mode")
        sudo(["ip", "link", "set", f"{interface}", "down"])
        sudo(["iwconfig", f"{interface}", "mode", "monitor"])
        i2d = extract_wifi_if_details(interface)
        if i2d[interface][1] != "monitor":
            print("Enabling monitor mode failed :(")
            res = False
        sudo(["ip", "link", "set", f"{interface}", "up"])

    if res:
        # Disable power save to prevent USB autosuspend/disconnect issues
        disable_power_save(interface)
        # Save interface name for recovery/restart scenarios
        save_interface_state(interface)
        print(f"Monitor mode enabled on {interface}")

    return res

def enable_managed_mode(i2d, interface):
    """Restore interface to managed mode (clean shutdown)."""
    info = cexec(["iw", i2d[interface][0], "info"])
    if "* managed" not in info:
        print(f"Interface {interface} doesn't support managed mode :(")
        exit(1)
    if i2d[interface][1] != "managed":
        print("Trying to enable managed mode")
        sudo(["ip", "link", "set", f"{interface}", "down"])
        sudo(["iwconfig", f"{interface}", "mode", "managed"])
        sudo(["ip", "link", "set", f"{interface}", "up"])

    # Clear state file on clean shutdown
    clear_interface_state()

def set_interface_channel(interface, channel):
    return sudo(["iwconfig", interface, "channel", str(channel)])

def extract_wifi_if_details(interface):
    i2d = {}
    devl = cexec(["iw", "dev"]).split("\n\t")
    ptype = ""
    for i in range(len(devl) - 1):
        if "Interface" in devl[i + 1]:
            iface = devl[i + 1].split(" ")[-1]
            dev = devl[i].split(" ")[-1].replace("#", "")
            for x in range(i + 2, len(devl), 1):
                if "type" in devl[x]:
                    ptype = devl[x].split(" ")[-1]
                    break
                elif "Interface" in devl[x]:
                    break
            i2d[iface] = (dev, ptype)
    if interface not in i2d:
        print("Invalid interface chosen.")
        exit(1)
    return i2d

def get_iw_interfaces(interfaces):
    print("Found interfaces:\n-----------------")
    for i in range(len(interfaces)):
        print(f"{i}:{interfaces[i]}")
    x = input("Enter interface number:")
    if int(x) < len(interfaces):
        interface = interfaces[int(x)]
    else:
        print("Invalid interface chosen.")
        exit(1)
    return interface
