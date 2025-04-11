#!/usr/bin/env python

import argparse
import logging
import socket
import sys
import time

# Adjust the import path based on how you run this script
try:
    # Assuming run from workspace root or PYTHONPATH includes cli/src
    from carvera_cli.streams.wifi import WiFiStream, SOCKET_TIMEOUT
    from carvera_cli.device.manager import DeviceManager
except ImportError:
    print("Error: Could not import WiFiStream or DeviceManager. Make sure PYTHONPATH is set correctly or run from the workspace root.")
    # Attempt relative import as fallback if run from cli dir? Unlikely to work well.
    sys.exit("Failed to import required modules.")

def main():
    parser = argparse.ArgumentParser(description="Test DeviceManager with WiFiStream connection.")
    parser.add_argument("-a", "--address", required=True, help="Device IP address (e.g., 192.168.1.100 or 192.168.1.100:2222)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-s", "--skip-info", action="store_true", help="Skip initial device info query")
    parser.add_argument("-c", "--command", default="M115", help="Command to execute via DeviceManager (e.g., 'M115', 'model', 'ls /sd')")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log = logging.getLogger("manual_test")

    stream = None
    dm = None
    try:
        log.info(f"Attempting to connect to {args.address}...")
        stream = WiFiStream(address=args.address)
        log.info("Connection successful.")

        log.info("Initializing DeviceManager...")
        dm = DeviceManager(stream=stream, address=args.address, verbose=args.verbose, skip_info=args.skip_info)
        log.info("DeviceManager initialized.")

        if not args.skip_info:
            log.info(f"Initial Device Info: {dm.device_info}")

        # Execute the specified command
        command_to_run = args.command
        log.info(f"Executing command: '{command_to_run}'")

        success, response = dm.execute(command_to_run)

        if success:
            log.info(f"Command '{command_to_run}' executed successfully.")
            log.info(f"""Response:
---
{response}
---""")
        else:
            log.error(f"Command '{command_to_run}' failed.")
            log.error(f"""Error Response:
---
{response}
---""")

        log.info("Test completed.")

    except socket.error as e:
        log.error(f"Failed to connect or communicate: {e}")
        sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}", exc_info=args.verbose)
        sys.exit(1)
    finally:
        if dm:
            log.info("Closing DeviceManager (and stream)...")
            dm.close()
            log.info("DeviceManager closed.")
        elif stream: # Should be closed by dm.close(), but just in case dm failed init
             log.info("Closing stream...")
             stream.close()
             log.info("Stream closed.")

if __name__ == "__main__":
    main() 