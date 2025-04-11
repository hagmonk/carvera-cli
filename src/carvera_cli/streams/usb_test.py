#!/usr/bin/env python

import argparse
import logging
import sys
import time
from carvera_cli.streams.usb import USBStream, SERIAL_TIMEOUT
from serial import SerialException

def main():
    parser = argparse.ArgumentParser(description="Test USBStream connection.")
    parser.add_argument("-p", "--port", required=True, help="Serial port address (e.g., /dev/ttyACM0 or COM3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log = logging.getLogger("usb_test")

    stream = None
    try:
        log.info(f"Attempting to connect to {args.port}...")
        stream = USBStream(address=args.port)
        log.info("Connection successful.")

        # Send a command
        command = b'M115\n' # Get firmware info
        log.info(f"Sending command: {command!r}")
        stream.send(command)

        # Read response
        log.info("Waiting for response...")
        start_time = time.monotonic()
        response_lines = []
        ok_received = False
        # Read for a maximum of 5 seconds or until 'ok'
        read_timeout = 5.0 

        while time.monotonic() - start_time < read_timeout:
            if stream.waiting_for_recv():
                line = stream.readline()
                if line:
                    decoded_line = line.decode(errors='ignore').strip()
                    log.info(f"Received: {decoded_line}")
                    response_lines.append(decoded_line)
                    if "ok" in decoded_line.lower():
                        ok_received = True
                        log.info("Received 'ok'.")
                        break
                else:
                    # readline() might return empty bytes if timeout hit internally
                    time.sleep(0.05) # Small sleep if no data immediately available
            else:
                time.sleep(0.05) # Small sleep if buffer is empty

        if not ok_received:
            log.warning(f"Did not receive 'ok' within {read_timeout} seconds.")

        log.info("Test completed.")

    except SerialException as e:
        log.error(f"Failed to connect or communicate: {e}")
        sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if stream:
            log.info("Closing connection...")
            stream.close()
            log.info("Connection closed.")

if __name__ == "__main__":
    main() 