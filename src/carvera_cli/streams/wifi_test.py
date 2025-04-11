#!/usr/bin/env python

import argparse
import logging
import socket
import sys
import time
from carvera_cli.streams.wifi import WiFiStream, SOCKET_TIMEOUT

def main():
    parser = argparse.ArgumentParser(description="Test WiFiStream connection.")
    parser.add_argument("-a", "--address", required=True, help="Device IP address (e.g., 192.168.1.100 or 192.168.1.100:2222)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log = logging.getLogger("wifi_test")

    stream = None
    reader = None
    try:
        log.info(f"Attempting to connect to {args.address}...")
        stream = WiFiStream(address=args.address)
        log.info("Connection successful.")

        # Send a command
        command = b'M115\n' # Get firmware info
        log.info(f"Sending command: {command!r}")
        stream.send(command)

        # Read response using makefile for line-based reading
        log.info("Waiting for response...")
        start_time = time.monotonic()
        response_lines = []
        ok_received = False
        read_timeout = 5.0 # Overall timeout for receiving the response

        # Create a file-like object for reading lines
        # Use errors='ignore' for robustness against potential invalid UTF-8 bytes
        # The socket should already have a timeout (SOCKET_TIMEOUT), 
        # but makefile().readline() might block differently, so we need the outer loop timeout.
        reader = stream.socket.makefile('r', encoding='utf-8', errors='ignore', newline='\n')

        while time.monotonic() - start_time < read_timeout:
            try:
                # Rely on readline() respecting the underlying socket timeout (SOCKET_TIMEOUT)
                line = reader.readline()

                if not line:
                    # Empty string typically means EOF / connection closed
                    log.warning("Connection closed while reading response.")
                    break
                    
                decoded_line = line.strip() # Already decoded by makefile
                log.info(f"Received: {decoded_line}")
                response_lines.append(decoded_line)
                if "ok" in decoded_line.lower():
                    ok_received = True
                    log.info("Received 'ok'.")
                    break

            except (socket.timeout):
                # readline() timed out (waited SOCKET_TIMEOUT)
                log.debug(f"Socket readline timed out after {SOCKET_TIMEOUT}s, checking overall timeout.")
                # Check overall timeout
                if time.monotonic() - start_time >= read_timeout:
                    log.warning(f"Read operation timed out after {read_timeout} seconds.")
                    break
                # Otherwise, continue the loop and try reading again
                continue 
            except (socket.error, OSError, ValueError) as e:
                log.error(f"Socket error during read: {e}")
                break # Exit loop on socket error
            except Exception as e:
                 log.error(f"Unexpected error during read: {e}", exc_info=True)
                 break

        if not ok_received:
            log.warning(f"Did not receive 'ok' within {read_timeout} seconds (or connection closed).")

        log.info("Test completed.")

    except socket.error as e:
        log.error(f"Failed to connect or communicate: {e}")
        sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if reader:
             try:
                 reader.close() # Close the file wrapper
             except Exception as e:
                 log.debug(f"Error closing socket reader: {e}")
        if stream:
            log.info("Closing connection...")
            stream.close()
            log.info("Connection closed.")

if __name__ == "__main__":
    main() 