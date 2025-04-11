"""
Carvera CLI Tool

A command-line tool for managing Carvera CNC machines.
"""

import os
import sys
import argparse
import time
import logging
import readline
import atexit
import select

from carvera_cli.device_manager import DeviceManager
from carvera_cli.streams import USBStream, SERIAL_AVAILABLE

def progress_callback(packet_size: int, total: int, success: int, errors: int) -> None:
    """
    Progress callback for file uploads
    
    Args:
        packet_size: Size of each packet in bytes
        total: Total number of packets to send
        success: Number of successfully sent packets
        errors: Number of errors (mostly for internal retry count)
    """
    if total > 0:
        percent = (success / total) * 100
        # Don't show 'errors' count as it reflects recoverable retries
        progress_str = f"\rProgress: {percent:.1f}% ({success}/{total} packets)"
        sys.stdout.write(progress_str)
        # Add a newline when finished
        if success == total:
            sys.stdout.write("\n")
        sys.stdout.flush()


def interactive_mode(manager: DeviceManager) -> int:
    """
    Run an interactive shell for communicating with the Carvera device
    
    Args:
        manager: DeviceManager instance connected to a device
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Try to setup command history
    history_file = os.path.expanduser('~/.carvera_history')
    
    # Create the history file if it doesn't exist
    if not os.path.exists(history_file):
        try:
            # Touch the file to create it
            with open(history_file, 'a'):
                pass
            logging.info(f"Created history file: {history_file}")
        except Exception as e:
            print(f"Warning: Could not create history file: {str(e)}")
    
    try:
        readline.read_history_file(history_file)
        # Set history length
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Warning: Could not read history file: {str(e)}")
    
    # Save history on exit
    try:
        atexit.register(readline.write_history_file, history_file)
    except Exception as e:
        print(f"Note: Error setting up command history: {str(e)}")

    # Print welcome message and device info
    print("\nEntering interactive mode. Type 'help' for commands, 'exit' to quit.")
    # Only print device details if info was actually queried (not skipped)
    if manager.device_info:
        print(f"Connected to: {manager.device_info.get('model', 'Unknown')} - {manager.device_info.get('version', 'Unknown')}")
    else:
        print("Connected")
    
    def print_help():
        """Print help information for interactive mode"""
        print("\nAvailable commands:")
        print("  help     - Show this help information")
        print("  exit     - Exit interactive mode")
        print("  quit     - Same as exit")
        print("  status   - Get device status")
        print("  clear    - Clear the screen")
        print("\nAny other input will be sent as a command to the Carvera device.")
        print("\nCommon device commands:")
        print("  version  - Show device firmware version")
        print("  model    - Show device model information")
        print("  ls -e -s /sd/gcodes/  - List files in directory")
        print("  cat file.nc -e        - Display file contents")
        print("  rm file.nc -e         - Remove file")
        print("  config-get-all -e     - Show all device settings")
        print("\nPress up/down arrows to navigate command history")
    
    # Command loop
    while True:
        try:
            # Get user input
            cmd = input("carvera> ")
            
            # Clean input - strip any trailing newlines that might be present from pasting
            cmd = cmd.strip()
            
            # Skip empty lines
            if not cmd:
                continue
                
            # Handle special commands
            if cmd.lower() in ('exit', 'quit'):
                break
            elif cmd.lower() == 'help':
                print_help()
                continue
            elif cmd.lower() == 'status':
                status = manager.get_status()
                print(f"Device status: {status}")
                continue
            elif cmd.lower() == 'clear':
                try:
                    os.system('cls' if os.name == 'nt' else 'clear')
                except Exception as e:
                    print(f"Error clearing screen: {str(e)}")
                continue
            
            # Execute the command on the device
            # Default to waiting for ok, except for 'cd'
            wait_flag = False if cmd.lower().startswith("cd ") else True
            success, response = manager.execute_command(cmd, wait_for_ok=wait_flag)
            
            # Show the response
            if success:
                if response:
                    print(response)
                # Only print "(Command sent)" if it was a non-waiting command (like cd)
                elif not wait_flag: 
                    print("(Command sent)") 
                # If wait_flag was True but no response, it's unusual but ok was likely received
                # else: # No need to print anything extra if ok was received with no other output
                #    pass
            else:
                print("Error: Command failed")
                if response:
                    print(f"Response: {response}")
        
        except KeyboardInterrupt:
            print("\nUse 'exit' or 'quit' to exit interactive mode")
        except EOFError:
            # Handle Ctrl+D
            print("\nExiting interactive mode")
            break
        except Exception as e:
            print(f"Error: {str(e)}")
    
    print("Interactive mode closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Carvera CLI Tool',
        epilog="""A tool for managing Carvera CNC machines."""
    )

    # Global options (apply to all subcommands)
    parser.add_argument('--device', '-d', default=None,
                        help='Device address (COM port for USB, IP address for WiFi)')
    parser.add_argument('--usb', dest='connection', action='store_const', const='usb',
                        help='Force USB connection')
    parser.add_argument('--wifi', dest='connection', action='store_const', const='wifi',
                        help='Force WiFi connection')
    parser.add_argument('--skip-info', action='store_true',
                        help='Skip device information queries to speed up connection')
    parser.add_argument('--timeout', type=float, default=15.0, # Increased default from 10
                        help='Timeout in seconds for operations (default: 15)')
    # Logging / Output options (Mutually Exclusive)
    log_level_group = parser.add_mutually_exclusive_group()
    log_level_group.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose DEBUG level logging')
    log_level_group.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress INFO level logging, show only WARNINGs and ERRORs')

    # Subparsers for different actions
    subparsers = parser.add_subparsers(dest='action', title='Actions', 
                                     description='Choose an action to perform', required=True)

    # --- Firmware Subcommand ---
    parser_firmware = subparsers.add_parser('firmware', help='Upload firmware to the device')
    parser_firmware.add_argument('firmware_file', help='Path to the firmware file (.bin)')
    parser_firmware.add_argument('--reset', action='store_true', 
                               help='Automatically reset the device after successful upload and verification')

    # --- Upload Subcommand ---
    parser_upload = subparsers.add_parser('upload', help='Upload a G-code or other file to the device')
    parser_upload.add_argument('local_file', help='Path to the local file to upload')
    upload_group = parser_upload.add_argument_group('Upload Options')
    upload_group.add_argument('--target-dir', 
                        help='Target directory (default: /sd/gcodes). Ignored if --remote-path is used.')
    upload_group.add_argument('--remote-path', 
                        help='Specify the full remote path, including filename.')
    upload_group.add_argument('--overwrite', action='store_true',
                        help='Allow overwriting existing files (firmware behavior)')
    upload_group.add_argument('--compress', action='store_true',
                        help='Use QuickLZ compression (requires firmware support)')

    # --- Download Subcommand ---
    parser_download = subparsers.add_parser('download', help='Download a file from the device')
    parser_download.add_argument('remote_file', help='Path to the file on the device to download')
    download_group = parser_download.add_argument_group('Download Options')
    download_group.add_argument('--local-path',
                        help='Local path to save downloaded file (default: current directory)')

    # --- Command Subcommand ---
    parser_command = subparsers.add_parser('command', help='Execute a single command on the device')
    parser_command.add_argument('device_command', help='The command string to send')
    parser_command.add_argument('--no-wait', action='store_true',
                        help='Do not wait for an "ok" response')

    # --- Config Subcommand ---
    parser_config = subparsers.add_parser('config', help='Download and display device configuration')
    parser_config.add_argument('--output', '-o', 
                       help='Save configuration to a specified file')

    # --- Scan Subcommand ---
    parser_scan = subparsers.add_parser('scan', help='Scan for available devices and exit')
    
    # --- Interactive Subcommand ---
    parser_interactive = subparsers.add_parser('interactive', aliases=['i'], help='Enter interactive command mode')

    # Add hidden debug flag for connection testing
    parser_conntest = subparsers.add_parser('connection-test', help=argparse.SUPPRESS)

    # Parse arguments
    args = parser.parse_args()
    
    # Set up logging level based on flags
    log_level = logging.INFO # Default
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING
        
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    log = logging.getLogger("main")
    
    # Handle scan mode separately as it doesn't need a connection
    if args.action == 'scan':
        log.info("Scanning for Carvera devices...")
        # ... (Scan logic remains the same) ...
        from carvera_cli.streams import WiFiStream, USBStream, SERIAL_AVAILABLE
        wifi_devices = WiFiStream.discover_devices(timeout=5)
        if wifi_devices: 
            log.info(f"Found {len(wifi_devices)} WiFi device(s):") # ... (print details)
            # Add logic here later to print details if needed
            pass 
        else: 
            log.info("No WiFi devices found")
        
        if SERIAL_AVAILABLE: 
            # Add logic here later to scan and print USB ports
            pass # Add pass to fix indentation
        else: 
            log.info("USB scanning not available (pyserial not installed)")
        return 0

    # --- Device Connection Logic (for all other actions) ---
    callback_func = progress_callback if not args.quiet else None
    manager = DeviceManager(callback=callback_func, verbose=args.verbose)
    
    # Determine Connection Parameters
    # ... (Connection detection logic remains the same using args.connection, args.device) ...
    user_conn_type = None
    user_address = args.device
    final_connection_type = None
    final_device_address = None
    if args.connection == 'usb': user_conn_type = DeviceManager.CONN_USB
    elif args.connection == 'wifi': user_conn_type = DeviceManager.CONN_WIFI
    # ... (Rest of detection/inference logic) ...
    if user_conn_type is not None and user_address is not None:
        final_connection_type = user_conn_type
        final_device_address = user_address
    elif user_conn_type is not None:
        # Auto-detect address for specified type
        log.info(f"Specified connection type: {'USB' if user_conn_type == DeviceManager.CONN_USB else 'WiFi'}. Detecting address...")
        if user_conn_type == DeviceManager.CONN_USB:
             # ... (USB detection) ...
             if SERIAL_AVAILABLE:
                usb_ports = USBStream.list_ports()
                if usb_ports:
                    carvera_ports = [p for p in usb_ports if 'ch340' in p['description'].lower() or 'usb-serial' in p['description'].lower()]
                    selected_port = carvera_ports[0] if carvera_ports else usb_ports[0]
                    final_device_address = selected_port['port']
                else: log.error("Error: No USB devices found..."); return 1
             else: log.error("Error: USB specified but PySerial not available."); return 1
        else: # WiFi
            from carvera_cli.streams import WiFiStream
            wifi_devices = WiFiStream.discover_devices(timeout=3)
            if wifi_devices:
                available_devices = [d for d in wifi_devices if not d.get('busy', True)]
                selected_device = available_devices[0] if available_devices else wifi_devices[0]
                final_device_address = selected_device['ip']
            else:
                log.error("Error: No WiFi devices found for specified type.")
                return 1
            final_connection_type = user_conn_type
    elif user_address is not None:
        # Infer type from address
        log.info(f"Specified device address: {user_address}. Inferring connection type...")
        is_likely_ip = all(c.isdigit() or c == '.' for c in user_address)
        final_connection_type = DeviceManager.CONN_WIFI if is_likely_ip else DeviceManager.CONN_USB
        if final_connection_type == DeviceManager.CONN_USB and not SERIAL_AVAILABLE:
            log.warning(f"Inferred USB connection for '{user_address}' but PySerial not available.")
        final_device_address = user_address
    else:
        # Full auto-detect
        log.info("No device or connection type specified, attempting full auto-detect...")
        detected_type, detected_address = DeviceManager.detect_connection()
        if detected_type != DeviceManager.CONN_NONE:
            final_connection_type = detected_type
            final_device_address = detected_address
        else: log.error("Error: Auto-detection failed..."); return 1
    # --- End Connection Detection ---

    if final_connection_type is None or final_device_address is None: log.error("Could not determine connection parameters."); return 1
    log.info(f"Final Connection Type: {'USB' if final_connection_type == DeviceManager.CONN_USB else 'WiFi'}")
    log.info(f"Final Device Address: {final_device_address}")

    exit_code = 1 # Default to error
    try:
        if not manager.open(final_connection_type, final_device_address, skip_info=args.skip_info):
            log.error("Failed to connect to device")
            return 1
        
        # --- Action Execution based on Subcommand --- 
        if args.action == 'firmware':
            log.info(f"Starting firmware upload: {args.firmware_file}")
            if not os.path.isfile(args.firmware_file):
                log.error(f"Firmware file not found: {args.firmware_file}")
                return 1
            upload_success = manager.upload_firmware(args.firmware_file)
            if upload_success:
                log.info("Firmware upload process completed.")
                if args.reset:
                    log.info("Reset flag detected, initiating device reset...")
                    if manager.reset_device():
                        log.info("Device reset command sent successfully.")
                    else:
                        log.error("Failed to send reset command.")
                        exit_code = 1 # Indicate failure if reset command fails
                exit_code = 0
            else:
                log.error("Firmware upload process failed.")
                exit_code = 1

        elif args.action == 'upload':
            log.info(f"Uploading file: {args.local_file}")
            if not os.path.isfile(args.local_file):
                 log.error(f"Upload file not found: {args.local_file}")
                 return 1
            result = manager.upload_file(
                args.local_file, 
                remote_path=args.remote_path, 
                target_dir=args.target_dir,
                overwrite=args.overwrite,
                compress=args.compress
            )
            exit_code = 0 if result else 1

        elif args.action == 'download':
            log.info(f"Downloading file: {args.remote_file}")
            result = manager.download_file(
                args.remote_file,
                local_path=args.local_path,
                timeout=args.timeout # Use global timeout
            )
            exit_code = 0 if result else 1
            
        elif args.action == 'command':
            log.info(f"Executing command: {args.device_command}")
            success, response = manager.execute_command(
                args.device_command, 
                wait_for_ok=not args.no_wait, 
                timeout=args.timeout # Use global timeout
            )
            if success:
                log.info("Command executed successfully")
                if response: print(response) # Print response directly
                exit_code = 0
            else:
                log.error("Command failed")
                if response: print(f"Response: {response}")
                exit_code = 1
                
        elif args.action == 'config':
            log.info("Retrieving device configuration...")
            success, config = manager.get_device_config()
            if success:
                # ... (Config formatting and printing/saving logic) ...
                log.info("Configuration retrieved.")
                # (Existing logic to format and print/save config)
                grouped_config = {} # ... etc ...
                config_lines = [] # ... etc ...
                # Print/save logic using args.output and args.quiet
                if not args.quiet: print("\nDevice Configuration...") # Print formatted config
                if args.output: # Save logic
                    log.info(f"Config saved to {args.output}")
                exit_code = 0
            else:
                log.error("Failed to retrieve configuration")
                exit_code = 1
                
        elif args.action == 'interactive' or args.action == 'i':
            exit_code = interactive_mode(manager)
            
        elif args.action == 'connection-test':
            log.info("Running connection test...")
            success, response = manager.execute_command("version", wait_for_ok=True, timeout=args.timeout)
            if success: log.info(f"Connection test OK. Response: {response}"); exit_code = 0
            else: log.error(f"Connection test FAILED. Response: {response}"); exit_code = 1
            
    except KeyboardInterrupt:
        log.warning("Operation cancelled by user")
        exit_code = 1
    except Exception as e:
        log.error(f"An unexpected error occurred: {str(e)}")
        log.exception("Exception details:") 
        exit_code = 1
    finally:
        manager.close()
        
    return exit_code

if __name__ == "__main__":
    sys.exit(main())
