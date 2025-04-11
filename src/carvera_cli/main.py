"""
Carvera CLI Tool

A command-line tool for managing Carvera CNC machines.
"""

import sys
import argparse
import logging
import socket # For error handling
import os # Added for path operations

from carvera_cli.streams.wifi import WiFiStream
from carvera_cli.streams.usb import USBStream
from carvera_cli.device.manager import DeviceManager
from carvera_cli.cmd.interactive import interactive_mode
from carvera_cli.cmd.config import config_get_all
from carvera_cli.cmd.files import handle_download, handle_stat, handle_upload, handle_md5, handle_ls, handle_upload_firmware

def main() -> int:
    parser = argparse.ArgumentParser(
        description='Carvera CLI Tool',
        epilog="""A tool for managing Carvera CNC machines."""
    )

    # Global options (apply to all subcommands)
    parser.add_argument('--device', '-d', default=None,
                        help='Device address (COM port for USB, IP address[:port] for WiFi)')
    parser.add_argument('--usb', dest='force_connection', action='store_const', const='usb',
                        help='Force USB connection (auto-detects port if --device not set)')
    parser.add_argument('--wifi', dest='force_connection', action='store_const', const='wifi',
                        help='Force WiFi connection (auto-detects device if --device not set)')
    parser.add_argument('--skip-info', action='store_true',
                        help='Skip device information queries to speed up connection')
    parser.add_argument('--timeout', type=float, default=15.0,
                        help='Default timeout in seconds for device commands (default: 15)')
    # Logging / Output options (Mutually Exclusive)
    log_level_group = parser.add_mutually_exclusive_group()
    log_level_group.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose DEBUG level logging')
    log_level_group.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress INFO level logging, show only WARNINGs and ERRORs')

    # Subparsers for different actions
    subparsers = parser.add_subparsers(dest='action', title='Actions', 
                                     description='Choose an action to perform', required=True)

    # --- Command Subcommand ---
    parser_command = subparsers.add_parser('command', help='Execute a single command on the device')
    parser_command.add_argument('device_command', nargs='+', help='The command string to send (can include spaces)')
    # --no-wait is removed as DeviceManager handles response waiting internally

    # --- Config Subcommand ---
    parser_config = subparsers.add_parser('config', help='Download and display device configuration')
    parser_config.add_argument('--output', '-o', 
                       help='Save configuration to a specified file')

    # --- Scan Subcommand ---
    parser_scan = subparsers.add_parser('scan', help='Scan for available devices and exit')
    scan_group = parser_scan.add_mutually_exclusive_group()
    scan_group.add_argument('--scan-usb', action='store_true', help="Scan only for USB devices")
    scan_group.add_argument('--scan-wifi', action='store_true', help="Scan only for WiFi devices")
    parser_scan.add_argument('--scan-timeout', type=int, default=3, help="Timeout for WiFi discovery (seconds)")
    
    # --- Interactive Subcommand ---
    parser_interactive = subparsers.add_parser('interactive', aliases=['i'], help='Enter interactive command mode')

    # --- Download Subcommand ---
    parser_download = subparsers.add_parser('download', help='Download a file from the device')
    parser_download.add_argument('remote_file', 
                               help='Path of the file on the device (if not absolute, will be treated as relative to /sd/gcodes/)')
    parser_download.add_argument('local_path', nargs='?', default=None,
                                 help='Local path to save the file (defaults to current directory)')
    parser_download.add_argument('--overwrite', action='store_true',
                                 help='Overwrite local file if it exists')
                                 
    # --- Upload Subcommand ---
    parser_upload = subparsers.add_parser('upload', help='Upload a file to the device')
    parser_upload.add_argument('local_file', help='Path to the local file to upload')
    parser_upload.add_argument('remote_path', nargs='?', default=None,
                               help='Absolute path or directory on the device (defaults to /sd/gcodes/)')
    parser_upload.add_argument('--overwrite', action='store_true',
                               help='Overwrite remote file if it exists')
                                 
    # --- Stat Subcommand ---
    parser_stat = subparsers.add_parser('stat', help='Get detailed information about a file on the device')
    parser_stat.add_argument('remote_file', help='Absolute path of the file on the device')
    parser_stat.add_argument('--json', action='store_true', 
                             help='Output file information in JSON format')
    
    # --- MD5 Subcommand ---
    parser_md5 = subparsers.add_parser('md5', help='Calculate MD5 checksum of a file on the device')
    parser_md5.add_argument('remote_file', help='Absolute path of the file on the device')
    
    # --- LS Subcommand ---
    parser_ls = subparsers.add_parser('ls', help='List files in a directory on the device')
    parser_ls.add_argument('remote_path', nargs='?', default=None,
                          help='Absolute path of the directory on the device (defaults to /sd/gcodes if not provided)')
    parser_ls.add_argument('--json', action='store_true', 
                          help='Output file information in JSON format')
    
    # --- Upload Firmware Subcommand ---
    parser_upload_firmware = subparsers.add_parser('upload-firmware',
                                                   help='Upload a validated firmware file to /sd/firmware.bin')
    parser_upload_firmware.add_argument('local_path',
                                        help='Path to the local firmware .bin file')
    parser_upload_firmware.add_argument('--reset', action='store_true',
                                        help='Reset the device after successful upload and verification')
    # Reuses global --timeout, --device etc.

    # Parse arguments
    args = parser.parse_args()
    
    # --- Logging Setup ---
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

    # --- Scan Action (handled before connection attempt) ---
    if args.action == 'scan':
        log.info("Scanning for devices...")
        found_devices = False
        if not args.scan_wifi: # Scan USB unless --scan-wifi is specified
             print("\nUSB Devices:")
             usb_ports = USBStream.list_ports()
             if usb_ports:
                 found_devices = True
                 for port_info in usb_ports:
                     print(f"  - Port: {port_info['port']}, Desc: {port_info['description']}")
             else:
                 print("  (No USB devices found)")
        
        if not args.scan_usb: # Scan WiFi unless --scan-usb is specified
             print("\nWiFi Devices (Broadcasting):")
             wifi_devices = WiFiStream.discover_devices(timeout=args.scan_timeout)
             if wifi_devices:
                 found_devices = True
                 for device_info in wifi_devices:
                     status = "(Busy)" if device_info.get('busy', False) else "(Available)"
                     print(f"  - IP: {device_info['ip']}, Name: {device_info['machine']} {status}")
             else:
                 print(f"  (No WiFi devices found broadcasting on UDP port {WiFiStream.UDP_PORT})")
        
        return 0 if found_devices else 1

    # --- Connection Logic --- 
    stream = None
    manager = None
    selected_address = args.device
    connection_type = args.force_connection
    
    try:
        # 1. Determine Connection Type and Address
        if connection_type is None and selected_address is None:
            log.debug("Auto-detecting connection...")
            # 1. Prioritize WiFi Discovery
            log.debug("Trying WiFi discovery first...")
            wifi_devices = WiFiStream.discover_devices(timeout=3)
            available_wifi = [d for d in wifi_devices if not d.get('busy', True)]
            if available_wifi:
                 selected_address = available_wifi[0]['ip']
                 connection_type = 'wifi'
                 log.debug(f"Auto-detected available WiFi device: {selected_address}")
            elif wifi_devices:
                 selected_address = wifi_devices[0]['ip']
                 connection_type = 'wifi'
                 log.warning(f"Auto-detected WiFi device (busy, using anyway): {selected_address}")
            else:
                 # 2. Fallback to USB Detection if WiFi fails
                 log.debug("No WiFi device found, trying USB detection...")
                 all_usb_ports = USBStream.list_ports()
                 # Filter out specific unwanted ports
                 valid_usb_ports = [p for p in all_usb_ports if p['port'] != '/dev/cu.debug-console']
                 if valid_usb_ports:
                     selected_address = valid_usb_ports[0]['port']
                     connection_type = 'usb'
                     log.debug(f"Auto-detected USB device: {selected_address}")
                 else:
                     log.error("Auto-detection failed: No available WiFi or valid USB devices found.")
                     return 1
        elif connection_type == 'usb' and selected_address is None:
            log.debug("USB forced, auto-detecting port...")
            all_usb_ports = USBStream.list_ports()
            valid_usb_ports = [p for p in all_usb_ports if p['port'] != '/dev/cu.debug-console']
            if valid_usb_ports:
                selected_address = valid_usb_ports[0]['port']
                log.debug(f"Using USB device: {selected_address}")
            else:
                log.error("USB forced, but no devices found.")
                return 1
        elif connection_type == 'wifi' and selected_address is None:
            log.debug("WiFi forced, auto-detecting device...")
            wifi_devices = WiFiStream.discover_devices(timeout=3)
            available_wifi = [d for d in wifi_devices if not d.get('busy', True)]
            if available_wifi:
                 selected_address = available_wifi[0]['ip']
                 log.debug(f"Using available WiFi device: {selected_address}")
            elif wifi_devices:
                 selected_address = wifi_devices[0]['ip']
                 log.warning(f"Using busy WiFi device: {selected_address}")
            else:
                 log.error("WiFi forced, but no devices found.")
                 return 1
        elif connection_type is None and selected_address is not None:
             log.debug(f"Device address provided ({selected_address}), inferring type...")
             addr_lower = selected_address.lower()
             if addr_lower.startswith('/dev/') or addr_lower.startswith('com'): 
                 connection_type = 'usb'
             else:
                 connection_type = 'wifi'
             log.debug(f"Inferred type: {connection_type.upper()}")
        # Else: connection_type and selected_address are both set by user

        if selected_address is None:
             log.error("Could not determine device address.")
             return 1
        if connection_type is None:
             log.error("Could not determine connection type.")
             return 1
             
        # 2. Create Stream
        log.debug(f"Attempting {connection_type.upper()} connection to {selected_address}...")
        if connection_type == 'usb':
            stream = USBStream(address=selected_address)
        elif connection_type == 'wifi':
            stream = WiFiStream(address=selected_address)
        else:
             log.error(f"Internal error: Invalid connection type '{connection_type}'")
             return 1 # Should not happen
        
        log.debug("Stream connected.")
        manager = DeviceManager(
            stream=stream,
            address=selected_address,
            verbose=args.verbose
        )

        log.debug("DeviceManager initialized.")
        
        # --- Action Execution --- 
        exit_code = 1 # Default to error

        if args.action == 'command':
            full_command = " ".join(args.device_command)
            log.debug(f"Executing command: '{full_command}'")
            success, response = manager.execute(full_command, timeout=args.timeout)
            if success:
                log.debug("Command executed successfully")
                if response: print(response)
                exit_code = 0
            else:
                log.error(f"Command failed: {response}")
                exit_code = 1
                
        elif args.action == 'config':
            exit_code = config_get_all(manager, args.timeout, args.output)
                
        elif args.action == 'interactive' or args.action == 'i':
            exit_code = interactive_mode(manager)

        elif args.action == 'download':
            # Delegate the download logic to the handler function
            exit_code = handle_download(manager, args)
            
        elif args.action == 'upload':
            # Delegate the upload logic to the handler function
            exit_code = handle_upload(manager, args)
            
        elif args.action == 'stat':
            # Delegate the stat logic to the handler function
            exit_code = handle_stat(manager, args)
            
        elif args.action == 'md5':
            # Delegate the md5 logic to the handler function
            exit_code = handle_md5(manager, args)
            
        elif args.action == 'ls':
            # Delegate the ls logic to the handler function
            exit_code = handle_ls(manager, args)
            
        elif args.action == 'upload-firmware':
            # Delegate the firmware upload logic to the handler function
            exit_code = handle_upload_firmware(manager, args)
            
    except (socket.error, IOError) as e:
         # Catch connection errors during Stream or DeviceManager init
         log.error(f"Connection failed: {e}")
         exit_code = 1
    except KeyboardInterrupt:
        log.warning("Operation cancelled by user")
        exit_code = 1
    except Exception as e:
        log.error(f"An unexpected error occurred: {str(e)}")
        # Show traceback if verbose
        if args.verbose:
             log.exception("Exception details:") 
        exit_code = 1
    finally:
        # Close the manager (which closes the stream)
        if manager:
             log.debug("Closing DeviceManager...")
             manager.close()
             log.debug("DeviceManager closed.")
        elif stream: # If manager failed init but stream was created
             log.debug("Closing Stream (manager failed init)...")
             stream.close()
             log.debug("Stream closed.")
        
    return exit_code

if __name__ == "__main__":
    sys.exit(main())
