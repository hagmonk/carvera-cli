"""
Firmware Uploader

Main interface for uploading firmware and files to Carvera CNC machines.
"""

import os
import sys
import time
import logging
import re
import select
import shutil
import socket
import hashlib
import tempfile
import threading
from pathlib import Path
from typing import Optional, List, Dict, Callable, Tuple, Any

from carvera_cli.streams import USBStream, WiFiStream
from carvera_cli.files import calculate_md5, prepare_file_for_upload, cleanup_temp_files

try:
    import quicklz
    QUICKLZ_AVAILABLE = True
except ImportError:
    QUICKLZ_AVAILABLE = False

# Constants
COMM_TIMEOUT = 10.0  # Command timeout in seconds
DEFAULT_GCODE_PATH = "/sd/gcodes"
BLOCK_HEADER_SIZE = 4

# Device response patterns
PATTERN_OK = re.compile(r'^(ok|OK).*$')
PATTERN_ERROR = re.compile(r'^(error|ERROR|alarm|ALARM).*$')
PATTERN_STATUS = re.compile(r'^<(\w*?),MPos:([+\-]?\d*\.\d*),([+\-]?\d*\.\d*),([+\-]?\d*\.\d*),WPos:([+\-]?\d*\.\d*),([+\-]?\d*\.\d*),([+\-]?\d*\.\d*),?(.*)>$')
PATTERN_VERSION = re.compile(r'^version:\s*(.+)$', re.IGNORECASE)
PATTERN_MODEL = re.compile(r'^model:\s*(.+)$', re.IGNORECASE)


class FirmwareUploader:
    """Main class for handling firmware uploads"""
    
    # Connection types
    CONN_NONE = 0
    CONN_USB = 1
    CONN_WIFI = 2
    
    # Constants and timeouts
    SERIAL_SCAN_RETRIES = 3
    CONNECTION_TIMEOUT = 5.0
    SPACE_REPLACEMENT = '\x01'  # Used to replace spaces in file paths
    
    # Message types
    MSG_NORMAL = 0
    MSG_ERROR = 1
    MSG_INTERNAL = 2
    
    # Command constants
    CMD_GET_CONFIG = "config-get-all -e"
    
    # Special character mapping - must exactly match Controller.py implementation
    SPECIAL_CHAR_MAP = {
        '?': '\x02',
        '&': '\x03',
        '!': '\x04',
        '~': '\x05'
    }
    
    def __init__(self, callback: Optional[Callable] = None, verbose: bool = False):
        self.usb_stream = USBStream()
        self.wifi_stream = WiFiStream()
        self.stream = None
        self.connection_type = self.CONN_NONE
        self.callback = callback
        self.device_info = {}
        self.buffer = b''  # For storing received data
        self.verbose = verbose
        self.machine_state = "Unknown"
        self.target_prefix = ""
        self.current_download_size = 0
        self.last_remote_md5 = None  # Will store the MD5 of the last file downloaded
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def open(self, conn_type: int, address: str) -> bool:
        """
        Open connection to device
        
        Args:
            conn_type: Connection type (CONN_USB or CONN_WIFI)
            address: Device address (COM port or IP address)
            
        Returns:
            True if connection successful, False otherwise
        """
        # Set the appropriate stream based on connection type
        if conn_type == self.CONN_USB:
            self.stream = self.usb_stream
            self.connection_type = self.CONN_USB
        else:
            self.stream = self.wifi_stream
            self.connection_type = self.CONN_WIFI
        
        # Try to open the connection
        if self.stream.open(address):
            print('Connected to device!')
            
            # Get device information
            if self.get_device_info():
                print(f"Device: {self.device_info.get('model', 'Unknown')}")
                print(f"Version: {self.device_info.get('version', 'Unknown')}")
                
                # Get initial status
                self.get_status()
                return True
            else:
                print("Warning: Connected but couldn't get device information")
                return True
        else:
            print('Connection failed!')
            return False
    
    def close(self) -> None:
        """Close connection to device"""
        if self.stream:
            try:
                self.stream.close()
            except Exception as e:
                print(f'Error closing stream: {str(e)}')
            self.stream = None
            
    def send_command(self, command: str, wait_for_response: bool = False, timeout: float = COMM_TIMEOUT) -> Tuple[bool, str]:
        """
        Send a command to the device and optionally wait for response
        
        Args:
            command: Command string to send
            wait_for_response: Whether to wait for response data
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success, response_text)
        """
        if not self.stream:
            return False, "Not connected"
            
        # Clear any pending data - read and discard
        while self.stream.waiting_for_recv():
            self.stream.recv()
        self.buffer = b''
        
        # Ensure command ends with newline
        if not command.endswith('\n'):
            command += '\n'
            
        if self.verbose:
            print(f"Sending command: {command.strip()}")
            
        # Send the command
        self.stream.send(command.encode())
        
        # The original Controller.py does NOT wait for responses on most commands
        # It just queues the command and continues. The responses are handled asynchronously.
        if not wait_for_response:
            # Give a small delay for the device to process it
            time.sleep(0.1)
            return True, ""
            
        # Get response if requested, using the specific timeout provided
        response = self._read_response(timeout)
        success = len(response) > 0
            
        return success, response
    
    def _read_response(self, timeout: float) -> str:
        """
        Read the response from the device without waiting for specific patterns
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            Combined response string
        """
        # Give the device a moment to respond
        time.sleep(0.1)
        
        # Read available data
        response_data = b''
        response_lines = []
        
        start_time = time.time()
        last_data_time = time.time()
        
        # Keep reading until timeout or until we've received an "ok" response
        while (time.time() - start_time) < timeout:
            if self.stream.waiting_for_recv():
                data = self.stream.recv()
                if data:
                    response_data += data
                    last_data_time = time.time()
                    
                    # If we have a complete line, process it
                    if b'\n' in response_data:
                        lines = response_data.split(b'\n')
                        # Keep the last line (might be incomplete)
                        response_data = lines[-1]
                        
                        # Add complete lines to our response
                        for line in lines[:-1]:
                            line_str = line.decode('utf-8', errors='ignore').strip()
                            if line_str:
                                response_lines.append(line_str)
                                
                                # If we see "ok" as a response, we've got what we need
                                if line_str.lower().startswith('ok'):
                                    # Allow a small delay to get any additional data
                                    time.sleep(0.1)
                                    break
                
                # If we got some data but there's none waiting now, we're probably done
                # unless we're still waiting for an ok
                if not self.stream.waiting_for_recv() and response_lines:
                    ok_received = any(line.lower().startswith('ok') for line in response_lines)
                    
                    # If we have an ok or we've been waiting for a bit with no new data, we're done
                    if ok_received or (time.time() - last_data_time) > 0.5:
                        # Add any remaining partial data
                        if response_data:
                            last_line = response_data.decode('utf-8', errors='ignore').strip()
                            if last_line:
                                response_lines.append(last_line)
                        break
            else:
                # No data waiting, if we have some response already we can check if it's complete
                if response_lines:
                    # If we've been waiting for more data for over half a second, probably done
                    if (time.time() - last_data_time) > 0.5:
                        break
                time.sleep(0.01)  # Short sleep to prevent CPU hogging
                
        # Add any remaining partial data
        if response_data:
            last_line = response_data.decode('utf-8', errors='ignore').strip()
            if last_line and last_line not in response_lines:
                response_lines.append(last_line)
                
        return '\n'.join(response_lines)
    
    def _parse_line(self, line: str) -> int:
        """
        Parse a line received from the device
        
        Args:
            line: Line string to parse
            
        Returns:
            Message type (MSG_NORMAL, MSG_ERROR, MSG_INTERNAL)
        """
        # Check for status message
        if line[0] == '<' and line[-1] == '>':
            status_match = PATTERN_STATUS.match(line)
            if status_match:
                self.machine_state = status_match.group(1)
                if self.verbose:
                    print(f"Machine state: {self.machine_state}")
            return self.MSG_INTERNAL
        
        # Check for error messages
        if PATTERN_ERROR.match(line):
            print(f"Error: {line}")
            return self.MSG_ERROR
            
        # Normal message
        if self.verbose:
            print(f"Device: {line}")
        return self.MSG_NORMAL
    
    def get_status(self) -> str:
        """
        Query the device status
        
        Returns:
            Current machine state
        """
        # Send status query
        self.stream.send(b"?")
        time.sleep(0.1)
        
        # Read and process response without waiting for OK
        response = self._read_response(0.5)
        
        # Parse status from response if available
        if response and '<' in response and '>' in response:
            self._parse_line(response)
            
        return self.machine_state
    
    def escape(self, value: str) -> str:
        """
        Escape special characters in a command
        
        Args:
            value: Command string to escape
            
        Returns:
            Escaped command string
        """
        result = value
        for char, replacement in self.SPECIAL_CHAR_MAP.items():
            result = result.replace(char, replacement)
        return result
    
    def execute_command(self, command: str, wait_for_ok: bool = True, timeout: float = None) -> Tuple[bool, str]:
        """
        Execute an arbitrary command on the device
        
        Args:
            command: Command to execute
            wait_for_ok: Whether to wait for an "ok" response
            timeout: Timeout in seconds (uses default if None)
            
        Returns:
            Tuple of (success, response)
        """
        if not self.stream:
            return False, "Not connected"
        
        # Escape special characters in the command
        escaped_command = self.escape(command)
        
        # Use a shorter timeout when waiting for responses in interactive mode
        if timeout is None:
            timeout = 3.0  # Shorter timeout to prevent excessive waiting
            
        # Send the command and wait for response
        success, response = self.send_command(escaped_command, wait_for_response=wait_for_ok, timeout=timeout)
        
        # When not waiting for OK, consider the command successful even with empty response
        if not wait_for_ok:
            if self.verbose:
                print(f"Command sent without waiting for response")
            return True, response
            
        return success, response
    
    def get_device_info(self) -> bool:
        """
        Query the device for model, version, etc.
        
        Returns:
            True if successful, False otherwise
        """
        # Use shorter timeout for device info queries
        query_timeout = 1.0
        
        print("Querying device information...", end="", flush=True)
        
        # Query version
        success, version_response = self.send_command("version", wait_for_response=True, timeout=query_timeout)
        if success and version_response:
            # Try to parse with regex first
            version_match = PATTERN_VERSION.search(version_response)
            if version_match:
                self.device_info['version'] = version_match.group(1)
            else:
                # Fall back to simple splitting
                try:
                    self.device_info['version'] = version_response.split(':')[1].strip()
                except (IndexError, AttributeError):
                    self.device_info['version'] = version_response
        
        print(".", end="", flush=True)
        
        # Query model
        success, model_response = self.send_command("model", wait_for_response=True, timeout=query_timeout)
        if success and model_response:
            # Try to parse with regex first
            model_match = PATTERN_MODEL.search(model_response)
            if model_match:
                self.device_info['model'] = model_match.group(1)
            else:
                # Fall back to simple splitting
                try:
                    self.device_info['model'] = model_response.split(':')[1].strip()
                except (IndexError, AttributeError):
                    self.device_info['model'] = model_response
        
        print(" Done")
        
        return bool(self.device_info)

    def get_device_config(self) -> Tuple[bool, Dict[str, str]]:
        """
        Get the device configuration
        
        Returns:
            Tuple of (success, config_dict)
        """
        config = {}
        
        # Send the command to get all configuration
        success, response = self.send_command(self.CMD_GET_CONFIG, wait_for_response=True, timeout=5.0)
        
        if not success or not response:
            return False, {}
            
        # Parse the configuration response
        try:
            # Split into lines and process each line
            for line in response.splitlines():
                line = line.strip()
                if not line or line.lower().startswith('ok'):
                    continue
                    
                # Split on the first equals sign
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    config[key] = value
                    
            return True, config
        except Exception as e:
            logging.error(f"Error parsing device configuration: {str(e)}")
            return False, {}
    
    def upload_file(self, file_path: str, target_dir: str = None, overwrite: bool = False, compress: bool = False) -> bool:
        """
        Upload a file to the device
        
        Args:
            file_path: Path to the file to upload
            target_dir: Target directory on the device (defaults to /sd/gcodes)
            overwrite: Whether to overwrite the file if it already exists
            compress: Whether to use QuickLZ compression for the file upload
            
        Returns:
            True if upload successful, False otherwise
        """
        if not self.stream:
            print("Error: Not connected to device")
            return False
            
        if not os.path.isfile(file_path):
            print(f"Error: File not found: {file_path}")
            return False
            
        # Get file name from path
        file_name = os.path.basename(file_path)
        
        # Set target directory (default if not specified)
        if not target_dir:
            target_dir = DEFAULT_GCODE_PATH
            
        # Make sure target directory exists and ends with a slash
        if not target_dir.endswith('/'):
            target_dir += '/'
            
        # Check if target directory exists
        print(f"Checking if target directory {target_dir} exists...")
        ls_cmd = f"ls -e -s {target_dir.replace(' ', self.SPACE_REPLACEMENT)}\n"
        self.stream.send(self.escape(ls_cmd).encode())
        
        # Wait a bit for the response
        time.sleep(0.5)
        response = self._read_response(1.0)
        
        if "No such file or directory" in response:
            print(f"Creating directory {target_dir}...")
            dir_create_cmd = f"mkdir {target_dir.replace(' ', self.SPACE_REPLACEMENT)} -e\n"
            self.stream.send(self.escape(dir_create_cmd).encode())
            time.sleep(0.5)  # Wait for directory creation
            
            # Check if directory was created
            self.stream.send(self.escape(ls_cmd).encode())
            response = self._read_response(1.0)
            if "No such file or directory" in response:
                print(f"Error: Failed to create directory {target_dir}")
                return False
                
        # Target file path on device - don't add .lz extension to the target path
        target_path = target_dir + file_name
            
        # Check if file already exists
        if not overwrite:
            print(f"Checking if file {target_path} already exists...")
            check_file_cmd = f"ls -e -s {target_path.replace(' ', self.SPACE_REPLACEMENT)}\n"
            self.stream.send(self.escape(check_file_cmd).encode())
            time.sleep(0.5)
            response = self._read_response(1.0)
            
            if target_path in response or file_name in response:
                print(f"Error: File {target_path} already exists. Use --overwrite to replace it.")
                return False
        
        # Prepare to upload
        try:
            print(f"Uploading {file_path} to {target_path}...")
            
            # Prepare the file for upload
            temp_file_path, size, is_compressed, error = prepare_file_for_upload(file_path, compress)
            if error:
                print(f"Error preparing file for upload: {error}")
                return False
                
            # Get the MD5 hash of the original file
            md5_hash = calculate_md5(file_path)
            if not md5_hash:
                print("Warning: Could not calculate MD5 hash")
                md5_hash = ""
            else:
                print(f"Original file MD5: {md5_hash}")
            
            # Send the upload command with the remote path
            # If we're compressing, add the .lz extension to the target path
            # The Carvera system expects compressed files to have the .lz extension
            remote_target_path = target_path + '.lz' if is_compressed else target_path
            # Important: Use `/` for path separators to match the syntax expected by the device
            normalized_path = remote_target_path.replace('\\', '/').replace(' ', self.SPACE_REPLACEMENT)
            upload_cmd = f"upload {normalized_path}\n"
            print(f"Sending upload command: {upload_cmd.strip()}")
            self.stream.send(self.escape(upload_cmd).encode())
            
            # Critical: Give the device time to process the command and prepare for file transfer
            time.sleep(2.0)
                
            # Now ready for XMODEM transfer
            try:
                # Use appropriate upload method based on connection type
                if self.connection_type == self.CONN_USB:
                    print("Using USB XMODEM transmission...")
                    success = self.usb_stream.upload(temp_file_path, md5_hash, self._upload_progress_callback)
                elif self.connection_type == self.CONN_WIFI:
                    print("Using WiFi XMODEM transmission...")
                    success = self.wifi_stream.upload(temp_file_path, md5_hash, self._upload_progress_callback)
                else:
                    raise ValueError("Unknown connection type")
                
                # Clean up temporary file
                cleanup_temp_files(temp_file_path)
                
                if success:
                    print(f"\nFile uploaded successfully to {target_path}")
                    return True
                else:
                    print("\nFile upload failed during XMODEM transmission")
                    return False
                    
            except Exception as e:
                print(f"\nError during file upload: {str(e)}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                # Try to clean up temporary files if there was an error
                cleanup_temp_files(temp_file_path)
                return False
                
        except Exception as e:
            print(f"Error during upload: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
            
    def _upload_progress_callback(self, packet_size: int, total: int, success: int, errors: int) -> None:
        """
        Callback to show upload progress
        
        Args:
            packet_size: Size of each data packet
            total: Total packets sent
            success: Number of successfully sent packets
            errors: Number of errors
        """
        if total > 0:
            percent = (success / total) * 100
            # Use carriage return to update same line
            sys.stdout.write(f"\rProgress: {percent:.1f}% ({success}/{total} packets) - Errors: {errors}")
            sys.stdout.flush()
    
    def upload_firmware(self, firmware_path: str) -> bool:
        """
        Upload firmware to the device
        
        Args:
            firmware_path: Path to firmware file
            
        Returns:
            True if upload successful, False otherwise
        """
        if not self.stream:
            print("Error: Not connected to device")
            return False
            
        if not os.path.isfile(firmware_path):
            print(f"Error: Firmware file not found: {firmware_path}")
            return False
            
        # Prepare firmware upload
        try:
            print(f"Preparing to upload firmware {firmware_path}...")
            
            # Send the firmware upload command
            upload_cmd = "firmware-update\n"
            self.stream.send(upload_cmd.encode())
            
            # Wait for upload prompt
            time.sleep(1.0)
            
            # Use appropriate upload method based on connection type
            try:
                if self.connection_type == self.CONN_USB:
                    print("Using USB XMODEM transmission...")
                    success = self.usb_stream.upload(firmware_path, "", self._upload_progress_callback)
                elif self.connection_type == self.CONN_WIFI:
                    print("Using WiFi XMODEM transmission...")
                    success = self.wifi_stream.upload(firmware_path, "", self._upload_progress_callback)
                else:
                    raise ValueError("Unknown connection type")
                
                if success:
                    print("\nFirmware uploaded successfully!")
                    print("Device will reboot to apply the update.")
                    return True
                else:
                    print("\nFirmware upload failed")
                    return False
                    
            except Exception as e:
                print(f"\nError during firmware upload: {str(e)}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                return False
                
        except Exception as e:
            print(f"Error preparing firmware upload: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
        
    @staticmethod
    def detect_connection() -> Tuple[int, str]:
        """
        Auto-detect the best connection method and device
        
        Returns:
            Tuple of (connection_type, device_address)
        """
        print("Scanning for devices...")
        
        # First try WiFi since it's more likely to be available
        print("Scanning for WiFi devices...")
        wifi_devices = WiFiStream.discover_devices(timeout=5)
        if wifi_devices:
            print(f"Found {len(wifi_devices)} device(s) on network")
            # Find the first available device
            for device in wifi_devices:
                # If the machine is not too busy, select it
                if not device.get('busy', True):
                    print(f"Selected WiFi device: {device['machine']} at {device['ip']}")
                    return (FirmwareUploader.CONN_WIFI, device['ip'])
                    
            # If no available device found but we have devices, use the first one
            if wifi_devices:
                device = wifi_devices[0]
                print(f"Selected WiFi device (busy): {device['machine']} at {device['ip']}")
                return (FirmwareUploader.CONN_WIFI, device['ip'])
        
        # Only check USB if WiFi devices aren't found and PySerial is available
        try:
            from carvera_cli.streams import SERIAL_AVAILABLE
            if SERIAL_AVAILABLE:
                print("Scanning for USB devices...")
                usb_ports = USBStream.list_ports()
                if usb_ports:
                    print(f"Found {len(usb_ports)} USB port(s)")
                    for port in usb_ports:
                        # Look for likely Carvera devices - this might need tuning
                        # based on how the device identifies itself
                        if "usb" in port['description'].lower() or "serial" in port['description'].lower():
                            print(f"Selected USB port: {port['port']} ({port['description']})")
                            return (FirmwareUploader.CONN_USB, port['port'])
        except ImportError:
            pass
                    
        # If we get here, we couldn't detect any devices
        print("No devices detected")
        return (None, "")

    def download_file(self, remote_file: str, local_path: str = None, timeout: float = 60.0) -> bool:
        """
        Download a file from the Carvera device using XMODEM protocol
        
        Args:
            remote_file: Path to the file on the device
            local_path: Local path to save the file (default: use filename from remote_file)
            timeout: Timeout in seconds
            
        Returns:
            True if successful, False otherwise
        """
        if not local_path:
            # Use the filename part of the remote path
            local_path = os.path.basename(remote_file)
        
        print(f"Downloading {remote_file} to {local_path}")
        
        # Prepare command
        command = f"download {remote_file}"
        
        # Get file MD5 first (used for verification after potential decompression)
        success, md5_result = self.execute_command(f"md5sum {remote_file}")
        if success and md5_result:
            try:
                # Format: "af4ac92685ecb511307ec3ae00f85412 /sd/gcodes/doomed.cnc"
                md5 = md5_result.split()[0]
                print(f"File MD5 (from device): {md5}") # Clarified source of MD5
            except (IndexError, ValueError):
                print(f"Unable to determine file MD5 from: {md5_result}")
                md5 = None
        else:
            md5 = None
        
        # Send the command and get initial response
        print(f"Sending download command: {command}")
        self.send_command(command, wait_for_response=False)
        
        # Create a temporary path for download
        tmp_file_path = local_path
        tmp_dir = os.path.dirname(tmp_file_path)
        if tmp_dir and not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)
        
        # Use XMODEM to receive the file
        if self.connection_type == self.CONN_WIFI:
            print(f"Using WiFi XMODEM reception with md5={md5}...")
            
            # Store the md5 for later verification after decompression
            if isinstance(md5, bytes):
                self.last_remote_md5 = md5.decode('utf-8')
            else:
                self.last_remote_md5 = md5
            
            try:
                # Create temp file path for download
                with open(tmp_file_path, 'wb') as f:
                    # Delegate download to the stream object
                    # Pass tmp_file_path, remote md5 (self.last_remote_md5), and a progress callback (optional)
                    # The stream's download method handles XMODEM internally
                    result = self.wifi_stream.download(
                        filename=tmp_file_path, 
                        local_md5=self.last_remote_md5, 
                        callback=None # Add callback if needed
                    )
                    
                # The result from wifi_stream.download indicates success/failure directly
                # It might return True/False, number of bytes, or None on error depending on implementation
                # We need to check the return value based on cli/src/carvera_cli/streams.py WiFiStream.download
                # Based on that code, it returns the result from modem.recv, which is bytes received or False/None on error
                
                # Assuming result is bytes received on success, or <= 0 / None on failure
                if result is None or (isinstance(result, int) and result <= 0):
                    print(f"\nError during file download (Stream reported failure)")
                    # Attempt cleanup of potentially partially downloaded file
                    if os.path.exists(tmp_file_path):
                        os.remove(tmp_file_path)
                    return False
                    
                print(f"\nDownload completed successfully: {result} bytes")
                
                # Files might be compressed using quicklz by the Carvera firmware
                # We need to decompress the file
                if result > 0 and QUICKLZ_AVAILABLE:
                    temp_compressed_path = tmp_file_path
                    decompressed_path = tmp_file_path + ".decompressed"
                    
                    print(f"Checking for compression...") # Refined message
                    
                    decompression_result = self._decompress_file(temp_compressed_path, decompressed_path)
                    
                    if decompression_result is True:
                        print(f"Decompression successful")
                        
                        self._replace_with_decompressed_file(temp_compressed_path, decompressed_path)
                        
                        # Verify using MD5 if we have the expected one from device
                        device_md5 = self.last_remote_md5
                        if device_md5 and len(device_md5) == 32:
                            file_md5 = calculate_md5(tmp_file_path)
                            if file_md5 and file_md5 == device_md5:
                                print(f"MD5 verification successful: {file_md5}")
                            else:
                                print(f"WARNING: MD5 mismatch after decompression!")
                                print(f" - Device Reported (for original file): {device_md5}")
                                print(f" - Calculated (decompressed data):   {file_md5}")
                        else:
                            print("Skipping MD5 verification (device did not provide valid MD5 for original file).")
                            
                    elif decompression_result is None:
                        # File did not appear to be compressed
                        print(f"File is not compressed.") # Refined message
                        # Clean up empty .decompressed file if it exists
                        if os.path.exists(decompressed_path):
                             try: os.remove(decompressed_path)
                             except OSError: pass 
                             
                    else: # decompression_result is False
                        print(f"ERROR: Decompression failed.") # Refined message
                        # Clean up potentially partial/empty .decompressed file
                        if os.path.exists(decompressed_path):
                             try: os.remove(decompressed_path)
                             except OSError: pass
                        
                elif not QUICKLZ_AVAILABLE:
                    print(f"NOTE: QuickLZ not available. Cannot check for or perform decompression.")
                
                # If we reached here without returning False earlier, assume download base success
                # The decompression status logging above informs the user about that specific step.
                return True
                
            except Exception as e:
                print(f"Error during download: {str(e)}")
                return False
                
        else:
            print("WiFi connection required for downloads")
            return False
    
    def _replace_with_decompressed_file(self, original_path: str, decompressed_path: str) -> bool:
        """
        Replace the original file with the decompressed file
        
        Args:
            original_path: Path to the original file
            decompressed_path: Path to the decompressed file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(decompressed_path):
                decompressed_size = os.path.getsize(decompressed_path)
                print(f"Replacing compressed file ({os.path.getsize(original_path)} bytes) with decompressed version ({decompressed_size} bytes)")
                
                # Read the decompressed file contents
                with open(decompressed_path, 'rb') as f_src:
                    decompressed_data = f_src.read()
                
                # Write the decompressed data to the original file
                with open(original_path, 'wb') as f_dst:
                    f_dst.write(decompressed_data)
                
                # Remove the temporary decompressed file
                os.remove(decompressed_path)
                
                # Verify file size after replacement
                final_size = os.path.getsize(original_path)
                
                # Verify the size
                if final_size != decompressed_size:
                    print(f"WARNING: File size mismatch after replacement: expected {decompressed_size}, got {final_size}")
                    return False
                
                return True
            else:
                print(f"Decompressed file not found: {decompressed_path}")
                return False
        except Exception as e:
            print(f"Error replacing file: {str(e)}")
            return False

    def _decompress_file(self, input_filename: str, output_filename: str) -> Optional[bool]:
        """
        Decompress a file using QuickLZ.

        Args:
            input_filename: Path to the compressed file
            output_filename: Path to save the decompressed file

        Returns:
            True if successful.
            None if the file does not appear to be QuickLZ compressed (header/block size).
            False if an error occurred during decompression.
        """
        try:
            # Open input and output files
            sum_checksum = 0
            read_size = 0
            file_size = os.path.getsize(input_filename)

            # print(f"Decompressing file: {input_filename} ({file_size} bytes)") # Removed print

            with open(input_filename, 'rb') as f_in, open(output_filename, 'wb') as f_out:
                # Read first few bytes to verify it's a compressed file
                header = f_in.read(4)
                f_in.seek(0)  # Reset position

                if not (header and len(header) == 4):
                    # print(f"Invalid header: {header}") # Removed print
                    return None # Not a QuickLZ file (or too small)

                # Check if this looks like a QuickLZ compressed file
                block_size = (header[0] << 24) + (header[1] << 16) + (header[2] << 8) + header[3]
                # print(f"Initial block size: {block_size}") # Removed print

                # QuickLZ uses a max block size internally, check against a reasonable limit
                # Also check if block size suggests it's not compressed (e.g., ASCII G-code)
                if block_size == 0 or block_size > 65536 or block_size < 8: # Adjusted checks
                #    print(f"Invalid block size: {block_size}") # Removed print
                    return None # Does not appear to be compressed

                # Process blocks
                block_count = 0
                total_decompressed = 0

                while read_size < (file_size - 2):
                    # Read block header (4 bytes for size)
                    block_header = f_in.read(BLOCK_HEADER_SIZE)
                    if not block_header: # End of file before checksum - might be okay if total size matches
                         if read_size == file_size:
                              break # Let checksum verify
                         else:
                              return False # Unexpected EOF
                    if len(block_header) < BLOCK_HEADER_SIZE:
                        # print(f"End of file reached after {block_count} blocks, {total_decompressed} bytes decompressed") # Removed print
                        # Allow reaching end if checksum is next
                        if read_size + len(block_header) == file_size -2:
                             break
                        return False # Error: Incomplete header read before end

                    # Calculate block size from header (big endian)
                    block_size = (block_header[0] << 24) + (block_header[1] << 16) + (block_header[2] << 8) + block_header[3]
                    if block_size == 0:
                        # print(f"Zero block size encountered at position {read_size}") # Removed print
                        break # Let checksum handle potential end-of-data

                    # Update read counter before reading block data
                    read_size += BLOCK_HEADER_SIZE

                    # Check if remaining file size is sufficient for block + checksum
                    if read_size + block_size + 2 > file_size:
                         return False # Error: block size exceeds remaining file data + checksum

                    # Read the compressed block
                    block = f_in.read(block_size)
                    if not block or len(block) < block_size:
                        # print(f"Incomplete block: expected {block_size} bytes, got {len(block) if block else 0}") # Removed print
                        return False # Error: Could not read full block

                    read_size += block_size

                    # Decompress the block
                    try:
                        decompressed_block = quicklz.decompress(block)
                        block_count += 1
                        total_decompressed += len(decompressed_block)
                    except Exception as e:
                        return False # Error during quicklz call

                    # Calculate checksum
                    for byte in decompressed_block:
                        sum_checksum = (sum_checksum + byte) & 0xFFFF

                    # Write the decompressed data
                    f_out.write(decompressed_block)

                # Verify checksum
                try:
                    # Ensure we are positioned correctly to read the checksum
                    # This assumes the loop exited cleanly or broke just before checksum
                    current_pos = f_in.tell()
                    if current_pos != file_size - 2:
                         # If loop finished early due to zero block size, seek to checksum
                         if current_pos < file_size - 2:
                              f_in.seek(file_size - 2)
                         else:
                              return False # Error: incorrect position for checksum reading

                    checksum_bytes = f_in.read(2)
                    if len(checksum_bytes) != 2:
                        # print(f"Failed to read checksum bytes") # Removed print
                        return False # Error: reading checksum
                    file_checksum = (checksum_bytes[0] << 8) + checksum_bytes[1]

                    # Compare checksums
                    # print(f"Checksum: file={file_checksum:04x}, calculated={sum_checksum:04x}") # Removed print
                    if file_checksum != sum_checksum:
                        # print(f"Checksum mismatch: file={file_checksum:04x}, calculated={sum_checksum:04x}") # Removed print
                        return False # Error: checksum mismatch

                    # print(f"Successfully decompressed {block_count} blocks, {total_decompressed} bytes") # Removed print
                    return True # Success!
                except Exception as e:
                    # print(f"Checksum verification error: {str(e)}") # Removed print
                    return False # Error during checksum verification
        except Exception as e:
            # print(f"Decompression failed: {str(e)}") # Removed print
            if os.path.exists(output_filename):
                 # Clean up partially written decompressed file on error
                try:
                    os.remove(output_filename)
                except OSError:
                    pass # Ignore errors during cleanup
            return False # Generic error during file handling 