import os
import time
import logging # Added for logging
import select # Add import for select module
from .streams import USBStream, WiFiStream, SERIAL_AVAILABLE # Ensure streams import is correct
from .utils import md5 # Ensure md5 utility is available
from .firmware_utils import validate_firmware_file # Import the validation function
import re # Added for re module

# ... XMODEM imports if needed directly, or assume modem is part of stream objects
# from .XMODEM import XMODEM # Example if needed

# Default timeout for commands (increased slightly)
DEFAULT_COMMAND_TIMEOUT = 15.0

class DeviceManager: # Renamed from FirmwareUploader
    """
    Manages communication and operations with a Carvera device.
    Handles device detection, connection, command execution, file transfers,
    configuration retrieval, and firmware updates.
    """

    # Connection type constants
    CONN_NONE = 0
    CONN_USB = 1
    CONN_WIFI = 2

    def __init__(self, callback=None, verbose=False):
        """
        Initializes the DeviceManager.

        Args:
            callback: Optional callback function for progress updates (e.g., file transfers).
            verbose: Enable verbose logging output if True.
        """
        # Configure logging for this class instance
        self.log = logging.getLogger("DeviceManager")
        # Removed setLevel - inherit from root logger configured in main.py
        
        # Remove handler setup - let root logger handle output
        # if not self.log.handlers:
        #     handler = logging.StreamHandler()
        #     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        #     handler.setFormatter(formatter)
        #     self.log.addHandler(handler)

        # Initialize streams without callback/verbose args
        self.usb_stream = USBStream()
        self.wifi_stream = WiFiStream()
        # Set verbose flag on streams after initialization
        self.usb_stream.verbose = verbose
        self.wifi_stream.verbose = verbose

        self.stream = None # Active stream object (USBStream or WiFiStream)
        self.connection_type = self.CONN_NONE
        self.callback = callback # Store callback for later use in upload/download
        self.verbose = verbose # Store verbose flag
        self.device_info = {} # To store model, version, etc.

        # Also configure the xmodem logger based on verbosity
        xmodem_logger = logging.getLogger('xmodem')
        if verbose:
            xmodem_logger.setLevel(logging.DEBUG)
        else:
            # Suppress xmodem INFO logs unless verbose
            xmodem_logger.setLevel(logging.WARNING)

    # --- Static Methods ---

    @staticmethod
    def detect_connection() -> tuple[int, str]:
        """
        Attempts to automatically detect a connected Carvera device (WiFi first, then USB).

        Returns:
            A tuple containing the connection type (CONN_WIFI or CONN_USB)
            and the device address (IP or COM port), or (CONN_NONE, "") if no device is found.
        """
        # Get logger for this class. Assume verbose flag controls level
        # Note: This might be better handled by passing logger or level in __init__
        log = logging.getLogger("DeviceManager") 
        
        # Try WiFi first
        log.info("Scanning for WiFi devices...")
        wifi_devices = WiFiStream.discover_devices(timeout=3)
        if wifi_devices:
            # Select the first available (not busy) device if possible
            available_devices = [d for d in wifi_devices if not d.get('busy', True)]
            selected_device = available_devices[0] if available_devices else wifi_devices[0]
            log.info(f"Found WiFi device: {selected_device['machine']} at {selected_device['ip']}")
            return DeviceManager.CONN_WIFI, selected_device['ip'] # Return only IP, port is standard

        # Try USB if no WiFi found or if SERIAL is available
        if SERIAL_AVAILABLE:
            log.info("Scanning for USB devices...")
            usb_ports = USBStream.list_ports()
            if usb_ports:
                # Prioritize ports with typical Carvera descriptions if possible
                carvera_ports = [p for p in usb_ports if 'ch340' in p['description'].lower() or 'usb-serial' in p['description'].lower()]
                selected_port = carvera_ports[0] if carvera_ports else usb_ports[0]
                log.info(f"Found USB device: {selected_port['port']} - {selected_port['description']}")
                return DeviceManager.CONN_USB, selected_port['port']
            else:
                log.info("No USB devices found.")
        else:
            log.info("USB scanning skipped (pyserial not installed or no devices found).")

        log.info("No devices detected.")
        return DeviceManager.CONN_NONE, ""

    # --- Connection Management ---

    def open(self, connection_type: int, address: str, skip_info: bool = False) -> bool:
        """
        Opens a connection to the device.

        Args:
            connection_type: CONN_USB or CONN_WIFI.
            address: The device address (COM port or IP address).
            skip_info: If True, skips querying device info after connecting.

        Returns:
            True if connection is successful, False otherwise.
        """
        self.close() # Ensure any existing connection is closed
        self.connection_type = connection_type

        try:
            if connection_type == self.CONN_USB:
                if not SERIAL_AVAILABLE:
                    self.log.error("Cannot connect via USB, pyserial is not installed.")
                    return False
                self.stream = self.usb_stream
            elif connection_type == self.CONN_WIFI:
                self.stream = self.wifi_stream
            else:
                self.log.error(f"Invalid connection type {connection_type}")
                return False

            self.log.info(f"Attempting to connect to {address}...")
            if self.stream.open(address):
                self.log.info("Connected successfully!")
                if not skip_info:
                    self.query_device_info()
                return True
            else:
                self.log.warning(f"Failed to connect to {address}.")
                self.stream = None
                self.connection_type = self.CONN_NONE
                return False
        except Exception as e:
            self.log.error(f"Error during connection: {e}", exc_info=self.verbose)
            self.stream = None
            self.connection_type = self.CONN_NONE
            return False

    def close(self) -> None:
        """Closes the connection to the device."""
        if self.stream:
            try:
                self.stream.close()
                self.log.info("Connection closed.")
            except Exception as e:
                self.log.error(f"Error closing stream: {e}", exc_info=self.verbose)
            finally:
                self.stream = None
                self.connection_type = self.CONN_NONE
                self.device_info = {}

    def query_device_info(self) -> None:
        """Queries and stores basic device information (model, version)."""
        if not self.stream:
            self.log.warning("Cannot query device info: Not connected.")
            return

        self.log.info("Querying device information...")
        self.device_info = {}
        success_model, resp_model = self.execute_command("model", wait_for_ok=True, timeout=5)
        if success_model and resp_model:
            # Example parsing, adjust based on actual device output format
            # Assuming format like "model = C1, 1, 5, 18174"
            parts = resp_model.split('=')
            if len(parts) > 1:
                 self.device_info['model'] = parts[1].strip()
            else:
                self.log.warning(f"Unexpected model response format: {resp_model}")
        else:
            self.log.warning("Failed to get model information.")

        success_ver, resp_ver = self.execute_command("version", wait_for_ok=True, timeout=5)
        if success_ver and resp_ver:
            # Try parsing "version = X.Y.Z" format first
            parts = resp_ver.split('=')
            if len(parts) > 1 and parts[0].strip().lower() == 'version':
                self.device_info['version'] = parts[1].strip()
            else:
                # Try parsing "Build Version: ..." format
                build_ver_match = re.search(r"Build Version:\s*(.*)", resp_ver, re.IGNORECASE)
                if build_ver_match:
                    # Extract the first line containing "Build Version:"
                    first_line = resp_ver.splitlines()[0]
                    build_ver = first_line.split(':', 1)[1].strip()
                    self.device_info['version'] = build_ver
                else:
                    # Log warning if neither format matches
                    self.log.warning(f"Unexpected version response format: {resp_ver}")
        else:
            self.log.warning("Failed to get version information.")

        if self.device_info:
            self.log.info(f"Device: model = {self.device_info.get('model', 'N/A')}")
            self.log.info(f"Version: version = {self.device_info.get('version', 'N/A')}")
        else:
             self.log.warning("Could not retrieve any device information.")


    # --- Command Execution ---

    def escape(self, value: str) -> str:
        """Escapes special characters for device commands."""
        # Based on Controller.py escape method
        return value.replace('?', '\x02').replace('&', '\x03').replace('!', '\x04').replace('~', '\x05').replace(' ', '\x01')

    def execute_command(self, command: str, wait_for_ok: bool = True, timeout: float = DEFAULT_COMMAND_TIMEOUT) -> tuple[bool, str]:
        """
        Sends a command to the device and optionally waits for a response.

        Args:
            command: The command string to send.
            wait_for_ok: If True, waits for an "ok" or error response.
                         If False, sends the command and returns immediately.
            timeout: Maximum time to wait for a response in seconds.

        Returns:
            A tuple (success: bool, response: str).
            'success' is True if the command was sent (and 'ok' received if wait_for_ok is True).
            'response' contains the accumulated response lines from the device.
        """
        if not self.stream:
            self.log.error("Cannot execute command: Not connected")
            return False, "Error: Not connected"

        # Ensure command ends with newline
        full_command = command if command.endswith('\n') else command + '\n'
        # Commands requiring escaping (like file paths) should be escaped *before* calling this method.
        # Here we just ensure the bytes are sent correctly.

        try:
            self.log.debug(f"Sending: {full_command.strip()}")
            self.stream.send(full_command.encode('utf-8'))

            if not wait_for_ok:
                self.log.debug("Command sent, not waiting for response.")
                return True, "" # Command sent, no response expected or waited for

            # Wait for response
            self.log.debug(f"Waiting for response (timeout={timeout}s)...")
            response_lines = []
            start_time = time.time()
            ok_received = False
            error_received = False
            buffer = b""
            last_data_time = None # Track time of last data received

            while time.time() - start_time < timeout:
                data_read = b"" # Track data read in this iteration
                # Use stream's method to check for data
                if self.stream.waiting_for_recv():
                    # Read available data up to buffer size
                    # Call recv differently based on connection type
                    if self.connection_type == self.CONN_USB:
                        data_read = self.stream.recv() # USBStream reads all available
                    else: # WiFi
                        data_read = self.stream.recv(1024) # WiFiStream needs buffer size
                        
                    if data_read:
                        self.log.debug(f"Raw Recv: {data_read!r}")
                        buffer += data_read
                        last_data_time = time.time() # Update time of last data receive
                    # else: data_read is None or empty, potentially connection closed?

                # --- Buffer Processing --- 
                # Check for termination patterns FIRST, before line splitting
                if buffer.endswith(b'ok\r\n'):
                    self.log.debug("Found 'ok\r\n' terminator.")
                    ok_received = True
                    buffer = buffer[:-4] # Remove terminator before line processing
                elif buffer.endswith(b'ok\n'):
                    self.log.debug("Found 'ok\n' terminator.")
                    ok_received = True
                    buffer = buffer[:-3] # Remove terminator before line processing
                elif buffer == b'\x04': # Check for EOT separately
                    self.log.debug("EOT (\x04) received as success signal.")
                    ok_received = True
                    buffer = b'' # Clear the EOT from buffer

                # Process complete lines from the (potentially trimmed) buffer
                lines_processed_this_iteration = 0
                while b'\n' in buffer:
                    line_bytes, buffer = buffer.split(b'\n', 1)
                    line = line_bytes.decode(errors='ignore').strip()
                    self.log.debug(f"Line Recv: {line}")
                    lines_processed_this_iteration += 1
                    if line: # Ignore empty lines (and potentially leftover 'ok')
                        # Check for errors within lines
                        if "error" in line.lower() or "fail" in line.lower() or "invalid" in line.lower() or "not found" in line.lower():
                            self.log.warning(f"Error indicator received: {line}")
                            error_received = True
                        # Add non-empty, non-ok lines to response
                        if line.lower() != 'ok': # Avoid adding ok if it was processed as a line
                             response_lines.append(line)
                
                # Update last_data_time if lines were processed (even from existing buffer)
                if lines_processed_this_iteration > 0:
                    last_data_time = time.time()

                # Check if termination was found
                if ok_received:
                    break # Exit the main while loop

                # Check for settle time if we received data but no terminator yet
                settle_duration = 0.5 # seconds to wait for more data after last receive
                if last_data_time is not None and not data_read and not ok_received:
                    if time.time() - last_data_time > settle_duration:
                        self.log.debug(f"No new data for {settle_duration}s after receiving data. Assuming command complete.")
                        ok_received = True # Treat as success
                        break

                # If no data was read *and* no previous data received, sleep briefly
                if not data_read and last_data_time is None:
                    time.sleep(0.01)
                # If no data read *but* we are waiting for settle time, shorter sleep
                elif not data_read and last_data_time is not None:
                     time.sleep(0.05)

            # --- Loop finished (timeout or ok_received) ---

            final_response = "\n".join(response_lines).strip() # Response lines collected (excluding 'ok')

            if ok_received:
                self.log.debug(f"Command successful. Response: {final_response}")
                return True, final_response
            elif error_received:
                 self.log.warning(f"Command likely failed (error indicator seen). Response: {final_response}")
                 return False, final_response # Return False on error, with the response
            else:
                self.log.warning(f"Timeout waiting for 'ok' or error. Response: {final_response}")
                # Add debug print for buffer content on timeout
                self.log.debug(f"Timeout buffer content: {buffer!r}")
                return False, f"Timeout waiting for response. Last lines: {final_response[-200:]}" # Timeout case

        except Exception as e:
            self.log.error(f"Exception sending/receiving command '{command}': {e}", exc_info=self.verbose)
            return False, str(e)

    # --- File Operations ---

    def _build_file_op_command(self, base_cmd: str, remote_path: str, *args) -> str:
        """Helper to build file operation commands with proper path handling & escaping."""
        norm_path = remote_path.replace('\\', '/')
        escaped_path = self.escape(norm_path)
        extra_args = " ".join(self.escape(arg.replace('\\', '/')) for arg in args)
        command = f"{base_cmd} {escaped_path}"
        if extra_args:
            command += f" {extra_args}"
        # Add the -e flag common in Controller.py commands if not already present
        # if ' -e' not in command:
        #      command += " -e" # Revisit if -e is needed for *all* file ops
        return command


    def upload_file(self, local_path: str, remote_path: str | None = None, target_dir: str | None = None, overwrite: bool = False, compress: bool = False) -> bool:
        """
        Uploads a general file (e.g., G-code) to the device.

        Args:
            local_path: Path to the local file to upload.
            remote_path: Optional. Full remote path including filename.
                         If provided, overrides target_dir.
            target_dir: Target directory on the device (default: '/sd/gcodes').
                        Used only if remote_path is not specified.
            overwrite: If True, allows overwriting existing files (behavior depends on firmware).
                       Note: Actual overwrite behavior is handled by the firmware.
            compress: If True, attempts QuickLZ compression before uploading (requires firmware support).

        Returns:
            True on success, False otherwise.
        """
        if not self.stream:
            self.log.error("Cannot upload file: Not connected")
            return False
        if not os.path.isfile(local_path):
            self.log.error(f"Local file not found: {local_path}")
            return False

        # Determine the final remote path
        if remote_path:
            final_remote_path = remote_path
            target_directory = os.path.dirname(remote_path)
        else:
            target_directory = target_dir if target_dir else "/sd/gcodes"
            filename = os.path.basename(local_path)
            final_remote_path = f"{target_directory.rstrip('/')}/{filename}"

        self.log.info(f"Target remote path determined as: {final_remote_path}")

        # --- Compression Handling (Placeholder) ---
        upload_local_path = local_path
        remote_upload_path = final_remote_path # Use the determined final path
        cleanup_compressed = False

        # TODO: Implement actual compression check and logic if needed
        if compress:
            self.log.warning("Compression requested but not implemented in this CLI version. Uploading original file.")
            # ... (Placeholder for future compression logic) ...
            # Example structure:
            # if self.device_supports_compression():
            #     try:
            #         compressed_path = self.compress_file_locally(local_path)
            #         if compressed_path:
            #             upload_local_path = compressed_path
            #             remote_upload_path = final_remote_path + ".lz" # Apply .lz to final path
            #             cleanup_compressed = True
            #         else: # Compression failed
            #             self.log.warning("Compression failed, uploading original.")
            #     except Exception as comp_e:
            #          self.log.error(f"Compression error: {comp_e}")
            # else:
            #     self.log.info("Compression not supported or enabled.")

        # --- MD5 Calculation ---
        try:
            # MD5 is calculated based on the original file content
            local_md5 = md5(local_path)
            self.log.debug(f"MD5 ({os.path.basename(local_path)}): {local_md5}")
        except Exception as e:
            self.log.error(f"Error calculating MD5 for {local_path}: {e}", exc_info=self.verbose)
            # if cleanup_compressed: os.remove(upload_local_path) # Cleanup if needed
            return False

        # --- Upload Command ---
        # Build the command using the potentially modified remote path (.lz)
        # Escape the path properly here
        upload_cmd_escaped = f"upload {self.escape(remote_upload_path.replace('\\', '/'))}"
        self.log.info(f"Sending upload command: {upload_cmd_escaped}")

        # Send command, don't wait for 'ok', expect XMODEM
        success, response = self.execute_command(upload_cmd_escaped, wait_for_ok=False)

        if not success:
             self.log.warning(f"Upload command might not have been acknowledged cleanly. Response: {response}")
             self.log.info("Attempting XMODEM transfer anyway...")
             time.sleep(0.5)
        else:
            self.log.debug(f"Upload command sent. Response: {response}")
            time.sleep(0.2)

        # --- XMODEM Transfer ---
        upload_result = False
        try:
            self.log.info(f"Starting XMODEM transfer of {os.path.basename(upload_local_path)}...")
            if self.stream and hasattr(self.stream, 'modem') and self.stream.modem:
                with open(upload_local_path, 'rb') as file_stream:
                    # Pass the ORIGINAL file's MD5 hash
                    upload_result = self.stream.modem.send(
                        stream=file_stream,
                        md5=local_md5, # MD5 of the original file content
                        retry=10,
                        callback=self.callback
                    )
                    upload_result = bool(upload_result)
            else:
                self.log.error("Stream object missing modem for XMODEM.")
        except Exception as e:
            self.log.error(f"Exception during XMODEM transfer: {e}", exc_info=self.verbose)
            # Try to cancel
            if self.stream and hasattr(self.stream, 'modem'): self.stream.modem.cancel()
        finally:
            pass # Remove redundant print("") # Newline after progress bar

        if upload_result:
            self.log.info(f"File '{os.path.basename(local_path)}' uploaded successfully to '{final_remote_path}'.")
            return True
        else:
            self.log.error(f"File upload failed for '{os.path.basename(local_path)}'.")
            return False


    def download_file(self, remote_path: str, local_path: str | None = None, timeout: float = 60.0) -> bool:
        """
        Downloads a file from the device.

        Args:
            remote_path: The full path to the file on the device.
            local_path: Optional. The local path to save the file.
                        If None, saves to the current directory with the same filename.
            timeout: Timeout for the download operation in seconds.

        Returns:
            True on success, False otherwise.
        """
        if not self.stream:
            self.log.error("Cannot download file: Not connected")
            return False

        filename = os.path.basename(remote_path)
        target_local_path = local_path if local_path else os.path.join(os.getcwd(), filename)
        target_local_dir = os.path.dirname(target_local_path)
        self.log.info(f"Attempting to download '{remote_path}' to '{target_local_path}'")

        # Create local directory if it doesn't exist
        if not os.path.isdir(target_local_dir):
            try:
                self.log.info(f"Creating local directory: {target_local_dir}")
                os.makedirs(target_local_dir)
            except Exception as e:
                self.log.error(f"Error creating directory {target_local_dir}: {e}", exc_info=self.verbose)
                return False

        # --- MD5 Calculation (if local file exists) ---
        local_md5 = ''
        if os.path.exists(target_local_path):
            self.log.debug(f"Local file '{target_local_path}' exists. Calculating MD5 for potential skip...")
            try:
                 local_md5 = md5(target_local_path)
                 self.log.debug(f"Existing local file MD5: {local_md5}")
            except Exception as e:
                 self.log.warning(f"Could not calculate MD5 for existing local file: {e}")
                 local_md5 = '' # Proceed with download

        # --- Download Command ---
        # Path needs escaping before sending
        download_cmd_escaped = f"download {self.escape(remote_path.replace('\\', '/'))}"
        self.log.info(f"Sending download command: {download_cmd_escaped}")

        # Send command, don't wait for 'ok', expect XMODEM start
        success, response = self.execute_command(download_cmd_escaped, wait_for_ok=False)

        if not success:
            self.log.warning(f"Download command might not have been acknowledged cleanly. Response: {response}")
            self.log.info("Attempting XMODEM transfer anyway...")
            time.sleep(0.5)
        else:
            self.log.debug(f"Download command sent. Response: {response}")
            time.sleep(0.2)

        # --- XMODEM Receive ---
        download_result = -1 # Use codes like main.py: >0 success, 0 same MD5, <0 error/cancel
        temp_local_path = target_local_path + ".tmp" # Download to temp file

        try:
            self.log.info(f"Starting XMODEM download to temporary file: {temp_local_path}...")
            if self.stream and hasattr(self.stream, 'modem') and self.stream.modem:
                 with open(temp_local_path, 'wb') as file_stream:
                    # The recv function should handle the XMODEM protocol and MD5 check
                    download_result = self.stream.modem.recv(
                        stream=file_stream,
                        md5=local_md5, # Pass existing local MD5 if available
                        retry=10,
                        timeout=timeout, # Use the provided timeout for the receive operation
                        callback=self.callback
                    )
            else:
                self.log.error("Stream object missing modem for XMODEM.")
                return False # Indicate failure immediately

        except Exception as e:
            self.log.error(f"Exception during XMODEM transfer: {e}", exc_info=self.verbose)
            download_result = -1 # Ensure failure code
        finally:
            print("") # Newline after progress bar
            # Clean up temp file if download failed partway through or was cancelled
            if download_result < 0 and os.path.exists(temp_local_path):
                self.log.debug(f"Cleaning up temporary file: {temp_local_path}")
                try:
                    os.remove(temp_local_path)
                except OSError as e_rem:
                    self.log.warning(f"Could not remove temporary file {temp_local_path}: {e_rem}")

        # --- Handle Download Result ---
        if download_result is None: # Should not happen with current XMODEM? Treat as error.
            self.log.error("Download failed (Result: None).")
            return False
        elif download_result > 0: # Download successful (new file or different MD5)
            self.log.info("XMODEM transfer successful.")
            try:
                # Replace original file with temp file
                self.log.debug(f"Moving {temp_local_path} to {target_local_path}")
                os.replace(temp_local_path, target_local_path)
                self.log.info(f"File saved successfully to: {target_local_path}")
                return True
            except OSError as e_mov:
                self.log.error(f"Error moving temporary file to final destination: {e_mov}")
                return False
        elif download_result == 0: # MD5 matched, file skipped
            self.log.info("Downloaded file MD5 matches existing local file. Download skipped.")
            # Clean up the temp file as it's not needed
            if os.path.exists(temp_local_path):
                 self.log.debug(f"Removing duplicate temporary file: {temp_local_path}")
                 try:
                     os.remove(temp_local_path)
                 except OSError as e_rem2:
                     self.log.warning(f"Could not remove temporary file {temp_local_path}: {e_rem2}")
            return True # Considered success as the correct file is present locally
        else: # download_result < 0 (Error or Cancelled)
            self.log.error("Download failed or was cancelled.")
            # Temp file should have been cleaned up in the finally block
            return False


    def upload_firmware(self, local_firmware_path: str) -> bool:
        """
        Uploads a firmware file (.bin) to the Carvera device.
        Performs validation, uploads to a temporary location in /sd/gcodes,
        and verifies the MD5 checksum after upload.

        Args:
            local_firmware_path: The local path to the firmware .bin file.

        Returns:
            True if the upload and MD5 check were successful, False otherwise.
        """
        if not self.stream:
            self.log.error("Cannot upload firmware: Not connected.")
            return False

        if not os.path.isfile(local_firmware_path):
            self.log.error(f"Firmware file not found: {local_firmware_path}")
            return False

        if not local_firmware_path.lower().endswith('.bin'):
             self.log.warning(f"Firmware file '{os.path.basename(local_firmware_path)}' does not end with .bin. Proceeding anyway.")

        # Upload to a temporary path in /sd/gcodes
        temp_remote_filename = "firmware.bin.tmp"
        remote_firmware_path = f"/sd/gcodes/{temp_remote_filename}"
        display_filename = os.path.basename(local_firmware_path)

        self.log.info(f"Preparing to upload firmware '{display_filename}' to temporary location '{remote_firmware_path}'...")

        # 0. Validate the firmware file before attempting upload
        self.log.info(f"Validating local firmware file: {local_firmware_path}")
        if not validate_firmware_file(local_firmware_path, self.log):
            self.log.error("Firmware validation failed. Aborting upload.")
            return False
        self.log.info("Local firmware validation passed.")

        # 1. Calculate MD5 hash of the local file
        try:
            local_md5 = md5(local_firmware_path)
            self.log.info(f"Local MD5: {local_md5}")
        except Exception as e:
            self.log.error(f"Error calculating MD5 for {local_firmware_path}: {e}", exc_info=self.verbose)
            return False

        # 2. Send the 'upload' command to the device
        # Path needs escaping for the command itself
        upload_cmd_escaped = f"upload {self.escape(remote_firmware_path.replace('\\', '/'))}"
        self.log.info(f"Sending firmware upload command: {upload_cmd_escaped}")

        # Don't wait for 'ok', expect XMODEM start
        success, response = self.execute_command(upload_cmd_escaped, wait_for_ok=False)

        if not success:
             # Even if execute_command reports failure (timeout waiting for 'ok'),
             # the command might have been received, and the device might be waiting for XMODEM.
             self.log.warning(f"Firmware upload command might not have been acknowledged cleanly. Response: {response}")
             self.log.info("Attempting XMODEM transfer anyway...")
             time.sleep(0.5) # Allow time for device to switch modes
        else:
            self.log.debug(f"Firmware upload command sent. Response: {response}")
            time.sleep(0.2) # Short delay

        # 3. Perform the XMODEM upload via the active stream's modem
        upload_result = False
        try:
            self.log.info("Starting XMODEM transfer for firmware...")
            
            # Ensure modem is initialized before use
            if not self.stream or not hasattr(self.stream, 'modem'):
                 self.log.error("Stream or modem not available for XMODEM transfer.")
                 return False
            
            # Import XMODEM here to avoid potential circular dependencies at module level
            from .xmodem import XMODEM 
            
            # Initialize modem if it's None, using appropriate mode based on connection
            if self.stream.modem is None:
                mode = 'xmodem8k' if self.connection_type == self.CONN_WIFI else 'xmodem'
                self.log.info(f"Initializing XMODEM modem (mode: {mode})...")
                self.stream.modem = XMODEM(self.stream.getc, self.stream.putc, mode=mode)
            
            # Proceed with the transfer
            # if self.stream and hasattr(self.stream, 'modem') and self.stream.modem: # Check already done
            with open(local_firmware_path, 'rb') as file_stream:
                # Use the stream's modem directly to send the raw binary data
                # Note: Compression is EXPLICITLY disabled for firmware
                upload_result = self.stream.modem.send(
                    stream=file_stream,
                    md5=local_md5,
                    retry=10,
                    callback=self.callback
                )
                upload_result = bool(upload_result) # Ensure boolean result
            # else:
            #     self.log.error("Stream object missing modem for XMODEM transfer.") # Should not be reached now
            #     return False

        except Exception as e:
            self.log.error(f"Exception during firmware XMODEM transfer: {e}", exc_info=self.verbose)
            # Attempt to cancel cleanly if possible
            if self.stream and hasattr(self.stream, 'modem'):
                try:
                    self.stream.modem.cancel()
                except Exception as cancel_e:
                    self.log.warning(f"Error trying to cancel modem: {cancel_e}")
            return False
        finally:
             pass # Remove redundant print("") # Newline after progress bar

        # 4. Handle result and verify remote MD5
        if upload_result:
            self.log.info("Firmware file transferred successfully via XMODEM.")

            # Add a delay to allow the device to finish writing the file
            delay_seconds = 2
            self.log.info(f"Waiting {delay_seconds} seconds before verifying MD5...")
            time.sleep(delay_seconds)

            # Explicitly clear any leftover buffer data before sending md5sum command
            self.log.debug("Clearing potential leftover buffer data...")
            while self.stream.waiting_for_recv():
                try:
                    _ = self.stream.recv()
                    self.log.debug(f"Discarded leftover data: {_!r}")
                    time.sleep(0.01) # Small pause to prevent tight loop if data streams continuously
                except Exception as e:
                    self.log.warning(f"Error while clearing buffer: {e}")
                    break # Exit loop on error
            self.log.debug("Buffer clearing attempt finished.")

            # Send a filesystem command to potentially clear any 'ignore next' state
            ls_dir = os.path.dirname(remote_firmware_path)
            ls_cmd = f"ls {self.escape(ls_dir.replace('\\', '/'))} -e" # Add -e flag like Controller.py
            self.log.debug(f"Sending list command ('{ls_cmd}') to potentially clear device state...")
            # Wait for the response to this command to ensure the buffer is cleared of the ignore message
            ls_success, ls_response = self.execute_command(ls_cmd, wait_for_ok=True, timeout=5)
            if not ls_success:
                 self.log.warning(f"Intermediate ls command failed or timed out. Response: {ls_response}")
            # time.sleep(0.2) # Delay might not be needed if we wait for response

            # 5. Verify MD5 on the device
            self.log.info(f"Verifying MD5 checksum of uploaded file on device: {remote_firmware_path}")
            md5_cmd = f"md5sum {self.escape(remote_firmware_path.replace('\\', '/'))}"
            self.log.debug(f"Sending MD5 command: {md5_cmd}")
            md5_success, md5_response = self.execute_command(md5_cmd, wait_for_ok=True, timeout=15) # Increased timeout for md5sum

            if md5_success and md5_response:
                # Check if the device explicitly ignored the command
                if "ok - ignore: [md5sum" in md5_response:
                    self.log.error(f"Device ignored the md5sum command. Response: {md5_response}")
                    self.log.error("Could not verify uploaded file checksum (device ignored command).")
                    return False
                    
                # Expected format: "<md5_hash> <filepath>"
                # Be robust: find the first 32-char hex string in the response
                match = re.search(r'\b([a-fA-F0-9]{32})\b', md5_response)
                if match:
                    remote_md5 = match.group(1)
                    self.log.info(f"Remote MD5: {remote_md5}")
                    if remote_md5.lower() == local_md5.lower():
                        self.log.info("✓ MD5 checksum verification successful!")
                        
                        # 6. Move verified file to final destination
                        final_firmware_path = "/sd/firmware.bin"
                        self.log.info(f"Moving verified temporary file to final destination: {final_firmware_path}")
                        mv_cmd = f"mv {self.escape(remote_firmware_path.replace('\\', '/'))} {self.escape(final_firmware_path.replace('\\', '/'))}"
                        self.log.debug(f"Sending move command: {mv_cmd}")
                        mv_success, mv_response = self.execute_command(mv_cmd, wait_for_ok=True, timeout=10)
                        
                        if mv_success:
                            self.log.info("Firmware file successfully moved.")
                            self.log.info("Next step: Manually reset the device to apply the firmware update.")
                            return True
                        else:
                            self.log.error(f"Failed to move firmware file to {final_firmware_path}. Response: {mv_response}")
                            self.log.error("Firmware is uploaded to temporary location but not moved.")
                            return False
                    else:
                        self.log.error(f"✗ MD5 checksum mismatch! Local={local_md5}, Remote={remote_md5}")
                        # Use logger for error message
                        self.log.error("Uploaded file checksum does not match local file.")
                        return False
                else:
                    self.log.error(f"Could not find a valid MD5 hash in the device response: {md5_response}")
                    # Use logger for error message
                    self.log.error("Could not verify uploaded file checksum.")
                    return False
            else:
                self.log.error(f"Failed to get MD5 checksum from device. Response: {md5_response}")
                # Use logger for error message
                self.log.error("Failed to verify uploaded file checksum on device.")
                return False
        else:
            self.log.error("Firmware transfer via XMODEM failed or was cancelled.")
            return False


    def get_device_config(self) -> tuple[bool, dict[str, str]]:
        """
        Downloads and parses the device configuration.

        Returns:
            A tuple (success: bool, config_dict: dict).
            'success' is True if config was retrieved and parsed.
            'config_dict' contains the configuration key-value pairs.
        """
        self.log.info("Retrieving device configuration...")
        # config-get-all requires escaping and the -e flag
        config_cmd = "config-get-all -e"
        success, response = self.execute_command(config_cmd, timeout=15)

        if not success:
            self.log.error(f"Failed to get config from device. Response: {response}")
            return False, {}

        config_dict = {}
        lines = response.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.lower() == 'ok': continue # Skip empty lines and 'ok'
            # Example line format: "machine.name=MyCarvera # Some comment"
            parts = line.split('#', 1)[0].strip() # Remove comments
            key_value = parts.split('=', 1)
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip()
                config_dict[key] = value
            else:
                 self.log.debug(f"Skipping unparsable config line: {line}")

        if not config_dict:
             self.log.warning("No configuration items parsed from response.")
             if self.verbose:
                 self.log.debug(f"Raw config response:\n{response}")
             return True, {} # Command succeeded, but no data parsed

        self.log.info(f"Parsed {len(config_dict)} configuration items.")
        return True, config_dict

    def get_status(self) -> str:
         """Gets the current device status using the '?' command."""
         # Status query does not need escaping
         success, response = self.execute_command("?", wait_for_ok=False, timeout=1.0)
         if success and response:
             # Status is typically within <...> brackets
             if response.startswith('<') and '>' in response:
                 # Extract content within the first <...> pair
                 end_index = response.find('>')
                 return response[:end_index + 1]
             self.log.debug(f"Unexpected status format: {response}")
             return response # Return raw response if format unexpected
         elif response:
             self.log.warning(f"Error getting status: {response}")
             return f"Error: {response}"
         else:
             self.log.warning("No response for status query (?)")
             return "Error: No response"

    def reset_device(self) -> bool:
        """Sends the reset command to the device."""
        self.log.info("Sending reset command to device...")
        # Reset command does not need escaping and does not return 'ok' usually
        success, response = self.execute_command("reset", wait_for_ok=False, timeout=5) 
        if not success:
            self.log.error(f"Failed to send reset command. Error: {response}")
        # Assume success if command was sent without immediate socket error
        return success

# ... (rest of the file, if any) 