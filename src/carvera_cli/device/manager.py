import logging
import re
import time
from typing import Optional, Tuple, Dict, Callable, Any
from functools import partial
import typing
from carvera_cli.streams.streams import Stream
    
# Constants for decompression from uploader.py
BLOCK_HEADER_SIZE = 4 

# Default timeout for commands (increased slightly)
DEFAULT_COMMAND_TIMEOUT = 15.0
# Time to wait for inactivity before considering a command finished
# (if no 'ok' is expected or received)
SETTLE_TIME = 0.3
# Longer timeout specifically for initial device info queries
INFO_QUERY_TIMEOUT = 5.0
CMD_EOT = b'\x04'
CMD_CAN = b'\x16'
# String versions of the special bytes for decoded string operations
CMD_EOT_STR = '\x04'
CMD_CAN_STR = '\x16'

# Command Type Constants (Internal use)
CMD_TYPE_GCODE = 1
CMD_TYPE_GRBL = 2
CMD_TYPE_SIMPLESHELL = 3
CMD_TYPE_SIMPLESHELL_EOT = 4
CMD_TYPE_XMODEM_TRIGGER = 5

# Forward declare DownloadTransport to avoid circular imports if needed for type hints
# This assumes DownloadTransport will be in transport/download.py
if typing.TYPE_CHECKING:
    from ..transport.download import DownloadTransport

class DeviceManager:
    """
    Manages communication and operations with a Carvera device via a provided Stream.
    Handles command execution via dynamic attribute access (e.g., dm.mem()),
    file transfers, configuration retrieval, and firmware updates.
    Connection management is handled externally.
    """

    def __init__(self, stream: Stream, address: str, verbose: bool = False):
        """
        Initializes the DeviceManager with an active communication stream.

        Args:
            stream: An already opened Stream object (USBStream or WiFiStream instance).
            address: The address associated with the stream (COM port or IP).
            callback: Optional callback function for progress updates (e.g., file transfers).
            verbose: Enable verbose logging output if True.
            skip_info: If True, skips querying device info upon initialization.
        """
        self.log = logging.getLogger("DeviceManager")
        self.stream: Optional[Stream] = stream
        self.address: str = address
        self.verbose = verbose
        self.device_info: Dict[str, str] = {}

        if not self.stream:
             self.log.error("DeviceManager initialized without a valid stream!")
             raise ValueError("DeviceManager requires a valid Stream object.")

        xmodem_logger = logging.getLogger('xmodem')
        if verbose:
            xmodem_logger.setLevel(logging.DEBUG)
        else:
            xmodem_logger.setLevel(logging.WARNING)

        self.log.debug(f"DeviceManager initialized with stream for address: {self.address}")
        self.log.debug(f"Stream object: {self.stream}")

    def close(self) -> None:
        """Closes the connection stream held by the manager."""
        if self.stream:
            try:
                self.stream.close()
                self.log.debug(f"Stream closed for address: {self.address}")
            except Exception as e:
                self.log.error(f"Error closing stream: {e}", exc_info=self.verbose)
            finally:
                self.stream = None
                self.address = ""
                self.device_info = {}
        else:
             self.log.debug("Close called but no active stream.")

    # --- Command Execution ---

    def _classify_command(self, command: str) -> int:
        """Classifies the command type based on its prefix or structure."""
        cmd_lower = command.lower().strip()
        # Check for g-code/m-code (starts with G, M, T followed by digits)
        if re.match(r"^[gmt]\d+", cmd_lower):
            return CMD_TYPE_GCODE
        # Check for GRBL (starts with $)
        elif cmd_lower.startswith('$'):
            return CMD_TYPE_GRBL
        # Check for XMODEM triggers (upload/download commands)
        elif cmd_lower.startswith("upload ") or cmd_lower.startswith("download "):
            return CMD_TYPE_XMODEM_TRIGGER
        # Check for SimpleShell EOT commands
        elif "-e" in cmd_lower:
            return CMD_TYPE_SIMPLESHELL_EOT
        else:
            return CMD_TYPE_SIMPLESHELL
        
    def _escape(self, value: str) -> str:
        return (value.replace(' ', '\x01')
                    .replace('?', '\x02')
                    .replace('&', '\x03')
                    .replace('!', '\x04')
                    .replace('~', '\x05'))

    def _unescape(self, value: str) -> str:
        return (value.replace('\x01', ' ')
                    .replace('\x02', '?')
                    .replace('\x03', '&')
                    .replace('\x04', '!')
                    .replace('\x05', '~'))

    def _build_full_command(self, command_name: str, *args: Any) -> str:
        """Builds the full command string from name and arguments."""
        # Simple joining for now. Assumes args are strings or stringifiable.
        # Escaping should happen *after* building the full string if needed by the command type
        # or applied to specific arguments (like paths) before passing them.
        full_command = command_name
        if args:
            full_command += " " + " ".join(map(str, args))
        return full_command.strip()

    def __getattr__(self, name: str) -> Callable[..., Tuple[bool, str]]:
        """
        Dynamically provides methods for sending device commands for names that
        don't correspond to existing methods (like cat, ls, md5, stat, etc.).
        """
        # Crucially, check hasattr *first*. If an explicit method like 'cat' exists,
        # Python's default mechanism handles it *before* __getattr__ is called.
        # This check primarily prevents intercepting private methods ('_') or attributes
        # that might somehow slip through the initial check.
        if name.startswith('_') or hasattr(type(self), name):
             # If it's a standard attribute/method, raise AttributeError to let Python handle it normally.
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}' or it's handled explicitly.")

        # Handle potential period-to-underscore mapping (e.g., m496.3 -> m496_3)
        if '.' in name:
            potential_handler_name = name.replace('.', '_')
            # Check if the handler exists explicitly on the class to avoid nested __getattr__
            if hasattr(type(self), potential_handler_name):
                # Get the handler (known to exist on class/instance now)
                handler = getattr(self, potential_handler_name)
                # If the explicit handler exists AND is callable, return it directly.
                if callable(handler):
                    self.log.debug(f"__getattr__ redirecting '{name}' to specific callable handler '{potential_handler_name}'")
                    return handler
                else:
                    self.log.debug(f"__getattr__ found explicit attribute '{potential_handler_name}' for '{name}' but it is not callable, proceeding with dynamic handler for '{name}'.")
            else:
                 # Log if we checked but didn't find an explicit handler
                 self.log.debug(f"__getattr__ found '.' in '{name}' but no specific handler '{potential_handler_name}' exists on class, proceeding with dynamic handler for '{name}'.")

        # If no period, or specific underscore handler was not found/callable on class, create the dynamic handler.
        # Crucially, uses the original 'name' passed to __getattr__.
        self.log.debug(f"__getattr__ creating dynamic handler for command: '{name}'")

        # Define the actual function that will be returned and called
        def dynamic_command_handler(*args: Any, timeout: Optional[float] = None, **kwargs: Any) -> Tuple[bool, str]:
            """Handles dynamically generated command calls (G-code, GRBL, SimpleShell)."""
            if not self.stream:
                self.log.error(f"Cannot execute dynamic command '{name}': No active stream.")
                return False, "Error: Not connected"

            effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
            
            # Classify first based on original name to determine case
            captured_name = name # Use the original name captured from outer scope
            prelim_command = self._build_full_command(captured_name, *args)
            cmd_type = self._classify_command(prelim_command)
            
            # Determine final command case
            if cmd_type == CMD_TYPE_GCODE:
                final_command_name = captured_name.upper()
            else:
                final_command_name = captured_name # Keep original case for non-GCODE
                
            # Build the final command string with the correct case
            full_command = self._build_full_command(final_command_name, *args)
            self.log.debug(f"Dispatching dynamic command: '{full_command}' (Args: {args}, Timeout: {effective_timeout}) (Original Name: '{captured_name}')")

            # Re-classify based on the final command string if needed (should be same type)
            # cmd_type = self._classify_command(full_command) # Optional re-check, likely unnecessary

            try:
                # Removed stream_output=False as it's the default and handled within _send_command_and_wait
                if cmd_type == CMD_TYPE_GCODE:
                    return self._execute_gcode(full_command, effective_timeout)
                elif cmd_type == CMD_TYPE_GRBL:
                    return self._execute_grbl(full_command, effective_timeout)
                elif cmd_type == CMD_TYPE_SIMPLESHELL:
                    # eot=False is default for _execute_simpleshell
                    return self._execute_simpleshell(full_command, effective_timeout)
                elif cmd_type == CMD_TYPE_SIMPLESHELL_EOT:
                     # Pass eot=True for simple shell -e flag
                    return self._execute_simpleshell(full_command, effective_timeout, eot=True)
                elif cmd_type == CMD_TYPE_XMODEM_TRIGGER:
                    # Timeout might not be directly applicable here, but pass it for consistency
                    return self._execute_xmodem_trigger(full_command, effective_timeout)
                else:
                    self.log.error(f"Unknown command type for dynamic command: {full_command}")
                    return False, f"Error: Unknown command type for '{name}'"
            except Exception as e:
                self.log.error(f"Error executing dynamic command '{full_command}': {e}", exc_info=self.verbose)
                return False, f"Error: Exception during dynamic command '{full_command}' ({e})"

        # Return the handler function itself. It captures 'name' from the outer scope.
        return dynamic_command_handler

    def execute(self, raw_command_string: str, timeout: Optional[float] = None) -> Tuple[bool, str]:
        """Executes a raw, pre-formatted command string on the device."""
        if not self.stream:
            self.log.error(f"Cannot execute raw command '{raw_command_string}': No active stream.")
            return False, "Error: Not connected"

        self.log.debug(f"Executing raw string via execute(): '{raw_command_string}'")
        parts = raw_command_string.strip().split(None, 1)
        if not parts:
            self.log.error("Cannot execute empty command string.")
            return False, "Error: Empty command"

        command_base = parts[0]
        # Convert command base to lowercase for case-insensitive lookup
        command_base = command_base.lower()
        
        args_str = parts[1] if len(parts) > 1 else ""
        # Simple space splitting for args. Does not handle quotes currently.
        args = args_str.split()

        try:
            # Use getattr. This will:
            # 1. Find explicit methods like 'cat', 'ls', 'm114' if command_base matches.
            # 2. Trigger __getattr__ if no explicit method exists, getting the dynamic_command_handler.
            handler = getattr(self, command_base)

            # Ensure the retrieved attribute is actually callable
            if not callable(handler):
                 # Use command_base for accurate error message
                 raise AttributeError(f"Attribute '{command_base}' found but is not callable.")

            self.log.debug(f"execute() dispatching to handler '{command_base}' with args: {args}, timeout: {timeout}")
            # Call the handler (explicit method or dynamic one).
            # Pass timeout as a keyword argument.
            return handler(*args, timeout=timeout)

        except AttributeError:
            # This catches cases where getattr fails (no explicit method AND __getattr__ raises AttributeError)
            # Or if the retrieved attribute is not callable.
            self.log.error(f"Command handler '{command_base}' not found or is not executable.")
            return False, f"Error: Unknown or non-executable command handler '{command_base}'"
        except Exception as e:
            # Catch any other unexpected errors during handler invocation
            self.log.error(f"Error during execute() dispatch for command '{raw_command_string}' using handler '{command_base}': {e}", exc_info=self.verbose)
            return False, f"Error: Exception during execute for '{raw_command_string}' ({e})"

    # --- Specific Command Execution Handlers ---

    def _send_command_and_wait(
        self,
        full_command: str,
        timeout: float,
        wait_for_ok: bool = False,
        stream_output: bool = False
    ) -> Tuple[bool, str]:
        """Core logic for sending command, waiting for response, handling delimiter/ok.
           All commands now complete on EOT detection, with semantics preserved.
        """
        if not self.stream:
            return False, "Error: Not connected"

        full_command_bytes = (full_command + '\n').encode('utf-8')
        response_lines = [] if not stream_output else None
        start_time = time.time()
        
        self.log.debug(f"Sending: {full_command!r} (wait_for_ok={wait_for_ok})")
        self.stream.send(full_command_bytes)
        # Always send our backup EOT command to ensure completion
        self.stream.send(b"echo " + CMD_EOT + b'\n')
        
        self.log.debug("Waiting for response lines...")

        # Track command completion state
        command_complete = False
        error_message = None
        line_count = 0  # Counter for tracking number of lines processed
        last_non_eot_line = ""  # Store the last line before EOT for ok check
        ok_received = False # Flag to track if 'ok' was received at any point
        
        while not command_complete:
            # Check for timeout
            if time.time() - start_time > timeout:
                self.log.warning(f"Command timeout ({timeout}s) exceeded for: {full_command!r}")
                return False, f"Error: Timeout waiting for response. Partial response: {response_lines}"
            
            # Read next line
            try:
                line_bytes = self.stream.readline()
                line_count += 1
            except Exception as e:
                self.log.error(f"Stream read error: {e}", exc_info=self.verbose)
                return False, f"Error: Communication failed during readline ({e})"
                
            if not line_bytes:
                continue
                
            # Decode line for processing
            line_decoded = line_bytes.decode(errors='ignore')
            line_stripped = line_decoded.strip()
            self.log.debug(f"Line {line_count} Recv: {line_stripped!r}")
            
            # Check if this line is 'ok' (case-insensitive)
            if line_stripped.lower() == "ok":
                ok_received = True
                self.log.debug("Received 'ok' confirmation.")
            
            # Store the line before EOT detection for "ok" check (if applicable)
            if CMD_EOT not in line_bytes and line_stripped:
                last_non_eot_line = line_stripped.lower()
            
            # Check for EOT - this is now our universal completion condition
            if CMD_EOT in line_bytes:
                self.log.debug(f"EOT detected in line: {line_stripped!r}")
                
                # Case 1: Just our artificial echo EOT response (echo: \x04)
                if "echo: " in line_stripped and line_stripped.endswith("\x04"):
                    self.log.debug("Detected artificial echo EOT")
                    # Don't add the echo command output to response
                
                # Case 2: Natural EOT followed by our echo (\x04echo: \x04)
                elif line_stripped.startswith("\x04") and "echo: " in line_stripped:
                    self.log.debug("Detected natural EOT followed by echo")
                    # Parse out any content before our echo command
                    content = line_decoded.split("echo:")[0]
                    if content.strip() and content.strip() != "\x04":
                        # Only add non-EOT content
                        cleaned_content = content.replace(CMD_EOT_STR, "").strip()
                        if cleaned_content:
                            if stream_output:
                                print(cleaned_content, end='')
                            else:
                                response_lines.append(cleaned_content)
                
                # Case 3: Just a natural EOT (\x04)
                else:
                    # Strip the EOT character and process remaining content
                    content = line_decoded.replace(CMD_EOT_STR, "").strip()
                    if content:
                        if stream_output:
                            print(content, end='')
                        else:
                            response_lines.append(content)
                            
                # All EOT cases result in command completion
                command_complete = True
                continue
                    
            if CMD_CAN in line_bytes:
                self.log.warning("CAN (cancel) byte received.")
                # Find the CAN character position in the decoded string
                content = line_decoded[:line_decoded.find(CMD_CAN_STR) if CMD_CAN_STR in line_decoded else len(line_decoded)]
                if stream_output:
                    print(content, end='')
                return False, "Error: Command cancelled by device"
                
            # Check for error indicators in any line
            if any(indicator in line_stripped.lower() for indicator in ["error", "fail", "invalid", "not found", "alarm"]):
                self.log.warning(f"Error indicator received: {line_stripped}")
                error_message = f"Error received from device: {line_stripped}"
                
            # Process normal output lines
            if stream_output:
                print(line_decoded, end='')
            else:
                if line_stripped:
                    response_lines.append(line_stripped)
        
        # Add final newline for streamed output
        if stream_output:
            print()
            
        # Return error if detected
        if error_message:
            return False, error_message
            
        # For G-code commands, check if 'ok' was received at any point
        if wait_for_ok and not ok_received:
            # Use last_non_eot_line for context in the error message, if available
            error_context = f" Last line received: {last_non_eot_line!r}" if last_non_eot_line else ""
            return False, f"Error: Expected 'ok' confirmation, but none received.{error_context}"
            
        # Success case
        if stream_output:
            self.log.debug(f"Command complete after {line_count} lines (streaming mode)")
            return True, ""  # No buffered response when streaming
        else:
            self.log.debug(f"Command complete after {line_count} lines with {len(response_lines)} non-empty lines")
            return True, "\n".join(response_lines)

    def _execute_gcode(self, full_command: str, timeout: float) -> Tuple[bool, str]:
        """
        Executes a G-code command, waiting for 'ok' response.
        Now uses universal EOT for completion, but still checks for 'ok' for success.
        """
        self.log.debug(f"Executing GCODE: {full_command}")
        return self._send_command_and_wait(full_command, timeout, wait_for_ok=True, stream_output=False)

    def _execute_grbl(self, full_command: str, timeout: float) -> Tuple[bool, str]:
        """
        Executes a GRBL command ($ prefixed).
        Now uses universal EOT for completion.
        """
        self.log.debug(f"Executing GRBL: {full_command}")
        return self._send_command_and_wait(full_command, timeout, wait_for_ok=False, stream_output=False)

    def _execute_simpleshell(self, full_command: str, timeout: float, eot: bool = False) -> Tuple[bool, str]:
        """
        Executes a SimpleShell command.
        Now uses universal EOT for completion. The eot parameter is kept for backward compatibility
        but no longer affects behavior since all commands use EOT detection.
        """
        self.log.debug(f"Executing SimpleShell: {full_command}")
        return self._send_command_and_wait(full_command, timeout, wait_for_ok=False, stream_output=False)

    def _execute_xmodem_trigger(self, full_command: str, timeout: float) -> Tuple[bool, str]:
        """
        Sends an XMODEM trigger command (upload/download) and returns immediately.
        This special case doesn't wait for completion.
        """
        if not self.stream: return False, "Error: Not connected"
        self.log.debug(f"Executing XMODEM Trigger: {full_command}")
        try:
            full_command_bytes = (full_command + '\n').encode('utf-8')
            self.stream.send(full_command_bytes)
            # Allow a very brief moment for command to be processed by firmware
            time.sleep(0.1)
            return True, "" # Assume success if send didn't fail
        except Exception as e:
            self.log.error(f"Failed to send XMODEM trigger '{full_command}': {e}", exc_info=self.verbose)
            return False, f"Error sending XMODEM trigger: {e}"

    # --- Public Command Methods ---

    def cat(self, remote_path: str, *args, timeout: Optional[float] = None) -> Tuple[bool, str]:
        """Streams the content of a remote file to stdout using the 'cat' command."""
        if not self.stream: return False, "Error: Not connected"
        effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        
        # Build the full cat command with escaped path
        escaped_path = self._escape(remote_path)
        all_args = [escaped_path] + list(args)
        full_command = self._build_full_command("cat", *all_args)

        # Call the generic handler with streaming enabled
        success, error_message = self._send_command_and_wait(
            full_command=full_command, 
            timeout=effective_timeout, 
            wait_for_ok=False, 
            stream_output=True # Enable streaming
        )
        
        # Return status and any error message (success returns "")
        return success, error_message
        
    def ls(self, remote_path: Optional[str] = None, *args, timeout: Optional[float] = None) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """
        Executes 'ls -s' command on the specified path and returns structured results.
        
        Args:
            remote_path: The path to list files from. Defaults to /sd/gcodes if not provided.
                         Any trailing slashes will be removed as they're not supported by the firmware.
            *args: Additional arguments to pass to ls.
            timeout: Optional timeout override for this command.
            
        Returns:
            Tuple of (success, file_dict) where file_dict contains file information
            with keys as filenames and values as dicts with size and timestamp.
        """
        if not self.stream: 
            return False, {"error": "Not connected"}
        
        # Default to /sd/gcodes if no path provided
        if remote_path is None:
            remote_path = "/sd/gcodes"
        
        # Remove any trailing slashes from the path as they're not supported by the firmware
        remote_path = remote_path.rstrip('/')
            
        effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        
        # Build the command with -s flag for size and timestamp
        ls_args = ["-e -s", self._escape(remote_path)] + list(args)
        full_command = self._build_full_command("ls", *ls_args)
        
        # Execute the command
        success, output = self._send_command_and_wait(
            full_command=full_command,
            timeout=effective_timeout,
            wait_for_ok=False,
            stream_output=False  # We need to process the output
        )
        
        if not success:
            return False, {"error": output}
            
        # Parse output into structured format
        result = {}
        lines = output.strip().split('\n')
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 3:
                # Unescape the filename to convert \x01 back to spaces
                filename = self._unescape(parts[0])
                result[filename] = {
                    "size": int(parts[1]),
                    "timestamp": parts[2]
                }
        
        return True, result
    
    def md5(self, remote_path: str, *args, timeout: Optional[float] = None) -> Tuple[bool, str]:
        """
        Executes 'md5sum' command on the specified file and returns the result.
        
        Args:
            remote_path: The path to the file to calculate MD5 checksum for.
            timeout: Optional timeout override for this command.
            
        Returns:
            Tuple of (success, response) where response contains the MD5 checksum.
        """
        if not self.stream: 
            return False, "Error: Not connected"
        
        effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        
        # SPECIAL CASE: md5sum does NOT convert 0x01 to spaces in the firmware,
        # so we must NOT escape the filepath for this specific command
        # Do NOT use _escape() here
        full_command = f"md5sum {remote_path}"
        
        # Execute the command
        success, output = self._send_command_and_wait(
            full_command=full_command,
            timeout=effective_timeout,
            wait_for_ok=False,
            stream_output=False  # We need to process the output
        )
        
        if not success:
            return False, output
            
        # Parse the MD5 output (format: md5_hash filename)
        # Ensure we return just the hash and strip any whitespace
        output = output.strip()
        md5_parts = output.split()
        if len(md5_parts) >= 1:
            return True, md5_parts[0].strip()
        
        return True, output.strip()
    
    def filesystem_md5(self, remote_path: str, *args, timeout: Optional[float] = None) -> Tuple[bool, str]:
        """
        Retrieves the stored MD5 checksum from the filesystem by reading the 
        corresponding .md5 file.
        
        Args:
            remote_path: The path to the file whose MD5 checksum to retrieve.
            timeout: Optional timeout override for this command.
            
        Returns:
            Tuple of (success, response) where response contains the stored MD5 checksum.
        """
        if not self.stream: 
            return False, "Error: Not connected"
        
        # Construct the path to the MD5 file
        path_parts = remote_path.rsplit('/', 1)
        if len(path_parts) != 2:
            return False, f"Error: Cannot determine parent directory for {remote_path}"
            
        parent_dir, filename = path_parts
        md5_file_path = f"{parent_dir}/.md5/{filename}"
        # Escape the MD5 file path
        escaped_md5_path = self._escape(md5_file_path)
        
        effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        
        # Use cat command to read the MD5 file
        full_command = self._build_full_command("cat", escaped_md5_path)
        
        # Execute the command
        success, output = self._send_command_and_wait(
            full_command=full_command,
            timeout=effective_timeout,
            wait_for_ok=False,
            stream_output=False  # We need to process the output
        )
        
        if not success:
            return False, output
            
        # Return the stripped MD5 checksum
        return True, output.strip()
    
    def stat(self, remote_path: str, *args, timeout: Optional[float] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Retrieves comprehensive information about a file on the device including size,
        timestamp, compressed size (if available), and MD5 checksum.
        
        Args:
            remote_path: The path to the file to get information about.
            timeout: Optional timeout override for commands.
            
        Returns:
            Tuple of (success, info_dict) where info_dict contains file metadata.
        """
        if not self.stream: 
            return False, {"error": "Not connected"}
        
        effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        
        # Get file basename and parent directory
        path_parts = remote_path.rsplit('/', 1)
        if len(path_parts) != 2:
            return False, {"error": f"Cannot determine parent directory for {remote_path}"}
            
        parent_dir, filename = path_parts
        result = {
            "filename": filename,
            "path": remote_path
        }
        
        # Get file basic info using structured ls
        ls_success, ls_output = self.ls(parent_dir, timeout=effective_timeout)
        if not ls_success:
            return False, {"error": f"Failed to get file info: {ls_output.get('error', 'Unknown error')}"}
        
        # The ls method now handles unescaping filenames internally
        # So filename should be a standard string with spaces
        
        # Check if the file exists in the directory
        if filename not in ls_output:
            return False, {"error": f"File {filename} not found in {parent_dir}"}
        
        # Extract basic file info from ls output
        file_info = ls_output[filename]
        result["size"] = file_info["size"]
        result["timestamp"] = file_info["timestamp"]
        
        # Check for compressed version in the .lz directory
        compressed_path = f"{parent_dir}/.lz"
        compressed_ls_success, compressed_ls_output = self.ls(compressed_path, timeout=effective_timeout)
        if compressed_ls_success and filename in compressed_ls_output:
            compressed_info = compressed_ls_output[filename]
            result["compressed_size"] = compressed_info["size"]
            result["compressed_timestamp"] = compressed_info["timestamp"]
        
        # Get MD5 checksum
        md5_success, md5_output = self.md5(remote_path, timeout=effective_timeout)
        if md5_success:
            result["md5"] = md5_output
        
        # Get stored filesystem MD5 (if available)
        fs_md5_success, fs_md5_output = self.filesystem_md5(remote_path, timeout=effective_timeout)
        if fs_md5_success:
            result["filesystem_md5"] = fs_md5_output
        
        return True, result

    def m114(self, *args, timeout: Optional[float] = None) -> Tuple[bool, str]:
        """
        Executes M114 (Get Current Position) and parses the specific 'ok c: ...' response.
        Uses _send_command_and_wait and processes the output.
        Ignores any passed arguments.
        """
        if not self.stream:
            return False, "Error: Not connected"

        effective_timeout = timeout if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        full_command = "M114" # M114 doesn't take arguments

        self.log.debug(f"Executing: {full_command!r} (Special M114 handling)")
        
        success, output = self._send_command_and_wait(
            full_command=full_command,
            timeout=effective_timeout,
            wait_for_ok=False,      # We handle the specific 'ok c:' format
            stream_output=False     # We need the output string to parse
        )

        # Check for communication errors first
        if not success:
            self.log.warning(f"M114 command failed during communication: {output}")
            return False, output

        # Communication succeeded, now parse the output for the specific format
        response_lines = output.strip().split('\n')
        for line in response_lines:
            # Use lower() for case-insensitive check
            if line.lower().startswith("ok c:"):
                # Found the expected response, strip prefix and return
                # Note: We return the original line minus prefix, preserving original case
                parsed_response = line[3:].strip()
                self.log.debug(f"Parsed M114 response: {parsed_response!r}")
                return True, parsed_response

        # If loop completes without finding the correct line
        self.log.warning(f"M114 command succeeded, but expected 'ok c:' response not found. Full response: {output!r}")
        return False, f"Error: M114 response format unexpected. Received: {output}"

    # --- File Operations ---

    def _build_file_op_command(self, base_cmd: str, remote_path: str, *args) -> str:
        """Helper to build file operation commands with escaped paths."""
        escaped_remote_path = self._escape(remote_path)
        command_parts = [base_cmd, escaped_remote_path]
        # Ensure args are strings before joining
        command_parts.extend(map(str, args))
        return " ".join(command_parts)

    def download_transport(self, remote_path: str, local_path: str, overwrite: bool, 
                         status_callback: Callable, timeout: float, expected_size: Optional[int] = None) -> 'DownloadTransport':
        """
        Factory method to create a DownloadTransport instance for handling file downloads.

        Args:
            remote_path: The absolute path of the file on the device.
            local_path: The desired local path to save the file.
            overwrite: Whether to overwrite the local file if it exists.
            status_callback: A callable for progress updates (e.g., XMODEM callback).
            timeout: Timeout for the XMODEM transfer in seconds.
            expected_size: Optional expected size of the file to download (for progress indication).

        Returns:
            An initialized DownloadTransport object.

        Raises:
            ConnectionError: If the DeviceManager has no active stream.
        """
        # (Import DownloadTransport locally to avoid circular imports at runtime)
        if not self.stream:
            raise ConnectionError("DeviceManager has no active stream.")
        
        # Pre-escape the remote path for the transport to use in commands
        escaped_remote_path = self._escape(remote_path)
        
        from ..transport.download import DownloadTransport # Relative import
        return DownloadTransport(
            stream=self.stream, 
            remote_path=escaped_remote_path,  # Escaped path for commands
            remote_path_display=remote_path,  # Original path for display
            local_path=local_path, 
            overwrite=overwrite,
            status_callback=status_callback, 
            timeout=timeout, 
            expected_size=expected_size
        )

    def upload_transport(self, local_path: str, remote_path: str, overwrite: bool, progress_display_func: Callable, timeout: float, compress: bool = True) -> 'UploadTransport':
        """
        Factory method to create an UploadTransport instance for handling file uploads.

        Args:
            local_path: The path of the local file to upload.
            remote_path: The absolute path on the device where the file should be saved (already escaped if needed).
            overwrite: Whether to overwrite the remote file if it exists.
            progress_display_func: A callable for displaying progress updates.
            timeout: Timeout for the XMODEM transfer in seconds.
            compress: If True (default), compress the file before uploading.

        Returns:
            An initialized UploadTransport object.
        """
        if not self.stream:
            raise ConnectionError("DeviceManager has no active stream.")
        
        # Pre-escape the remote path for the transport to use in commands
        escaped_remote_path = self._escape(remote_path)
        
        from ..transport.upload import UploadTransport # Relative import
        return UploadTransport(
            stream=self.stream, 
            local_path=local_path,
            remote_path=escaped_remote_path,  # Escaped path for commands
            remote_path_display=remote_path,  # Original path for display
            overwrite=overwrite, 
            progress_display_func=progress_display_func, 
            timeout=timeout,
            compress=compress # Pass compress flag
        )

