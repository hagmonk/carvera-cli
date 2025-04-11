import os
import struct
import time
import logging
import quicklz
import hashlib
from typing import Callable, Optional
import sys

from ..streams.streams import Stream
from ..transport.xmodem import XMODEM
from .utils import transfer_timer

# Constants matching main.py::compress_file and decompress_file logic
BLOCK_SIZE = 4096
BLOCK_HEADER_SIZE = 4 # 4 bytes for big-endian uint32 block size
CHECKSUM_SIZE = 2     # 2 bytes for big-endian uint16 checksum

class DownloadTransport:
    """
    Handles the download of a file from the Carvera device, including XMODEM transfer
    and potential QuickLZ decompression.
    """
    def __init__(self, stream: Stream, remote_path: str, local_path: str, overwrite: bool, 
                 status_callback: Optional[Callable] = None, timeout: float = 60.0, 
                 expected_size: Optional[int] = None, remote_path_display: Optional[str] = None):
        """
        Initializes the DownloadTransport.

        Args:
            stream: An active Stream object for communication.
            remote_path: The absolute path of the file on the device (already escaped if needed).
            local_path: The local path where the file should be saved.
            overwrite: If True, overwrite the local file if it exists.
            status_callback: Optional callback for XMODEM progress updates.
            timeout: Timeout for the XMODEM transfer in seconds.
            expected_size: Optional expected size of the file to download (for progress indication).
            remote_path_display: User-friendly version of remote_path with spaces for logging (optional).
        """
        self.log = logging.getLogger("DownloadTransport")
        self.stream = stream
        self.remote_path = remote_path  # Escaped path for commands
        self.remote_path_display = remote_path_display or remote_path  # User-friendly path for logs
        self.local_path = local_path
        self.overwrite = overwrite
        self.status_callback = status_callback
        self.timeout = timeout
        self.verbose = logging.getLogger().isEnabledFor(logging.DEBUG) # Check root logger level
        # Store remote file md5 when available
        self.remote_md5 = None
        # Store expected file size for progress
        self.expected_size = expected_size

    def execute(self) -> bool:
        """
        Executes the download process: triggers download, receives via XMODEM,
        attempts decompression, and handles cleanup.

        Returns:
            True if the download and processing were successful, False otherwise.
        """
        temp_local_path = self.local_path + ".tmp"
        local_dir = os.path.dirname(self.local_path)

        # --- Pre-checks ---
        if os.path.exists(self.local_path) and not self.overwrite:
            self.log.error(f"Local file '{self.local_path}' already exists. Use --overwrite.")
            return False
        elif os.path.exists(self.local_path) and self.overwrite:
            # Use absolute path for logging
            self.log.info(f"Overwriting {self.local_path}")

        if local_dir and not os.path.isdir(local_dir):
            try:
                self.log.info(f"Creating local directory: {local_dir}")
                os.makedirs(local_dir)
            except Exception as e:
                self.log.error(f"Error creating directory {local_dir}: {e}", exc_info=self.verbose)
                return False

        # --- Trigger Download ---
        download_command = f"download {self.remote_path}\n".encode('utf-8')
        # Use debug level for the command details (use display path for better readability)
        self.log.debug(f"Initiating download trigger: download {self.remote_path_display}")
        try:
            self.stream.send(download_command)
            time.sleep(0.2) # Allow firmware to react
        except Exception as e:
            self.log.error(f"Failed to send download trigger command: {e}", exc_info=self.verbose)
            return False

        # --- Create callback wrapper ---
        wrapped_callback = None
        if self.status_callback:
            # We need to track packets as they come in to ensure progress goes to 100%
            # Keep a reference to the last seen count in a list so it can be modified in the closure
            progress_state = [0]  # [last_packet_count]
            
            def wrapped_callback(packet_size, success_count, error_count):
                # Update the highest packet count we've seen
                if success_count > progress_state[0]:
                    progress_state[0] = success_count
                
                # When we receive the final packet, we'll report 100% by making
                # total = current count
                if progress_state[0] > 0:
                    # Pass the current count as both success and total to show 100%
                    self.status_callback(packet_size, progress_state[0], progress_state[0], error_count)
                else:
                    # Fallback if somehow progress_state[0] is still 0
                    self.status_callback(packet_size, 1, 1, error_count)
        
        # --- XMODEM Receive ---
        xmodem_transfer = XMODEM(self.stream.getc, self.stream.putc, mode='xmodem')
        received_size = None
        download_result = False

        try:
            # Use display path for user-facing logs
            self.log.info(f"Downloading {self.remote_path_display}")
            self.log.debug(f"Waiting for XMODEM handshake to receive {self.remote_path_display}...")
            
            # Use transfer_timer to handle newline and timing/rate logging
            with transfer_timer(self.log, "XMODEM transfer", expected_size=self.expected_size, cleanup_progress=True):
                with open(temp_local_path, 'wb') as file_stream:
                    received_size = xmodem_transfer.recv(
                        stream=file_stream,
                        retry=10,
                        timeout=int(self.timeout),
                        quiet=not self.verbose, # Use verbose flag from logger
                        callback=wrapped_callback  # Use the wrapped callback
                    )
                    download_result = received_size is not None and received_size >= 0
                    # Explicitly check for -1 which indicates manual cancel in some implementations
                    if received_size == -1:
                        download_result = False
                        self.log.warning("XMODEM receive cancelled.")

        except Exception as e:
            self.log.error(f"Exception during XMODEM receive: {e}", exc_info=self.verbose)
            download_result = False
            try:
                self.stream.send(XMODEM.CAN * 3) # Attempt CAN on error
            except Exception:
                self.log.debug("Ignoring error sending CAN after XMODEM receive exception.")

        # --- Process Result ---
        if download_result:
            # Log the received size at debug level only
            self.log.debug(f"XMODEM received {received_size} bytes successfully to {temp_local_path}.")
            # Log the compressed size for the user
            self.log.info(f"Downloaded {received_size} bytes (compressed file)")
            
            # Calculate MD5 of the downloaded file
            try:
                md5_raw = self._calculate_md5(temp_local_path)
                if md5_raw:
                    md5_hex = md5_raw.hexdigest()
                    self.log.info(f"Downloaded file MD5 (compressed file): {md5_hex}")
            except Exception as e:
                self.log.debug(f"Could not calculate MD5 of downloaded file: {e}")
                
            # --- Attempt Decompression ---
            decompressed_correctly = self._attempt_decompression(temp_local_path)

            if decompressed_correctly:
                try:
                    # If overwrite is enabled or the target doesn't exist, replace it.
                    if self.overwrite or not os.path.exists(self.local_path):
                         if os.path.exists(self.local_path):
                              os.remove(self.local_path) # Remove existing target first for os.rename
                         os.rename(temp_local_path, self.local_path)
                         self.log.debug(f"File saved successfully to: {self.local_path}")
                         return True
                    else:
                         # This case should have been caught by pre-checks, but handle defensively
                         self.log.error(f"Target file {self.local_path} exists and overwrite is false. Cannot move temp file.")
                         # Clean up temp file as we cannot complete the operation
                         os.remove(temp_local_path)
                         return False

                except OSError as e_mov:
                    self.log.error(f"Error moving temporary file {temp_local_path} to {self.local_path}: {e_mov}")
                    # Clean up temp file if move fails
                    if os.path.exists(temp_local_path):
                        try: os.remove(temp_local_path)
                        except OSError: pass
                    return False
            else:
                # Decompression failed (e.g., checksum error)
                self.log.error(f"Processing failed for {temp_local_path} (decompression/checksum error).")
                # Cleanup temp file
                if os.path.exists(temp_local_path):
                    try: os.remove(temp_local_path)
                    except OSError: pass
                return False
        else:
            # XMODEM failed or was cancelled
            self.log.error("XMODEM receive failed or was cancelled.")
            # Cleanup temp file
            if os.path.exists(temp_local_path):
                self.log.debug(f"Cleaning up temporary download file due to failure: {temp_local_path}")
                try:
                    os.remove(temp_local_path)
                except OSError as e_rem:
                    self.log.warning(f"Could not remove temporary file {temp_local_path}: {e_rem}")
            return False

    def _calculate_md5(self, file_path: str):
        """
        Calculate MD5 hash for a file.
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            MD5 hash object or None if file couldn't be read
        """
        md5 = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
            return md5
        except Exception as e:
            self.log.debug(f"Error calculating MD5 for {file_path}: {e}")
            return None

    def _attempt_decompression(self, file_path: str) -> bool:
        """
        Checks if a file appears to be QuickLZ compressed (based on header/size)
        and attempts to decompress it in place, verifying the checksum.

        Args:
            file_path: The path to the downloaded file (likely a .tmp file).

        Returns:
            True if the file was successfully decompressed (or wasn't compressed),
            False if decompression failed (e.g., checksum mismatch).
        """
        is_compressed = False
        try:
            total_size = os.path.getsize(file_path)
            if total_size < BLOCK_HEADER_SIZE + CHECKSUM_SIZE:
                self.log.debug(f"File {file_path} too small to be compressed ({total_size} bytes). Assuming not compressed.")
                return True # Not compressed, treat as success

            with open(file_path, 'rb') as f_in:
                header_bytes = f_in.read(BLOCK_HEADER_SIZE)
                if len(header_bytes) < BLOCK_HEADER_SIZE:
                     self.log.warning(f"Could not read header from {file_path}. Assuming not compressed.")
                     return True # Error reading header, assume not compressed

                first_block_size = struct.unpack('>I', header_bytes)[0]
                # Heuristic check: Is the first block size plausible?
                if 0 < first_block_size <= BLOCK_SIZE: # Allow slightly larger if compression is inefficient? No, stick to BLOCK_SIZE.
                    is_compressed = True
                    self.log.debug(f"File {file_path} appears to be QuickLZ compressed (first block size: {first_block_size}).")
                    self.log.info("Decompressing file")
                else:
                    self.log.debug(f"File {file_path} does not appear compressed (invalid first block size: {first_block_size}). Skipping decompression.")
                    return True # Doesn't look compressed

        except OSError as e:
            self.log.error(f"Error checking file header for {file_path}: {e}. Assuming not compressed.", exc_info=self.verbose)
            return True # Treat error during check as "not compressed"

        if not is_compressed:
            return True

        # --- Perform Decompression ---
        decompressed_temp_path = file_path + ".decomp"
        calculated_checksum = 0
        processed_bytes = 0

        try:
            with open(file_path, 'rb') as f_in, open(decompressed_temp_path, 'wb') as f_out:
                while True:
                    current_pos = f_in.tell()
                    # Check if we have enough space left for at least a header and checksum
                    if current_pos + BLOCK_HEADER_SIZE + CHECKSUM_SIZE > total_size:
                        # We should have exited on the checksum check below if everything was ok
                        self.log.error(f"Decompression error: Unexpected end of file or truncated data near byte {current_pos} in {file_path}.")
                        raise ValueError("Truncated compressed file or invalid structure")

                    header_bytes = f_in.read(BLOCK_HEADER_SIZE)
                    if not header_bytes:
                        self.log.error("Decompression error: Unexpected EOF reading block header.")
                        raise ValueError("Unexpected EOF reading block header")
                    
                    compressed_size = struct.unpack('>I', header_bytes)[0]
                    processed_bytes += BLOCK_HEADER_SIZE

                    # Check if we have enough bytes for the claimed block size AND the final checksum
                    if current_pos + BLOCK_HEADER_SIZE + compressed_size + CHECKSUM_SIZE > total_size:
                         self.log.error(f"Decompression error: Declared block size ({compressed_size}) exceeds available file data near byte {current_pos}.")
                         raise ValueError("Declared block size exceeds available file data")

                    compressed_block = f_in.read(compressed_size)
                    if len(compressed_block) < compressed_size:
                        self.log.error("Decompression error: Unexpected EOF reading compressed block.")
                        raise ValueError("Unexpected EOF reading compressed block")
                    processed_bytes += compressed_size

                    # Check if this block is the last one (before the checksum)
                    is_last_block = (processed_bytes + CHECKSUM_SIZE == total_size)

                    try:
                        decompressed_block = quicklz.decompress(compressed_block)
                    except Exception as qlz_error:
                        self.log.error(f"QuickLZ decompression failed: {qlz_error}", exc_info=self.verbose)
                        raise # Re-raise to be caught by the outer try/except

                    f_out.write(decompressed_block)

                    # Update checksum based on *decompressed* data
                    # Correct checksum calculation (sum bytes modulo 65536)
                    block_sum = sum(decompressed_block)
                    calculated_checksum = (calculated_checksum + block_sum) % 65536

                    if is_last_block:
                        break # Exit loop after processing the last block

            # --- Verify Checksum ---
            with open(file_path, 'rb') as f_in:
                f_in.seek(-CHECKSUM_SIZE, os.SEEK_END) # Go to the checksum position
                checksum_bytes = f_in.read(CHECKSUM_SIZE)
                if len(checksum_bytes) < CHECKSUM_SIZE:
                     self.log.error("Decompression error: Could not read checksum from end of file.")
                     raise ValueError("Could not read checksum")
                stored_checksum = struct.unpack('>H', checksum_bytes)[0]

            if calculated_checksum == stored_checksum:
                # Get the decompressed file size
                decompressed_size = os.path.getsize(decompressed_temp_path)
                # Log both the checksum and the decompressed file size
                self.log.info(f"QuickLZ checksum validated: 0x{calculated_checksum:04x} ({calculated_checksum})")
                self.log.info(f"Decompressed file size: {decompressed_size} bytes")
                
                # Calculate MD5 of the decompressed file
                try:
                    md5_raw = self._calculate_md5(decompressed_temp_path)
                    if md5_raw:
                        md5_hex = md5_raw.hexdigest()
                        self.log.info(f"Decompressed file MD5: {md5_hex}")
                except Exception as e:
                    self.log.debug(f"Could not calculate MD5 of decompressed file: {e}")
                
                self.remote_md5 = calculated_checksum  # Store checksum for reference
                # Replace the original temp file with the decompressed one
                os.replace(decompressed_temp_path, file_path)
                self.log.debug(f"Successfully decompressed and replaced {file_path}")
                return True
            else:
                self.log.error(f"Decompression FAILED: Checksum mismatch! Calculated=0x{calculated_checksum:04x}, Stored=0x{stored_checksum:04x}")
                # Cleanup the failed decompressed file
                if os.path.exists(decompressed_temp_path):
                    try: os.remove(decompressed_temp_path)
                    except OSError: pass
                return False

        except (OSError, ValueError, Exception) as e:
            self.log.error(f"Error during decompression process for {file_path}: {e}", exc_info=self.verbose)
            # Cleanup any partial decompressed file
            if os.path.exists(decompressed_temp_path):
                try: os.remove(decompressed_temp_path)
                except OSError: pass
            return False
