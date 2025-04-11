import os
import time
import struct
import logging
import hashlib
import tempfile
from typing import Callable, Optional
import sys

from ..streams.streams import Stream
from ..transport.xmodem import XMODEM
from ..cmd.utils import compress_file, cleanup_temp_files, calculate_md5
from .utils import transfer_timer

# Constants matching main.py::compress_file and decompress_file logic
BLOCK_SIZE = 4096
BLOCK_HEADER_SIZE = 4  # 4 bytes for big-endian uint32 block size
CHECKSUM_SIZE = 2      # 2 bytes for big-endian uint16 checksum
MD5_VERIFICATION_TIMEOUT = 30.0  # Seconds to wait for MD5 verification
MD5_POLL_INITIAL_DELAY = 1.0     # Initial seconds between polls
MD5_POLL_MAX_DELAY = 5.0         # Maximum seconds between polls

class UploadTransport:
    """
    Handles the upload of a file to the Carvera device, including XMODEM transfer,
    optional QuickLZ compression, and MD5 verification.
    """
    def __init__(self, stream: Stream, local_path: str, remote_path: str, overwrite: bool, 
                 progress_display_func: Optional[Callable] = None, timeout: float = 60.0,
                 remote_path_display: Optional[str] = None, compress: bool = True):
        """
        Initializes the UploadTransport.

        Args:
            stream: An active Stream object for communication.
            local_path: The path of the local file to upload.
            remote_path: The absolute path on the device where the file should be saved (already escaped if needed).
            overwrite: If True, overwrite the remote file if it exists.
            progress_display_func: Optional standard callback for displaying progress.
            timeout: Timeout for the XMODEM transfer in seconds.
            remote_path_display: User-friendly version of remote_path with spaces for logging (optional).
            compress: If True (default), compress the file before uploading.
        """
        self.log = logging.getLogger("UploadTransport")
        self.stream = stream
        self.local_path = local_path
        self.remote_path = remote_path  # Escaped path for commands
        self.remote_path_display = remote_path_display or remote_path  # User-friendly path for logs
        self.overwrite = overwrite
        self.progress_display_func = progress_display_func
        self.timeout = timeout
        self.compress = compress # Store compress flag
        self.verbose = logging.getLogger().isEnabledFor(logging.DEBUG)
        
        self.original_size = 0
        self.original_md5 = ""
        self.temp_file_path = None
        self.compressed_size = 0

    def execute(self) -> bool:
        """
        Executes the upload process: compresses the file, triggers upload, sends via XMODEM,
        and verifies the MD5 hash was created correctly.

        Returns:
            True if the upload and verification were successful, False otherwise.
        """
        # --- Pre-checks ---
        if not os.path.exists(self.local_path):
            self.log.error(f"Local file '{self.local_path}' does not exist.")
            return False
            
        # --- Calculate original file MD5 and size ---
        self.original_size = os.path.getsize(self.local_path)
        self.original_md5 = calculate_md5(self.local_path)
        if not self.original_md5:
            self.log.error(f"Failed to calculate MD5 for {self.local_path}")
            return False
        self.log.info(f"Original file MD5: {self.original_md5}")
        self.log.info(f"Original file size: {self.original_size} bytes")
        
        # --- Handle Compression (or lack thereof) ---
        path_to_upload = self.local_path # Default to original path
        size_for_progress = self.original_size # Default to original size
        upload_target_path = self.remote_path # Default target path (no .lz)
        self.temp_file_path = None # Ensure temp file is None if not compressing
        
        if self.compress:
            self.log.info(f"Compressing file for upload: {self.local_path}")
            try:
                # Use compress_file utility
                compressed_temp_path, compressed_size, error = compress_file(self.local_path)
                if error:
                    self.log.error(f"Compression failed: {error}")
                    return False # Return early if compression fails
                
                # Update variables for compressed upload
                self.temp_file_path = compressed_temp_path
                self.compressed_size = compressed_size
                path_to_upload = self.temp_file_path # Upload the compressed file
                size_for_progress = self.compressed_size # Progress based on compressed size
                upload_target_path = self.remote_path + ".lz" # Append .lz for firmware decompression trigger
                
                self.log.info(f"Compressed file size: {self.compressed_size} bytes " +
                             f"({self.compressed_size/self.original_size:.1%} of original)")
            except Exception as e:
                self.log.error(f"Error during compression: {e}", exc_info=self.verbose)
                # Ensure potential temp file is cleaned up on compression error
                if self.temp_file_path and os.path.exists(self.temp_file_path):
                     cleanup_temp_files(self.temp_file_path)
                return False
        else: # Not compressing
             self.log.info("Compression disabled for this upload.")
             # Variables already set to defaults (local_path, original_size, remote_path)
             
        # --- Trigger Upload --- 
        # Use the determined upload_target_path
        upload_command = f"upload {upload_target_path}\n".encode('utf-8')
        
        self.log.debug(f"Initiating upload trigger: upload {upload_target_path}")
        try:
            self.stream.send(upload_command)
            
            # --- Wait for XMODEM Handshake --- 
            self.log.debug("Waiting for firmware XMODEM handshake (NAK or CRC)...")
            crc_mode = -1 # -1: Undetermined, 0: Checksum, 1: CRC
            handshake_attempts = 0
            handshake_timeout = 10.0 # Seconds to wait for initial NAK/CRC
            start_handshake_time = time.time()

            while time.time() - start_handshake_time < handshake_timeout:
                char = self.stream.getc(1) # Read one byte
                if char == XMODEM.NAK:
                    self.log.info("Handshake received: NAK (Checksum mode)")
                    crc_mode = 0
                    break
                elif char == XMODEM.CRC:
                    self.log.info("Handshake received: CRC ('C' - CRC-16 mode)")
                    crc_mode = 1
                    break
                elif char:
                    # Discard other characters (like potential 'ok' from upload cmd)
                    self.log.debug(f"Discarding non-handshake byte: {char!r}")
                else:
                    # No data, wait briefly
                    time.sleep(0.1)
                    handshake_attempts += 1
            
            if crc_mode == -1:
                self.log.error(f"Timeout waiting for XMODEM start handshake (NAK or CRC) after {handshake_timeout}s.")
                self._cleanup()
                return False
            # --- End Handshake Wait ---

            # --- XMODEM Send ---
            xmodem_transfer = XMODEM(self.stream.getc, self.stream.putc, mode='xmodem8k')
            upload_result = False
            
            # --- Define Internal XMODEM Callback --- 
            xmodem_callback = None
            if self.progress_display_func:
                # Define the actual callback here, closing over the correct size
                def internal_xmodem_callback(packet_size, total_packets, success_count, error_count):
                    transferred_bytes = packet_size * success_count
                    # Call the display function with the appropriate size
                    self.progress_display_func(packet_size, total_packets, success_count, error_count, size_for_progress, transferred_bytes)
                xmodem_callback = internal_xmodem_callback
            # --- End Internal Callback Definition ---

            # Use transfer_timer with cleanup_progress=True to handle the newline after progress display
            with transfer_timer(self.log, "XMODEM transfer", size_for_progress, cleanup_progress=True):
                with open(path_to_upload, 'rb') as file_stream: # Use determined path
                    upload_result = xmodem_transfer.send(
                        stream=file_stream,
                        md5=self.original_md5, 
                        crc_mode=crc_mode, 
                        retry=10,
                        timeout=int(self.timeout),
                        quiet=not self.verbose,
                        callback=xmodem_callback # Pass the internal callback
                    )
            
            if upload_result:
                self.log.info("XMODEM transfer ACKed by firmware.")

                # --- Consume any lingering output --- 
                self.log.debug("Attempting to consume any lingering output from firmware...")
                cleanup_timeout = 1.5 # Max seconds to wait for stream to clear
                start_cleanup_time = time.monotonic()
                consumed_lines = 0
                while time.monotonic() - start_cleanup_time < cleanup_timeout:
                    # Use the stream's default readline timeout
                    line = self.stream.readline() 
                    if line:
                        consumed_lines += 1
                        self.log.debug(f"Consuming post-XMODEM line: {line.decode(errors='ignore').strip()!r}")
                        # Reset timer slightly on activity, but still enforce overall timeout
                        # start_cleanup_time = time.monotonic() - (cleanup_timeout * 0.1) # Optional: gives a bit more time if actively receiving
                        continue # Check immediately for more lines
                    else:
                        # readline timed out, stream appears quiet
                        self.log.debug(f"Stream appears quiet after consuming {consumed_lines} lines.")
                        break # Exit cleanup loop
                else:
                    # This block executes if the while loop finished due to timeout
                    self.log.warning(f"Timeout ({cleanup_timeout}s) reached while consuming post-XMODEM stream data. Consumed {consumed_lines} lines.")
                # --- End lingering output consumption ---
                
                # Use display path for user-facing log message
                self.log.info(f"Upload process successful for {self.remote_path_display}")
                
                self._cleanup()
                return True
                
            else: # upload_result was False
                self.log.error("XMODEM transfer failed")
                self._cleanup()
                return False
                
        except Exception as e:
            # Catch exceptions during handshake or send setup
            self.log.error(f"Exception during upload process: {e}", exc_info=self.verbose)
            try:
                # Attempt to cancel any pending operation on the device
                self.stream.send(XMODEM.CAN * 3) 
            except Exception:
                self.log.debug("Ignoring error sending CAN after upload exception.")
            self._cleanup()
            return False
            
    def _cleanup(self) -> None:
        """Cleans up temporary files created during the upload process."""
        if self.temp_file_path and os.path.exists(self.temp_file_path): # Only cleanup if temp path was set
            self.log.debug(f"Cleaning up temporary file: {self.temp_file_path}")
            cleanup_temp_files(self.temp_file_path)
