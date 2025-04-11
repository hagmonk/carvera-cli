import sys
import os # Needed for path operations
import logging # Needed for logging
import argparse # Needed for type hinting args
import json
import hashlib  # For MD5 verification
from datetime import datetime  # For timestamp parsing
import time # Added for sleep

# Added imports for firmware upload
from .utils import validate_firmware_file, prepare_file_for_upload, cleanup_temp_files, calculate_md5

"""
Transport module for Carvera Controller CLI.

This module provides handlers for file-related operations like:
- download: Download files from the device
- stat: Get detailed information about files on the device
- upload: Upload files to the device
"""

from carvera_cli.device.manager import DeviceManager # Needed for type hinting

def progress_callback(packet_size: int, total: int, success: int, errors: int, total_bytes: int = None, transferred_bytes: int = None) -> None:
    """
    Progress callback for file uploads/downloads

    Args:
        packet_size: Size of each packet in bytes
        total: Total number of packets to send
        success: Number of successfully sent packets
        errors: Number of errors (mostly for internal retry count)
        total_bytes: Optional total file size in bytes
        transferred_bytes: Optional current transferred bytes
    """
    try:
        # Check if we're in quiet mode
        if logging.getLogger().getEffectiveLevel() >= logging.WARNING:
            return  # Skip progress output in quiet mode
            
        # Use byte-based progress if available
        if total_bytes is not None and transferred_bytes is not None:
            # Cap percentage at 100% to avoid confusion
            percent = min(100.0, (transferred_bytes / total_bytes) * 100)
            
            # Cap displayed transferred bytes to not exceed total bytes
            displayed_transferred = min(transferred_bytes, total_bytes)
            
            # Format size in human-readable format (KB, MB)
            if total_bytes >= 1024 * 1024:
                size_str = f"{displayed_transferred / (1024 * 1024):.1f}/{total_bytes / (1024 * 1024):.1f} MB"
            else:
                size_str = f"{displayed_transferred / 1024:.1f}/{total_bytes / 1024:.1f} KB"
            progress_str = f"\rProgress: {percent:.1f}% ({size_str})"
        elif total > 0:
            # Fall back to packet-based progress
            percent = min(100.0, (success / total) * 100)
            # Don't show 'errors' count as it reflects recoverable retries
            progress_str = f"\rProgress: {percent:.1f}% ({success}/{total} packets)"
        else:
            progress_str = f"\rProgress: {success} packets"
            
        sys.stdout.write(progress_str)
        sys.stdout.flush()
    except Exception as e:
        # Silently handle any errors in the callback to prevent transport issues
        pass

def handle_stat(manager: DeviceManager, args: argparse.Namespace) -> int:
    """
    Handles the stat action logic to retrieve and display file information.

    Args:
        manager: The initialized DeviceManager instance.
        args: The parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    log = logging.getLogger("cmd.transport")
    log.info(f"Getting file info for {args.remote_file}")
    
    try:
        # Call the stat method on the device manager
        success, result = manager.stat(
            remote_path=args.remote_file,
            timeout=args.timeout
        )
        
        if not success:
            # Handle error case
            error_msg = result.get("error", "Unknown error")
            log.error(f"Failed to get file information: {error_msg}")
            return 1
            
        # Format the file information for display
        if args.json:
            # Output as JSON if requested
            print(json.dumps(result, indent=2))
        else:
            # Pretty print formatted output
            print(f"File: {result['filename']}")
            print(f"Size: {result['size']} bytes")
            print(f"Timestamp: {result['timestamp']}")
            
            # Show compressed size if available
            if 'compressed_size' in result:
                print(f"Compressed size: {result['compressed_size']} bytes")
                compression_ratio = result['size'] / result['compressed_size']
                print(f"Compression ratio: {compression_ratio:.2f}x")
            
            # Show MD5 checksums
            if 'md5' in result:
                print(f"MD5 checksum: {result['md5']}")
            if 'filesystem_md5' in result:
                print(f"Filesystem MD5: {result['filesystem_md5']}")
                
                # Check if checksums match
                if 'md5' in result and result['md5'] != result['filesystem_md5']:
                    print("WARNING: MD5 checksums do not match!")
        
        return 0
    except Exception as e:
        log.error(f"An error occurred during the stat operation: {e}", exc_info=args.verbose)
        return 1

def handle_download(manager: DeviceManager, args: argparse.Namespace) -> int:
    """
    Handles the download action logic.

    Args:
        manager: The initialized DeviceManager instance.
        args: The parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    log = logging.getLogger("cmd.transport")
    
    # Handle relative paths - if the path doesn't start with '/',
    # treat it as relative to /sd/gcodes/
    remote_file = args.remote_file
    if not remote_file.startswith('/'):
        remote_file = f"/sd/gcodes/{remote_file}"
        log.info(f"Using absolute path: {remote_file}")
    
    # Get information about the remote file using stat
    log.info(f"Getting file information for {remote_file}")
    stat_success, file_info = manager.stat(remote_file, timeout=args.timeout)
    
    if not stat_success:
        error_msg = file_info.get("error", "Unknown error")
        log.error(f"Failed to get file information: {error_msg}")
        return 1
    
    # Get relative path for logging
    rel_file = os.path.basename(remote_file)
    log.info(f"Downloading {rel_file}")
    
    # Determine file size for progress reporting (use compressed size if available)
    file_size = file_info.get("compressed_size", file_info.get("size", 0))
    log.debug(f"File size for progress reporting: {file_size} bytes")
    
    # Get MD5 for validation - prioritize the remote file's actual MD5
    expected_md5 = file_info.get("md5", file_info.get("filesystem_md5", None))
    if expected_md5:
        log.info(f"Remote file MD5: {expected_md5}")
    
    local_target_path = args.local_path
    if not local_target_path:
        # Default to current directory if local_path is not provided
        local_target_path = os.path.join(os.getcwd(), os.path.basename(remote_file))
    
    try:
        # Create a customized callback that includes file size information
        def enhanced_callback(packet_size, total, success, errors):
            # Calculate bytes transferred based on packet size and success count
            transferred_bytes = packet_size * success
            # Call the standard callback with additional file size information
            progress_callback(packet_size, total, success, errors, file_size, transferred_bytes)
        
        # Create the download transport using the factory method
        download_transport = manager.download_transport(
            remote_path=remote_file,
            local_path=local_target_path,
            overwrite=args.overwrite,
            status_callback=enhanced_callback,  # Use our enhanced callback
            timeout=args.timeout,  # Use the global timeout
            expected_size=file_size  # Pass the expected size from stat
        )
        
        # Execute the download
        result = download_transport.execute()
        
        if not result:
            # Specific error logged within DownloadTransport
            log.error("File download failed.")
            return 1
            
        # Verify the MD5 checksum if we know it
        if expected_md5 and os.path.exists(local_target_path):
            log.info("Verifying downloaded file integrity...")
            # Calculate MD5 of downloaded file
            with open(local_target_path, 'rb') as f:
                file_hash = hashlib.md5()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
                local_md5 = file_hash.hexdigest()
            
            if local_md5 == expected_md5:
                log.info("MD5 checksum verification successful.")
                # Don't print the MD5 again - it's already reported at the start of the download
            else:
                log.error(f"MD5 verification failed. Expected: {expected_md5}, Got: {local_md5}")
                log.warning(f"MD5 checksum mismatch! Expected: {expected_md5}, Got: {local_md5}")
        
        log.debug("File download completed successfully.")
        log.info(f"Downloaded {rel_file} to {local_target_path}")
        return 0
    except Exception as e:
        log.error(f"An error occurred during the download operation: {e}", exc_info=args.verbose)
        return 1

def handle_upload(manager: DeviceManager, args: argparse.Namespace) -> int:
    """
    Handles the upload action logic.

    Args:
        manager: The initialized DeviceManager instance.
        args: The parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    log = logging.getLogger("cmd.transport")
    
    # Pre-check the local file
    if not os.path.exists(args.local_file):
        log.error(f"Local file '{args.local_file}' does not exist.")
        return 1
    
    # Get file information
    file_size = os.path.getsize(args.local_file)
    rel_file = os.path.basename(args.local_file)
    log.info(f"Uploading {rel_file} ({file_size} bytes)")
    
    # Determine remote path
    remote_path = args.remote_path
    if not remote_path:
        # If no remote path is specified, use the same filename in the default directory
        remote_path = f"/sd/gcodes/{rel_file}"
    elif remote_path.endswith('/'):
        # If remote path is a directory, append the filename (after removing trailing slashes)
        remote_path = f"{remote_path.rstrip('/')}/{rel_file}"
    
    log.info(f"Target remote path: {remote_path}")
    
    # Check if remote file already exists
    stat_success, file_info = manager.stat(remote_path, timeout=args.timeout)
    if stat_success:
        # File exists
        if not args.overwrite:
            log.error(f"Remote file '{remote_path}' already exists. Use --overwrite to replace it.")
            return 1
        log.info(f"Remote file exists and will be overwritten.")
    
    try:
        # Use the standard progress_callback directly
        upload_transport = manager.upload_transport(
            local_path=args.local_file,
            remote_path=remote_path,
            overwrite=args.overwrite,
            progress_display_func=progress_callback, # Pass the standard callback
            timeout=args.timeout
        )
        
        # Execute the upload
        result = upload_transport.execute()
        
        if not result:
            # Specific error logged within UploadTransport
            log.error("File upload failed.")
            return 1
            
        log.info(f"Uploaded {rel_file} to {remote_path} successfully.")
        return 0
    except Exception as e:
        log.error(f"An error occurred during the upload operation: {e}", exc_info=args.verbose)
        return 1

def handle_md5(manager: DeviceManager, args: argparse.Namespace) -> int:
    """
    Handles the md5 action logic to retrieve and display the MD5 checksum of a file.

    Args:
        manager: The initialized DeviceManager instance.
        args: The parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    log = logging.getLogger("cmd.files")
    log.info(f"Calculating MD5 checksum for {args.remote_file}")
    
    success, result = manager.md5(
        remote_path=args.remote_file,
        timeout=args.timeout
    )
    
    if not success:
        log.error(f"Failed to calculate MD5 checksum: {result}")
        return 1
        
    # Display the MD5 checksum
    print(f"{result}  {args.remote_file}")
    return 0

def format_size(size_in_bytes):
    """Format size in human-readable format (B, KB, MB, GB)."""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.1f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

def format_timestamp(timestamp_str):
    """
    Format a timestamp string into a human-readable date and time.
    
    The Carvera device returns timestamps as strings in the format:
    'YYYYMMDDhhmmss' (e.g., '20250412011819').
    """
    try:
        # Try to parse the timestamp in Carvera's format: YYYYMMDDhhmmss
        if len(timestamp_str) == 14 and timestamp_str.isdigit():
            dt = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Fallback to ISO format parsing if it looks like ISO
        if 'T' in timestamp_str:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        pass
        
    # If we can't parse it, return the original string
    return timestamp_str

def handle_ls(manager: DeviceManager, args: argparse.Namespace) -> int:
    """
    Handles the ls action logic to list files in a directory on the device.

    Args:
        manager: The initialized DeviceManager instance.
        args: The parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    log = logging.getLogger("cmd.files")
    
    # remote_path can be None, which will be handled by manager.ls with a default of /sd/gcodes
    path_display = args.remote_path or '/sd/gcodes'
    log.info(f"Listing files in {path_display}")
    
    success, result = manager.ls(
        remote_path=args.remote_path,  # This can be None, DeviceManager.ls will handle it
        timeout=args.timeout
    )
    
    if not success:
        log.error(f"Failed to list files: {result.get('error', 'Unknown error')}")
        return 1
        
    # Display the file listing
    if args.json:
        # Output as JSON if requested
        print(json.dumps(result, indent=2))
    else:
        # Sort files by name for consistent output
        sorted_files = sorted(result.keys())
        
        # Get the longest filename for formatting
        max_filename_len = max([len(filename) for filename in sorted_files], default=0)
        
        # Print a header
        print(f"{'Filename':<{max_filename_len + 2}}{'Size':<12}Timestamp")
        print("-" * (max_filename_len + 2 + 12 + 19))
        
        # Calculate total size
        total_size = 0
        
        # Print each file
        for filename in sorted_files:
            file_info = result[filename]
            size_bytes = file_info['size']
            total_size += size_bytes
            
            # Format size and timestamp for human readability
            size_str = format_size(size_bytes)
            timestamp_str = format_timestamp(file_info['timestamp'])
            
            print(f"{filename:<{max_filename_len + 2}}{size_str:<12}{timestamp_str}")
        
        # Print summary with total files and total size in human-readable format
        print(f"\nTotal: {len(sorted_files)} files, {format_size(total_size)}")
    
    return 0

def handle_upload_firmware(manager: DeviceManager, args: argparse.Namespace) -> int:
    """
    Handles the firmware upload logic.

    Args:
        manager: The initialized DeviceManager instance.
        args: The parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    log = logging.getLogger("cmd.files")

    if not os.path.isfile(args.local_path):
        log.error(f"Local firmware file not found: {args.local_path}")
        return 1

    # Calculate local MD5 first
    log.info(f"Calculating MD5 for local file: {args.local_path}")
    local_md5 = calculate_md5(args.local_path)
    if not local_md5:
        log.error("Failed to calculate local MD5. Aborting upload.")
        return 1
    log.info(f"Local firmware MD5: {local_md5}")

    log.info(f"Validating firmware file: {args.local_path}")
    if not validate_firmware_file(args.local_path, log):
        log.error("Firmware validation failed. Aborting upload.")
        return 1
    log.info("Firmware validation successful.")

    remote_path = "/sd/firmware.bin"
    log.info(f"Target remote path: {remote_path}")

    transport = None
    success = False
    try:
        log.info(f"Starting firmware upload to {remote_path}...")
        transport = manager.upload_transport(
            local_path=args.local_path,
            remote_path=remote_path,
            overwrite=True,
            progress_display_func=progress_callback,
            timeout=args.timeout,
            compress=False # Explicitly disable compression for firmware
        )
        success = transport.execute()

        if success:
            log.info("XMODEM transfer successful. Verifying remote MD5...")
            # # Add delay before checking MD5
            # log.info("Waiting 2 seconds for firmware to finalize MD5...")
            # time.sleep()
            
            # Verify MD5 checksum on the device
            verify_success, remote_md5 = manager.md5(remote_path, timeout=args.timeout)
            
            if verify_success and remote_md5 == local_md5:
                log.info("Firmware MD5 verification successful.")
                # Keep success = True
                
                # Check if reset flag is set
                if args.reset:
                    log.info("Reset flag provided. Sending reset command...")
                    reset_success, reset_response = manager.reset(timeout=args.timeout)
                    if reset_success:
                        log.info("Reset command sent successfully.")
                        # Note: We might not get a response if the device resets immediately
                    else:
                        log.warning(f"Failed to send reset command: {reset_response}")
                        # Consider if this should fail the overall operation? For now, just warn.
                
            else:
                log.error(f"Firmware MD5 verification failed! Expected: {local_md5}, Got: {remote_md5 if verify_success else 'Error retrieving remote MD5'}")
                success = False # Mark as failure if verification fails
        else:
            log.error("Firmware upload failed.")

    except Exception as e:
        log.error(f"An error occurred during the firmware upload operation: {e}", exc_info=args.verbose)
        success = False
    finally:
        pass

    return 0 if success else 1
        