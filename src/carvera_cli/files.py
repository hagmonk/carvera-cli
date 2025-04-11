"""
File Handling Utilities

Utilities for file upload, compression, and management for Carvera devices.
"""

import os
import struct
import hashlib
import logging
import tempfile
from typing import Optional, Callable, Tuple

# Try to import quicklz for compression, handle gracefully if not available
try:
    import quicklz
    QUICKLZ_AVAILABLE = True
except ImportError:
    QUICKLZ_AVAILABLE = False

# Constants
DEFAULT_BLOCK_SIZE = 65536


def calculate_md5(file_path: str) -> str:
    """
    Calculate MD5 hash of a file
    
    Args:
        file_path: Path to the file
        
    Returns:
        MD5 hex digest string
    """
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        logging.error(f"Error calculating MD5: {str(e)}")
        return ""


def compress_file(input_path: str) -> Tuple[str, int, Optional[str]]:
    """
    Compress a file using QuickLZ
    
    Args:
        input_path: Path to the file to compress
        
    Returns:
        Tuple of (output_path, compressed_size, error_message)
        error_message is None if successful, otherwise contains the error
    """
    if not QUICKLZ_AVAILABLE:
        return input_path, 0, "QuickLZ not available. Install with: pip install pyquicklz"
    
    try:
        # Create a temporary directory for the compressed file
        temp_dir = tempfile.mkdtemp(prefix="carvera_")
        output_path = os.path.join(temp_dir, os.path.basename(input_path) + '.lz')
        
        # Read the input file
        with open(input_path, "rb") as f:
            file_data = f.read()
        
        original_size = len(file_data)
        
        # Set up compression parameters
        block_size = DEFAULT_BLOCK_SIZE
        checksum = 0
        compressed_blocks = 0
        
        # Open the output file
        with open(output_path, 'wb') as f_out:
            # Process the input file in blocks
            pos = 0
            while pos < len(file_data):
                # Read a block
                block = file_data[pos:pos+block_size]
                pos += len(block)
                
                # Calculate checksum
                for byte in block:
                    checksum += byte
                
                # Compress the block
                compressed_block = quicklz.compress(block)
                
                # Calculate compressed size and create header
                cmprs_size = len(compressed_block)
                buffer_hdr = struct.pack('>I', cmprs_size)  # Big-endian uint32
                
                # Write header and compressed block
                f_out.write(buffer_hdr)
                f_out.write(compressed_block)
                compressed_blocks += 1
            
            # Write the checksum at the end (16-bit)
            sum_data = struct.pack('>H', checksum & 0xffff)
            f_out.write(sum_data)
        
        # Get final compressed size
        compressed_size = os.path.getsize(output_path)
        compression_ratio = compressed_size / original_size * 100
        
        logging.info(f"Compression complete: {compressed_size} bytes ({compression_ratio:.1f}% of original size)")
        return output_path, compressed_size, None
        
    except Exception as e:
        logging.error(f"Compression error: {str(e)}")
        return input_path, 0, str(e)


def prepare_file_for_upload(file_path: str, compress: bool = False) -> Tuple[str, int, bool, Optional[str]]:
    """
    Prepare a file for upload, optionally with compression
    
    Args:
        file_path: Path to the file to upload
        compress: Whether to use compression
        
    Returns:
        Tuple of (temp_file_path, size, compressed, error_message)
    """
    if not os.path.isfile(file_path):
        return "", 0, False, f"File not found: {file_path}"
    
    # Get original file size
    original_size = os.path.getsize(file_path)
    
    if compress and QUICKLZ_AVAILABLE:
        try:
            # Compress the file
            temp_file_path, compressed_size, error = compress_file(file_path)
            if error:
                # Fall back to no compression if there's an error
                logging.warning(f"Compression failed: {error}. Uploading uncompressed file.")
                compress = False
            else:
                return temp_file_path, compressed_size, True, None
        except Exception as e:
            logging.error(f"Error during compression: {str(e)}")
            compress = False
    elif compress and not QUICKLZ_AVAILABLE:
        logging.warning("QuickLZ not available. Install with: pip install pyquicklz")
        compress = False
    
    if not compress:
        # Create a temporary copy of the original file
        try:
            temp_dir = tempfile.mkdtemp(prefix="carvera_")
            temp_file_path = os.path.join(temp_dir, os.path.basename(file_path))
            
            with open(file_path, 'rb') as src, open(temp_file_path, 'wb') as dst:
                dst.write(src.read())
                
            return temp_file_path, original_size, False, None
        except Exception as e:
            logging.error(f"Error creating temporary file: {str(e)}")
            return "", 0, False, str(e)
    
    # This should never be reached, but just in case
    return "", 0, False, "Unexpected error in prepare_file_for_upload"


def cleanup_temp_files(file_path: str) -> None:
    """
    Clean up temporary files
    
    Args:
        file_path: Path to the temporary file
    """
    try:
        if file_path and os.path.exists(file_path):
            temp_dir = os.path.dirname(file_path)
            # Remove the file
            os.remove(file_path)
            # Try to remove the directory too
            try:
                os.rmdir(temp_dir)
            except:
                pass
    except Exception as e:
        logging.error(f"Error cleaning up temporary files: {str(e)}") 