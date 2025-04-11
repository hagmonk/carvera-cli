import time
import contextlib
import logging
import sys
from typing import Optional, Callable

@contextlib.contextmanager
def transfer_timer(logger: logging.Logger, operation_name: str = "Transfer", 
                  data_size: Optional[int] = None, 
                  log_level: int = logging.INFO,
                  cleanup_progress: bool = False,
                  skip_logging: bool = False,
                  expected_size: Optional[int] = None):
    """
    Context manager for timing file transfer operations and calculating data rates.
    
    Args:
        logger: Logger instance to use for output
        operation_name: Name of the operation being timed (e.g., "Upload", "Download")
        data_size: Optional size in bytes of the data being transferred
        log_level: Logging level to use for the timing message
        cleanup_progress: If True, prints a newline before logging to clean up progress display
        skip_logging: If True, measures time but doesn't log anything (for manual logging)
        expected_size: Optional expected size for downloads (when final size is unknown beforehand)
        
    Example:
        with transfer_timer(logger, "Upload", file_size, cleanup_progress=True):
            # Code that performs the transfer with progress display
            xmodem.send(file_stream)
    """
    start_time = time.time()
    try:
        yield
    finally:
        elapsed_time = time.time() - start_time
        
        # If we need to clean up after a progress display, print a newline first
        if cleanup_progress:
            sys.stdout.write("\n")
            sys.stdout.flush()
        
        if not skip_logging:
            # Log the basic timing information
            message = f"{operation_name} completed in {elapsed_time:.2f} seconds"
            
            # Use expected_size if data_size isn't known (for downloads)
            effective_size = data_size if data_size is not None else expected_size
            
            # If data size is provided or we have an expected size, calculate and add transfer rate
            if effective_size and elapsed_time > 0:
                bytes_per_second = effective_size / elapsed_time
                
                # Format with appropriate units
                if bytes_per_second >= 1024 * 1024:
                    rate_str = f"{bytes_per_second / (1024 * 1024):.2f} MiB/s"
                else:
                    rate_str = f"{bytes_per_second / 1024:.2f} KiB/s"
                    
                message += f" ({rate_str})"
                
            logger.log(log_level, message) 