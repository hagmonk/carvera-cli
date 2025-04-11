import logging
import serial
import serial.tools.list_ports
from typing import Optional, List, Dict

from carvera_cli.streams.streams import Stream

# Constants
SERIAL_TIMEOUT = 0.3  # seconds

class USBStream(Stream):
    """USB Serial connection established on initialization."""
    
    def __init__(self, address: str):
        """
        Initialize and open serial connection. Raises serial.SerialException on failure.
        """
        self.serial: Optional[serial.Serial] = None # Type hint for clarity
        self.modem = None # Restore modem for XMODEM
        self.verbose = False
        self.log = logging.getLogger("USBStream")
        self._read_buffer = b''  # Buffer for readline implementation
        
        self.log.debug(f"Attempting to open {address}...")
        try:
            # --- Connection Attempt ---
            self.serial = serial.Serial(
                port=address,
                baudrate=115200,
                timeout=SERIAL_TIMEOUT
            )
            self.log.debug("Serial object created. Performing DTR sequence...")

            # --- DTR TOGGLE ---
            # NO LOGGING INSIDE THIS BLOCK
            try:
                self.serial.dtr = False
            except IOError: pass
            self.serial.reset_input_buffer()
            try:
                self.serial.dtr = True
            except IOError: pass
            # --- END DTR TOGGLE ---

            self.log.info(f"Serial port opened successfully: {address}")

        except (serial.SerialException, OSError, ImportError) as e:
            self.log.error(f"Serial connection error during init: {str(e)}")
            # Ensure serial is None if init fails partially
            if self.serial and self.serial.is_open:
                 try:
                     self.serial.close()
                 except Exception: # Ignore close errors during init failure
                     pass
            self.serial = None
            # Re-raise the original exception to signal failure
            raise serial.SerialException(f"Failed to open USB device {address}: {e}") from e
        except Exception as e: # Catch any other unexpected init errors
            self.log.error(f"Unexpected error during USBStream init: {str(e)}", exc_info=True)
            if self.serial and self.serial.is_open:
                 try:
                     self.serial.close()
                 except Exception:
                     pass
            self.serial = None
            raise # Re-raise unexpected exceptions

    def close(self) -> bool:
        """Close serial connection"""
        closed_successfully = True
        # No need to check if self.serial exists, __init__ guarantees it if successful
        # or raises an exception otherwise. We only need to check if it's not None
        # in case close is called multiple times or after a failed init somehow.
        if self.serial:
            try:
                if hasattr(self, 'modem') and self.modem is not None:
                    # Consider if modem cleanup is needed. If XMODEM manages its own state,
                    # this might be removable. Assuming it might be needed for now.
                    # self.modem.clear_mode_set() # If modem has state tied to stream
                    pass # Assuming modem state is handled elsewhere or not needed here

                if self.serial.is_open:
                    self.log.debug("Closing serial port...")
                    self.serial.close()
                    self.log.debug("Serial port closed.")
                else:
                    self.log.debug("Serial port was already closed.")

            except Exception as e:
                self.log.error(f"Error closing serial connection: {str(e)}")
                closed_successfully = False
            finally:
                # Always set self.serial to None after attempting close
                self.serial = None
                self._read_buffer = b''  # Clear buffer on close
                self.log.debug("self.serial set to None.")
        else:
             self.log.debug("Close called but self.serial is already None.")

        return closed_successfully # Return status of the close operation

    def send(self, data: bytes) -> None:
        """Send data over serial connection"""
        try:
            # self.log.debug(f"Sending data: {data!r}") # Avoid logging potentially large data
            self.serial.write(data)
            self.serial.flush()
        except (serial.SerialException, AttributeError, OSError) as e: # Added AttributeError for self.serial=None case, OSError
             # Log error here is fine
             self.log.error(f"Error during serial send: {e}")
             # Optional: Re-raise or handle differently depending on desired behavior
             # raise IoError("Serial send failed") from e

    def readline(self) -> bytes:
        """
        Read a line from the serial connection, handling multiple terminator types.
        Checks for newline, EOT (0x04), and CAN (0x16) characters as terminators.
        """
        if not self.serial:
            return b''
            
        try:
            # First, read any available bytes into our buffer
            if self.serial.in_waiting:
                new_data = self.serial.read(self.serial.in_waiting)
                if new_data:
                    self._read_buffer += new_data
            
            # If buffer is still empty after read attempt, try a blocking read with timeout
            if not self._read_buffer and self.serial.timeout > 0:
                byte = self.serial.read(1)
                if byte:
                    self._read_buffer += byte
            
            # Check for terminators in our buffer
            for terminator in [b'\n', b'\x04', b'\x16']:  # \n, EOT, CAN
                found_pos = self._read_buffer.find(terminator)
                if found_pos != -1:
                    # Include the terminator in the returned line
                    line = self._read_buffer[:found_pos + 1]
                    # Remove the line and terminator from buffer
                    self._read_buffer = self._read_buffer[found_pos + 1:]
                    return line
            
            # No terminator found, return empty bytes
            return b''
            
        except (serial.SerialException, AttributeError, OSError) as e:
            self.log.error(f"Error during serial readline: {e}", exc_info=self.verbose)
            return b''  # Return empty bytes on error

    def waiting_for_recv(self) -> bool:
        """Check if there is data waiting in serial buffer or our internal buffer"""
        if self._read_buffer:
            return True
            
        try:
            # NO LOGGING
            return bool(self.serial.in_waiting)
        except (AttributeError, OSError, Exception) as e: # Catch potential errors if port closed unexpectedly
            # Log error here is fine
            self.log.debug(f"Error checking in_waiting: {e}")
            return False

    # Restore getc/putc for XMODEM
    def getc(self, size: int, timeout: float = 1.0) -> Optional[bytes]:
        """Read specific number of bytes (XMODEM)."""
        try:
            # A simple read might not respect the passed timeout if the default
            # serial timeout is shorter. This requires more complex handling if precise
            # timeout per call is needed, e.g., temporarily changing self.serial.timeout.
            # For now, relies on the default timeout set in __init__.
            data = self.serial.read(size)
            # Check if the correct amount of data was received
            if data and len(data) == size:
                return data
            # Handle timeout or incomplete read (read returned less than 'size')
            # self.log.debug(f"getc timeout or incomplete read: expected {size}, got {len(data)}") # Potentially noisy
            return None
        except (serial.SerialException, AttributeError, OSError) as e: # Added AttributeError for self.serial=None case, OSError
            # Log error here is fine
            self.log.error(f"Error during serial getc read: {e}")
            return None

    def putc(self, data: bytes, timeout: float = 1.0) -> Optional[int]:
        """Write specific bytes (XMODEM)."""
        try:
            # Similar timeout consideration as getc. Relies on default write timeout handling.
            bytes_written = self.serial.write(data)
            self.serial.flush() # Ensure data is sent immediately
            return bytes_written or None # Should return number of bytes written or None on error
        except (serial.SerialException, AttributeError, OSError) as e: # Added AttributeError for self.serial=None case, OSError
            # Log error here is fine
            self.log.error(f"Error during serial putc write: {e}")
            return None

    # Restore list_ports static method
    @staticmethod
    def list_ports() -> List[Dict[str, str]]:
        """List available serial ports (Static method - no self.log)."""
        ports = []
        try:
            for port in serial.tools.list_ports.comports():
                ports.append({
                    'port': port.device,
                    'description': port.description,
                    'hwid': port.hwid
                })
        except Exception as e:
            # Use root logger for static method error
            logging.error(f"Error listing serial ports: {str(e)}")
        return ports

    # Omit upload/download methods for now, as they were complex
    # and DeviceManager handles the XMODEM logic using getc/putc.


