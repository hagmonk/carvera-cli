import logging
import select
import socket
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple
# Removed XMODEM import from top level as upload/download are commented out
# from carvera_cli.xmodem import XMODEM 
from carvera_cli.streams.streams import Stream

TCP_PORT = 2222
UDP_PORT = 3333
SOCKET_TIMEOUT = 0.3  # seconds
# Increased default connection timeout slightly
CONNECTION_TIMEOUT = 5.0 # seconds 

class WiFiStream(Stream):
    """WiFi network connection implementation, established on initialization."""
    
    def __init__(self, address: str, verbose: bool = False):
        """
        Initialize and open socket connection. Raises socket.error on failure.
        
        Args:
            address: IP address and optional port (format: 192.168.1.100:2222)
                     If no port specified, default TCP_PORT is used.
        """
        # super().__init__() # No base __init__ in Stream
        self.address = address # Store address as instance variable
        self.socket: Optional[socket.socket] = None
        # self.modem: Optional['XMODEM'] = None # Removed modem instance - handled externally
        self.log = logging.getLogger(f"WiFiStream({self.address})") # Use self.address here too
        self.verbose = verbose
        self._read_buffer = b'' # Add internal buffer for readline
        self._connect()

    def _connect(self):
        self.log.debug(f"Attempting to connect to {self.address}...") # Already DEBUG
        try:
            self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            
            # Set socket options for better reliability with small packets
            # Disable Nagle's algorithm to prevent buffering of small packets like EOT
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.log.debug("TCP_NODELAY set to prevent small packet buffering")
            
            # Set a larger receive buffer size to ensure we don't lose small packets
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)  # 128KB
            self.log.debug("Increased socket receive buffer size for better reliability")
            
            # Enable keepalive to detect network issues earlier
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.log.debug("Socket keepalive enabled")
            
            ip_port = self.address.split(':') # Use self.address
            ip = ip_port[0]
            port = int(ip_port[1]) if len(ip_port) > 1 else TCP_PORT
            
            self.socket.settimeout(CONNECTION_TIMEOUT)  # Initial connection timeout
            self.socket.connect((ip, port))
            self.socket.settimeout(SOCKET_TIMEOUT)  # Normal operation timeout
            
            self.log.info(f"WiFi connection established successfully to {self.address}") # Keep INFO
            
        except (socket.timeout, socket.error, OSError) as e:
            self.log.error(f"WiFi connection error during init: {str(e)}")
            # Ensure socket is closed and set to None if init fails partially
            if self.socket:
                 try:
                     self.socket.close()
                 except Exception: # Ignore close errors during init failure
                     pass
            self.socket = None
            # Re-raise the original exception (or a consistent one)
            raise socket.error(f"Failed to connect to WiFi device {self.address}: {e}") from e # Use self.address
        except Exception as e: # Catch any other unexpected init errors
            self.log.error(f"Unexpected error during WiFiStream init: {str(e)}", exc_info=True)
            if self.socket:
                 try:
                     self.socket.close()
                 except Exception:
                     pass
            self.socket = None
            raise # Re-raise unexpected exceptions

    # Removed open method
    # def open(self, address: str) -> bool:
    #     ...
    
    def close(self) -> bool:
        """Close socket connection"""
        closed_successfully = True
        # Only need to check if socket is not None
        if self.socket:
            try:
                # Reset XMODEM mode_set flag if modem exists - This logic should move outside Stream
                # if hasattr(self, 'modem') and self.modem is not None:
                #     self.modem.clear_mode_set()
                
                self.log.debug("Closing socket...")
                self.socket.close()
                self.log.debug("Socket closed.")
            except Exception as e:
                self.log.error(f"Error closing WiFi connection: {str(e)}")
                closed_successfully = False
            finally:
                # Always set self.socket to None after attempting close
                self.socket = None 
                self.log.debug("self.socket set to None.")
        else:
            self.log.debug("Close called but self.socket is already None.")
            
        return closed_successfully
    
    def send(self, data: bytes) -> None:
        """Send data over socket connection"""
        # No self.socket check needed
        try:
            self.socket.sendall(data) # Use sendall for simplicity/reliability
        except (socket.error, AttributeError, OSError) as e: # Added AttributeError/OSError
            self.log.error(f"Error during socket send: {e}")
            # Optional: Re-raise a specific error type?
            raise IOError("WiFi send failed") from e 
    
    def recv(self, bufsize: int = 1024) -> bytes:
        """Receive data from socket connection with improved handling for small packets.
           Uses select() for timeout handling and then tries to read all available data.
        """
        if not self.socket:
            return b''
            
        try:
            # Use select to check if data is available with proper timeout handling
            ready_to_read, _, _ = select.select([self.socket], [], [], self.socket.gettimeout())
            
            if not ready_to_read:
                # No data available within timeout
                return b''
                
            # Data is available - get everything we can without blocking
            data = b''
            try:
                # First read - might get everything or just part of the data
                chunk = self.socket.recv(bufsize)
                if not chunk:  # Connection closed by peer
                    return b''
                data += chunk
                
                # Try to get any remaining data that might be buffered
                # without waiting (non-blocking)
                try:
                    while True:
                        # MSG_DONTWAIT = non-blocking read
                        more_data = self.socket.recv(bufsize, socket.MSG_DONTWAIT)
                        if not more_data:
                            break
                        data += more_data
                except (socket.error, BlockingIOError):
                    # No more data available right now - this is expected
                    pass
            except socket.error as e:
                # Handle socket errors during read
                self.log.error(f"Error during socket recv: {e}", exc_info=self.verbose)
                return b''
            
            return data
            
        except socket.timeout:
            # This is expected if no data arrives within the default timeout
            return b''
        except (socket.error, AttributeError, OSError) as e:
            # Handle other socket errors
            self.log.error(f"Error during socket recv: {e}", exc_info=self.verbose)
            return b''
    
    def readline(self, timeout: Optional[float] = None) -> bytes:
        """Read one line from the stream, ending in \n.
           Uses the socket's default timeout unless overridden.
           Returns empty bytes (b'') on timeout or connection closed.
        """
        if not self.socket:
            return b''
            
        start_time = time.monotonic()
        
        # Use provided timeout or the socket's default
        effective_timeout = timeout if timeout is not None else self.socket.gettimeout()
        if effective_timeout is None:
             self.log.warning("readline called on blocking socket without specific timeout, may block indefinitely.")
             # Set a reasonable default if none exists to prevent potential infinite block
             effective_timeout = 30.0 # Default readline timeout if socket is blocking
            
        # Check immediate buffer first before any reads
        for terminator in [b'\n', b'\x04', b'\x16']:  # \n, EOT, CAN
            found_pos = self._read_buffer.find(terminator)
            if found_pos != -1:
                # Include the terminator in the returned line
                line = self._read_buffer[:found_pos + 1]
                # Remove the line and terminator from buffer
                self._read_buffer = self._read_buffer[found_pos + 1:]
                return line
            
        while True:
            # Check overall timeout
            elapsed_time = time.monotonic() - start_time
            if elapsed_time > effective_timeout:
                # Return whatever is left in the buffer if we timeout
                line = self._read_buffer 
                self._read_buffer = b'' 
                self.log.debug(f"readline timed out after {effective_timeout:.2f}s. Returning partial: {line!r}")
                return line # Return partial line on timeout

            # Calculate remaining time for the recv call
            remaining_time = max(0.001, effective_timeout - elapsed_time)
            if remaining_time <= 0.001: # Effectively zero time left
                line = self._read_buffer
                self._read_buffer = b''
                self.log.debug(f"readline timed out just before recv. Returning partial: {line!r}")
                return line
            
            # Set socket timeout for the upcoming recv call
            original_timeout = self.socket.gettimeout()
            try:
                self.socket.settimeout(remaining_time)
                # Use our improved recv method to get data more aggressively
                chunk = self.recv(1024)
            except Exception as e:
                self.log.error(f"Error during readline recv: {e}", exc_info=self.verbose)
                chunk = b''
            finally:
                # Always restore original timeout
                if self.socket:
                    self.socket.settimeout(original_timeout)

            # Handle empty chunk (timeout or connection closed)
            if not chunk:
                # Check if socket is closed
                if not self.socket or self.socket.fileno() == -1:
                    line = self._read_buffer
                    self._read_buffer = b''
                    self.log.warning(f"readline: socket closed. Returning partial: {line!r}")
                    return line
                # Just a timeout, keep looping
                continue
                
            # Add the new data to our buffer
            self._read_buffer += chunk
            
            # After adding to buffer, immediately check for terminators
            for terminator in [b'\n', b'\x04', b'\x16']:  # \n, EOT, CAN
                found_pos = self._read_buffer.find(terminator)
                if found_pos != -1:
                    # Include the terminator in the returned line
                    line = self._read_buffer[:found_pos + 1]
                    # Remove the line and terminator from buffer
                    self._read_buffer = self._read_buffer[found_pos + 1:]
                    return line

    def waiting_for_recv(self) -> bool:
        """Check if there is data waiting in socket buffer using select. Returns False on error."""
        # No self.socket check needed
        try:
            socket_list = [self.socket]
            # Get the list of sockets which are readable with timeout=0 (non-blocking)
            read_sockets, _, _ = select.select(socket_list, [], [], 0)
            return bool(read_sockets)
        except (ValueError, AttributeError, Exception) as e: # Handle closed socket, etc.
            self.log.debug(f"Error checking waiting_for_recv (socket likely closed): {e}")
            return False
        
    def getc(self, size: int, timeout: float = 1.0) -> Optional[bytes]:
        """
        Read exactly size bytes from the socket (intended for XMODEM).

        Args:
            size: Number of bytes to read.
            timeout: Total timeout in seconds for the read operation.

        Returns:
            Bytes read (exactly size bytes) or None if timeout or error occurs.
        """
        # No self.socket check needed initially
        
        data = bytearray()
        start_time = time.monotonic()
        
        # Store original timeout to restore it later
        original_timeout = self.socket.gettimeout()
        
        try:
            while len(data) < size:
                time_elapsed = time.monotonic() - start_time
                remaining_time = timeout - time_elapsed
                
                if remaining_time <= 0:
                    # self.log.debug(f"getc timeout: read {len(data)}/{size} bytes in {timeout}s")
                    return None # Timeout occurred

                # Set socket timeout for this specific read attempt
                # Use a small positive value to avoid blocking indefinitely if remaining_time is tiny
                current_read_timeout = max(0.001, remaining_time) 
                self.socket.settimeout(current_read_timeout)

                try:
                    # Read up to the remaining number of bytes needed
                    bytes_to_read = size - len(data)
                    chunk = self.socket.recv(bytes_to_read)
                    
                    if not chunk:
                        # Socket closed by peer
                        self.log.warning("getc: Socket closed by peer while reading.")
                        return None 
                        
                    data.extend(chunk)
                    
                except socket.timeout:
                    # Individual recv timed out, but overall timeout might not be reached yet.
                    # Loop continues to check overall timeout.
                    # If remaining_time was indeed <=0, the check at loop start will catch it.
                    # If overall timeout not reached, simply means no data arrived in this interval.
                     pass # Continue loop to check overall timeout

        except (socket.error, AttributeError, OSError) as e:
            self.log.error(f"Socket error during getc: {e}", exc_info=self.verbose)
            return None
        except Exception as e: # Catch unexpected errors
             self.log.error(f"Unexpected error during getc: {e}", exc_info=True)
             return None
        finally:
            # Restore original socket timeout
            try:
                if self.socket: # Check if socket still exists before restoring
                    self.socket.settimeout(original_timeout)
            except (socket.error, AttributeError, OSError): 
                 # Ignore errors during timeout restoration, especially if socket closed
                 pass

        # After loop, check if we got the required size (handles cases where loop exits unexpectedly)
        if len(data) == size:
            return bytes(data)
        else:
            # Should have been caught by timeout check, but as a safeguard
            # self.log.debug(f"getc failed: read {len(data)}/{size} bytes") 
            return None

    def putc(self, data: bytes, timeout: float = 1.0) -> Optional[int]:
        """
        Write data to the socket (intended for XMODEM).

        Args:
            data: Data to write.
            timeout: Timeout in seconds (Note: Actual network timeout depends on TCP stack).

        Returns:
            Number of bytes written or None if error.
        """
        # No self.socket check needed initially
        
        # Note: Standard socket.sendall doesn't have an explicit timeout parameter like recv.
        # The system's TCP timeout mechanisms apply. We can set a socket timeout
        # beforehand, but sendall might block longer internally.
        # This implementation mirrors the simplicity of the original putc.
        
        original_timeout = self.socket.gettimeout()
        bytes_written = None
        try:
            # Set timeout for the operation, although sendall might block differently
            # self.socket.settimeout(timeout) # Optional: set timeout before sendall
            bytes_written = self.socket.sendall(data) # sendall returns None on success
            # If sendall succeeds, the number of bytes written is len(data)
            return len(data)
        except (socket.timeout, socket.error, AttributeError, OSError) as e: # Added AttributeError/OSError
            self.log.error(f"Socket putc error: {e}", exc_info=self.verbose)
            return None
        except Exception as e: # Catch unexpected errors
             self.log.error(f"Unexpected error during putc: {e}", exc_info=True)
             return None
        finally:
             # Restore original socket timeout
            try:
                if self.socket:
                     self.socket.settimeout(original_timeout)
            except (socket.error, AttributeError, OSError):
                 pass # Ignore restoration errors

    @staticmethod
    def discover_devices(timeout: int = 3) -> List[Dict[str, any]]:
        """
        Discover Carvera devices on the network by listening for UDP broadcasts.
        (Static method - unchanged)
        """
        log = logging.getLogger("WiFiStream.Discovery") 
        detector = MachineDetector()
        
        if not detector.sock:
             log.error("Discovery failed: Could not initialize listener socket.")
             return []
             
        log.info(f"Listening for device broadcasts on UDP port {detector.LISTEN_PORT} for {timeout} seconds...") # Keep INFO
            
        end_time = time.time() + timeout
        while time.time() < end_time:
            # Repeatedly check for broadcast packets
            detector.check_for_responses() 
            # Reduce sleep time for potentially faster discovery within timeout
            time.sleep(0.05) # Short sleep between checks 
            
        # Get final list and close socket
        collected_responses = detector.get_final_responses()
        detector.close_socket()

        if collected_responses:
            log.info(f"Discovery finished. Found {len(collected_responses)} device(s).") # Keep INFO
        else:
            log.info("Discovery finished. No devices found.") # Keep INFO
                   
        return collected_responses

class MachineDetector:
    """Handles UDP broadcast listening for device discovery (Unchanged)"""
    
    LISTEN_PORT = 3333 # Port the device broadcasts *to*

    def __init__(self):
        self.sock = None
        self.responses = {}
        self.log = logging.getLogger("MachineDetector")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to receive broadcasts
            self.sock.bind(("", self.LISTEN_PORT)) 
            self.sock.settimeout(0.1) # Short timeout for each recvfrom check
            self.log.debug(f"UDP Listening socket bound to port {self.LISTEN_PORT}")
        except Exception as e:
            self.log.error(f"Error creating or binding UDP listener socket on port {self.LISTEN_PORT}: {str(e)}")
            self.sock = None

    def is_machine_busy(self, addr: str) -> bool:
        return self.responses.get(addr, {'busy': True}).get('busy', True)

    def check_for_responses(self) -> None:
        """Listens for and parses UDP broadcast packets, accumulating unique responses."""
        if not self.sock:
            return # Socket failed to initialize
        
        try:
            # Try to receive packets non-blockingly
            while True: 
                data, addr = self.sock.recvfrom(1024) 
                if not data:
                    break # No more data available right now
                    
                response_str = data.decode(errors='ignore')
                # Sender IP is in addr[0], not necessarily part of the payload format from C++
                sender_ip = addr[0]
                self.log.debug(f"Received discovery broadcast from {sender_ip}: {response_str.strip()}")
                
                # Parse format: "NAME,IP,PORT,BUSY_STATUS" (IP in payload might be device's idea of its IP)
                parts = response_str.strip().split(',')
                if len(parts) >= 4:
                    machine_name = parts[0]
                    device_ip_in_payload = parts[1] # Device-reported IP
                    # Use sender_ip as the key, as it's the reliable address we received from
                    ip_key = sender_ip 
                    is_busy = (parts[3] == '1') # Check if busy status is '1'
                    
                    if ip_key not in self.responses:
                        self.responses[ip_key] = {'ip': ip_key, 'machine': machine_name, 'busy': is_busy}
                        self.log.info(f"Discovered machine: {machine_name} at {ip_key}{ ' (Busy)' if is_busy else ''}")
                else:
                     self.log.debug(f"Ignored malformed broadcast from {sender_ip}: {response_str.strip()}")
                        
        except (socket.timeout, BlockingIOError):
            # Normal if no packet arrived during this check interval
            pass 
        except Exception as e:
            self.log.error(f"Error receiving UDP broadcast: {str(e)}")
            
    def get_final_responses(self) -> List[Dict[str, any]]:
        """Returns the accumulated list of unique responses."""
        return list(self.responses.values())
        
    def close_socket(self):
        if self.sock:
            try:
                self.sock.close()
                self.log.debug("Closed UDP listener socket.")
            except Exception as e:
                 self.log.debug(f"Error closing listener socket: {e}")
            finally:
                self.sock = None


