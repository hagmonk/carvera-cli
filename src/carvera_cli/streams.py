"""
Stream Classes for Communication

Provides base Stream class and implementations (USB, WiFi) for
communicating with Carvera CNC devices.
"""

import time
import socket
import select
import logging
import re
from typing import Optional, List, Dict, Callable, Tuple

# Try to import serial module for detection, handle gracefully if not available
try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

# Constants
SERIAL_TIMEOUT = 0.3  # seconds
TCP_PORT = 2222
UDP_PORT = 3333
SOCKET_TIMEOUT = 0.3  # seconds


class Stream:
    """Base class for communication streams"""
    
    def open(self, address: str) -> bool:
        """Open the connection"""
        raise NotImplementedError
    
    def close(self) -> bool:
        """Close the connection"""
        raise NotImplementedError
    
    def send(self, data: bytes) -> None:
        """Send data over the connection"""
        raise NotImplementedError
    
    def recv(self, bufsize: int = 1024) -> bytes:
        """Receive data from the connection"""
        raise NotImplementedError
    
    def waiting_for_recv(self) -> bool:
        """Check if there is data waiting to be received"""
        raise NotImplementedError


class USBStream(Stream):
    """USB Serial connection implementation"""
    
    def __init__(self):
        self.serial = None
        self.modem = None
        self.verbose = False
    
    def open(self, address: str) -> bool:
        """
        Open serial connection to the device
        
        Args:
            address: Serial port name (COM1, /dev/ttyUSB0, etc.)
            
        Returns:
            True if connection successful, False otherwise
        """
        if not SERIAL_AVAILABLE:
            print("Warning: PySerial not installed. USB connections will not be available.")
            print("Install with: pip install pyserial")
            logging.error("PySerial not installed. Cannot open USB connection.")
            return False
            
        try:
            self.serial = serial.serial_for_url(
                address.replace('\\', '\\\\'),  # Escape for Windows
                115200,  # Baud rate
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=SERIAL_TIMEOUT,
                write_timeout=SERIAL_TIMEOUT,
                xonxoff=False,
                rtscts=False
            )
            
            # Toggle DTR to reset Arduino/microcontroller
            try:
                self.serial.setDTR(0)
            except IOError:
                pass
            
            self.serial.flushInput()
            try:
                self.serial.setDTR(1)
            except IOError:
                pass
            
            return True
        except (serial.SerialException, OSError, ImportError) as e:
            logging.error(f"Serial connection error: {str(e)}")
            return False
    
    def close(self) -> bool:
        """Close serial connection"""
        if self.serial is None:
            return True
            
        try:
            # Reset XMODEM mode_set flag if modem exists
            if hasattr(self, 'modem') and self.modem is not None:
                self.modem.clear_mode_set()
                
            self.serial.close()
        except Exception as e:
            logging.error(f"Error closing serial connection: {str(e)}")
            return False
            
        self.serial = None
        return True
    
    def send(self, data: bytes) -> None:
        """Send data over serial connection"""
        if self.serial:
            self.serial.write(data)
    
    def recv(self) -> bytes:
        """Receive data from serial connection"""
        if self.serial:
            return self.serial.read()
        return b''
    
    def waiting_for_recv(self) -> bool:
        """Check if there is data waiting in serial buffer"""
        if self.serial:
            return bool(self.serial.in_waiting)
        return False
        
    def getc(self, size: int, timeout: float = 1.0) -> Optional[bytes]:
        """
        Read data from the serial port (for XMODEM)
        
        Args:
            size: Number of bytes to read
            timeout: Timeout in seconds
            
        Returns:
            Bytes read or None if timeout or incomplete data
        """
        if not self.serial:
            return None
            
        # Set temporary timeout for this read
        old_timeout = self.serial.timeout
        self.serial.timeout = timeout
        
        try:
            data = self.serial.read(size)
            # Only return data if we got exactly the requested number of bytes
            if data and len(data) == size:
                return data
            # Return None for timeout or partial read
            return None
        finally:
            # Restore original timeout
            self.serial.timeout = old_timeout
    
    def putc(self, data: bytes, timeout: float = 1.0) -> Optional[int]:
        """
        Write data to the serial port (for XMODEM)
        
        Args:
            data: Data to write
            timeout: Timeout in seconds
            
        Returns:
            Number of bytes written or None if timeout
        """
        if not self.serial:
            return None
            
        # Set temporary timeout for this write
        old_timeout = self.serial.write_timeout
        self.serial.write_timeout = timeout
        
        try:
            return self.serial.write(data) or None
        except (serial.SerialTimeoutException, serial.SerialException):
            return None
        finally:
            # Restore original timeout
            self.serial.write_timeout = old_timeout
            
    def upload(self, file_path: str, md5: str, callback: Optional[Callable] = None) -> bool:
        """
        Upload a file using XMODEM protocol
        
        Args:
            file_path: Path to the file to upload
            md5: MD5 hash (unused in this implementation)
            callback: Progress callback function
            
        Returns:
            True if upload successful, False otherwise
        """
        if not self.serial:
            logging.error("Cannot upload: No serial connection")
            return False
            
        # Import XMODEM implementation here to avoid circular import
        from carvera_cli.xmodem import XMODEM
            
        # Initialize XMODEM if not already initialized
        if self.modem is None:
            # Use xmodem mode (128-byte blocks) for USB as in the original code
            self.modem = XMODEM(self.getc, self.putc, 'xmodem')
            
        # Open the file and send it
        try:
            with open(file_path, 'rb') as stream:
                return self.modem.send(stream, md5, retry=10, timeout=10, callback=callback)
        except Exception as e:
            logging.error(f"XMODEM upload error: {str(e)}")
            return False
        
    @staticmethod
    def list_ports() -> List[Dict[str, str]]:
        """
        List available serial ports
        
        Returns:
            List of dicts with port info (port, description, hwid)
        """
        if not SERIAL_AVAILABLE:
            print("Warning: PySerial not installed. USB connections will not be available.")
            print("Install with: pip install pyserial")
            logging.warning("Cannot list USB ports, PySerial not installed")
            return []
            
        ports = []
        try:
            for port in serial.tools.list_ports.comports():
                ports.append({
                    'port': port.device,
                    'description': port.description,
                    'hwid': port.hwid
                })
        except Exception as e:
            logging.error(f"Error listing serial ports: {str(e)}")
        
        return ports

    def download(self, filename: str, local_md5: str, callback: Optional[Callable] = None) -> bool:
        """
        Download a file using XMODEM protocol
        
        Args:
            filename: Local path to save the file
            local_md5: MD5 hash of existing file (for comparison)
            callback: Progress callback function
            
        Returns:
            True if download successful, False otherwise
        """
        if not self.serial:
            logging.error("Cannot download: No serial connection")
            return False
            
        # Import XMODEM implementation here to avoid circular import
        from carvera_cli.xmodem import XMODEM
            
        # Initialize XMODEM if not already initialized
        if self.modem is None:
            # Use xmodem mode (128-byte blocks) for USB as in the original code
            self.modem = XMODEM(self.getc, self.putc, 'xmodem')
            
        # Set a good timeout for XMODEM transfers
        old_timeout = self.serial.timeout
        self.serial.timeout = 2.0
        
        # Clear any pending data
        try:
            while self.serial.in_waiting:
                self.serial.read(self.serial.in_waiting)
        except Exception as e:
            logging.debug(f"Error clearing serial buffer: {str(e)}")
            pass
            
        # Open the file and receive data
        try:
            with open(filename, 'wb') as stream:
                # Using retry=10 to match exactly what the original Carvera code does
                result = self.modem.recv(stream, local_md5, retry=20, timeout=2.0, callback=callback)
                return result  # Return the raw result for proper handling by uploader
        except Exception as e:
            logging.error(f"XMODEM download error: {str(e)}")
            return None
        finally:
            # Restore original timeout
            try:
                self.serial.timeout = old_timeout
            except:
                pass


class MachineDetector:
    """Handles UDP broadcast listening for device discovery"""
    
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


class WiFiStream(Stream):
    """WiFi network connection implementation"""
    
    def __init__(self):
        self.socket = None
        self.modem = None
        self.verbose = False  # For logging errors
    
    def open(self, address: str) -> bool:
        """
        Open socket connection to the device
        
        Args:
            address: IP address and optional port (format: 192.168.1.100:2222)
                    If no port specified, default TCP_PORT is used
                    
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            ip_port = address.split(':')
            ip = ip_port[0]
            port = int(ip_port[1]) if len(ip_port) > 1 else TCP_PORT
            
            self.socket.settimeout(2)  # Initial connection timeout
            self.socket.connect((ip, port))
            self.socket.settimeout(SOCKET_TIMEOUT)  # Normal operation timeout
            
            return True
        except (socket.timeout, socket.error) as e:
            logging.error(f"WiFi connection error: {str(e)}")
            return False
    
    def close(self) -> bool:
        """Close socket connection"""
        if self.socket is None:
            return True
            
        try:
            # Reset XMODEM mode_set flag if modem exists
            if hasattr(self, 'modem') and self.modem is not None:
                self.modem.clear_mode_set()
                
            self.socket.close()
        except Exception as e:
            logging.error(f"Error closing WiFi connection: {str(e)}")
            return False
            
        self.socket = None
        return True
    
    def send(self, data: bytes) -> None:
        """Send data over socket connection"""
        if self.socket:
            self.socket.send(data)
    
    def recv(self, bufsize: int = 1024) -> bytes:
        """Receive data from socket connection"""
        if self.socket:
            try:
                # Read up to bufsize bytes
                return self.socket.recv(bufsize)
            except (socket.timeout, socket.error):
                pass
        return b''
    
    def waiting_for_recv(self) -> bool:
        """Check if there is data waiting in socket buffer"""
        if self.socket:
            socket_list = [self.socket]
            # Get the list of sockets which are readable with timeout=0 (non-blocking)
            read_sockets, _, _ = select.select(socket_list, [], [], 0)
            return bool(read_sockets)
        return False
        
    def getc(self, size: int, timeout: float = 0.5) -> Optional[bytes]:
        """
        Read data from the socket (for XMODEM)
        
        Args:
            size: Number of bytes to read
            timeout: Timeout in seconds
            
        Returns:
            Bytes read or None if timeout or error
        """
        if not self.socket:
            return None
            
        # Store original timeout
        orig_timeout = self.socket.gettimeout()
        
        try:
            # Set new timeout for this operation
            self.socket.settimeout(timeout)
            
            # First check if data is available
            ready = select.select([self.socket], [], [], timeout)
            if not ready[0]:
                return None
                
            # Read the requested number of bytes
            data = b''
            remaining = size
            start_time = time.time()
            
            while remaining > 0:
                # Check if we're out of time
                if time.time() - start_time > timeout:
                    return None
                
                # Try to read remaining bytes
                chunk = self.socket.recv(remaining)
                if not chunk:  # Connection closed
                    return None
                    
                data += chunk
                remaining -= len(chunk)
                
                # If we got all the data, return it
                if len(data) == size:
                    return data
                    
                # Short sleep to prevent CPU spinning
                time.sleep(0.01)
                
            return data
        except (socket.timeout, socket.error, BlockingIOError) as e:
            # For debugging, log the error
            if self.verbose:
                logging.debug(f"Socket getc error: {str(e)}")
            return None
        finally:
            # Restore original timeout
            try:
                self.socket.settimeout(orig_timeout)
            except:
                pass

    def putc(self, data: bytes, timeout: float = 0.5) -> Optional[int]:
        """
        Write data to the socket (for XMODEM)
        
        Args:
            data: Data to write
            timeout: Timeout in seconds
            
        Returns:
            Number of bytes written or None if timeout or error
        """
        if not self.socket:
            return None
            
        # Store original timeout
        orig_timeout = self.socket.gettimeout()
        
        try:
            # Set socket timeout for this operation
            self.socket.settimeout(timeout)
            
            # Check if socket is writable
            ready = select.select([], [self.socket], [], timeout)
            if not ready[1]:
                return None
                
            # Send the data
            bytes_sent = self.socket.send(data)
            
            # Verify all data was sent
            if bytes_sent != len(data):
                if self.verbose:
                    logging.debug(f"Only sent {bytes_sent}/{len(data)} bytes")
                return None
                
            return bytes_sent
        except (socket.timeout, socket.error, BlockingIOError) as e:
            # For debugging, log the error
            if self.verbose:
                logging.debug(f"Socket putc error: {str(e)}")
            return None
        finally:
            # Restore original timeout
            try:
                self.socket.settimeout(orig_timeout)
            except:
                pass
            
    def upload(self, file_path: str, md5: str, callback: Optional[Callable] = None) -> bool:
        """
        Upload a file using XMODEM protocol
        
        Args:
            file_path: Path to the file to upload
            md5: MD5 hash (unused in this implementation)
            callback: Progress callback function
            
        Returns:
            True if upload successful, False otherwise
        """
        if not self.socket:
            logging.error("Cannot upload: No WiFi connection")
            return False
            
        # Import XMODEM implementation here to avoid circular import
        from carvera_cli.xmodem import XMODEM
            
        # Initialize XMODEM if not already initialized
        if self.modem is None:
            # Use xmodem8k mode (8192-byte blocks) for WiFi as in WIFIStream.py
            self.modem = XMODEM(self.getc, self.putc, 'xmodem8k')
            
        # Reset socket timeout for better stability during XMODEM transfer
        old_timeout = self.socket.gettimeout()
        self.socket.settimeout(1.0)  # Longer socket timeout during XMODEM
        
        # Clear any pending data in receive buffer
        try:
            while self.waiting_for_recv():
                self.socket.recv(1024)
        except:
            pass
            
        # Open the file and send it
        try:
            with open(file_path, 'rb') as stream:
                # Use longer timeout and more retries for better reliability
                result = self.modem.send(stream, md5, retry=20, timeout=2.0, callback=callback)
                return result
        except Exception as e:
            logging.error(f"XMODEM upload error: {str(e)}")
            return False
        finally:
            # Restore original socket timeout
            try:
                self.socket.settimeout(old_timeout)
            except:
                pass
        
    @staticmethod
    def discover_devices(timeout: int = 3) -> List[Dict[str, any]]:
        """
        Discover Carvera devices on the network by listening for UDP broadcasts.
        """
        log = logging.getLogger("WiFiStream.Discovery") 
        detector = MachineDetector()
        
        if not detector.sock:
             log.error("Discovery failed: Could not initialize listener socket.")
             return []
             
        log.info(f"Listening for device broadcasts on UDP port {detector.LISTEN_PORT} for {timeout} seconds...")
            
        end_time = time.time() + timeout
        while time.time() < end_time:
            # Repeatedly check for broadcast packets
            detector.check_for_responses() 
            time.sleep(0.1) # Short sleep between checks
            
        # Get final list and close socket
        collected_responses = detector.get_final_responses()
        detector.close_socket()

        if collected_responses:
            log.info(f"Discovery finished. Found {len(collected_responses)} device(s).")
        else:
            log.info("Discovery finished. No devices found.")
                   
        return collected_responses

    def download(self, filename: str, local_md5: str, callback: Optional[Callable] = None) -> bool:
        """
        Download a file using XMODEM protocol
        
        Args:
            filename: Local path to save the file
            local_md5: MD5 hash of existing file (for comparison)
            callback: Progress callback function
            
        Returns:
            True if download successful, False otherwise
        """
        if not self.socket:
            logging.error("Cannot download: No WiFi connection")
            return False
            
        # Import XMODEM implementation here to avoid circular import
        from carvera_cli.xmodem import XMODEM
            
        # Initialize XMODEM if not already initialized
        if self.modem is None:
            # Use xmodem8k mode (8192-byte blocks) for WiFi as in the original code
            self.modem = XMODEM(self.getc, self.putc, 'xmodem8k')
            
        # Reset socket timeout for better stability during XMODEM transfer
        old_timeout = self.socket.gettimeout()
        self.socket.settimeout(2.0)  # Longer socket timeout during XMODEM transfer
        
        # Clear any pending data in receive buffer
        try:
            ready = select.select([self.socket], [], [], 0.1)
            while ready[0]:
                self.socket.recv(4096)
                ready = select.select([self.socket], [], [], 0.1)
        except:
            pass
            
        # For debugging only - enable verbose packets if needed
        self.modem.verbose_packets = True
            
        # Open file for writing and receive data
        try:
            with open(filename, 'wb') as stream:
                # Using retry=10 to match exactly what the original Carvera code does
                result = self.modem.recv(stream, local_md5, retry=20, timeout=2.0, callback=callback)
                return result  # Return the raw result for proper handling by uploader
        except Exception as e:
            logging.error(f"XMODEM download error: {str(e)}")
            return None
        finally:
            # Restore original socket timeout
            try:
                self.socket.settimeout(old_timeout)
            except:
                pass 