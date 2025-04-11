import logging
from typing import Optional, Tuple, Union

# Import the specific stream types
from ..streams.usb import USBStream
from ..streams.wifi import WiFiStream
# Import the Stream protocol
from ..streams.streams import Stream

class Connection:
    """Handles detection and creation of device communication streams."""

    @staticmethod
    def wifi(address: str) -> Optional[Stream]:
        """
        Attempts to establish a WiFi connection.

        Args:
            address: IP address (and optional port) of the device.

        Returns:
            A Stream instance if successful, None otherwise.
        """
        log = logging.getLogger("Connection.wifi")
        log.info(f"Attempting WiFi connection to {address}...")
        try:
            stream: WiFiStream = WiFiStream(address=address)
            log.info(f"WiFi connection successful to {address}.")
            # Return the WiFiStream instance, which conforms to the Stream protocol
            return stream
        except Exception as e:
            log.error(f"Failed to connect via WiFi to {address}: {e}")
            return None

    @staticmethod
    def usb(port: str) -> Optional[Stream]:
        """
        Attempts to establish a USB serial connection.

        Args:
            port: The serial port identifier (e.g., /dev/ttyUSB0 or COM3).

        Returns:
            A Stream instance if successful, None otherwise.
        """
        log = logging.getLogger("Connection.usb")
        log.info(f"Attempting USB connection to {port}...")
        try:
            stream: USBStream = USBStream()
            if stream.open(port):
                log.info(f"USB connection successful to {port}.")
                # Return the USBStream instance, which conforms to the Stream protocol
                return stream
            else:
                log.error(f"Failed to open USB connection to {port}.")
                return None
        except Exception as e:
            log.error(f"Unexpected error connecting via USB to {port}: {e}", exc_info=True)
            return None

    @staticmethod
    def auto(wifi_timeout: int = 3) -> Optional[Tuple[Stream, str]]:
        """
        Automatically detects and connects to the first available Carvera device.
        Prioritizes WiFi, then checks USB.

        Args:
            wifi_timeout: Seconds to wait for WiFi discovery broadcasts.

        Returns:
            A tuple containing the connected Stream object and its address (IP or port),
            or (None, "") if no device is found or connection fails.
        """
        log = logging.getLogger("Connection.auto")

        # --- Try WiFi First ---
        log.info(f"Scanning for WiFi devices ({wifi_timeout}s timeout)...")
        try:
            wifi_devices = WiFiStream.discover_devices(timeout=wifi_timeout)
            if wifi_devices:
                available_devices = [d for d in wifi_devices if not d.get('busy', True)]
                selected_device_info = available_devices[0] if available_devices else wifi_devices[0]
                device_ip = selected_device_info['ip']
                device_name = selected_device_info['machine']
                is_busy = selected_device_info.get('busy', False)
                log.info(f"Found WiFi device: {device_name} at {device_ip}{' (Busy)' if is_busy else ''}")

                stream: Optional[Stream] = Connection.wifi(device_ip)
                if stream:
                    log.info(f"Auto-connected via WiFi to {device_ip}")
                    return stream, device_ip
                else:
                    log.warning(f"Found WiFi device {device_ip}, but failed to establish connection.")
            else:
                 log.info("No WiFi devices found.")

        except Exception as e:
            log.error(f"Error during WiFi discovery or connection: {e}", exc_info=True)

        # --- Try USB If WiFi Fails ---
        log.info("Scanning for USB devices...")
        try:
            usb_ports = USBStream.list_ports()
            if usb_ports:
                carvera_ports = [p for p in usb_ports if 'ch340' in p['description'].lower() or 'usb-serial' in p['description'].lower()]
                selected_port_info = carvera_ports[0] if carvera_ports else usb_ports[0]
                port_name = selected_port_info['port']
                port_desc = selected_port_info['description']
                log.info(f"Found USB device: {port_name} - {port_desc}")

                stream: Optional[Stream] = Connection.usb(port_name)
                if stream:
                     log.info(f"Auto-connected via USB to {port_name}")
                     return stream, port_name
                else:
                     log.warning(f"Found USB device {port_name}, but failed to establish connection.")
            else:
                log.info("No USB devices found.")

        except Exception as e:
             log.error(f"Error during USB discovery or connection: {e}", exc_info=True)

        # --- No Connection ---
        log.info("Auto-detection failed: No connectable device found.")
        return None, "" 