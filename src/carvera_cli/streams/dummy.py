import logging
from typing import List, Optional, Union

from .streams import Stream # Import the Stream protocol

class DummyStream(Stream):
    """A minimal dummy stream implementation for testing DeviceManager command sending."""

    def __init__(self, address: str = "dummy_addr"):
        self.log = logging.getLogger("DummyStream")
        self.address = address
        self.is_open = False
        self.sent_data: List[bytes] = []
        self.log.debug(f"Initialized minimal DummyStream for {address}")

    # --- Stream Protocol Methods --- #

    def open(self, address: str = "") -> bool:
        """Simulates opening the stream."""
        self.address = address if address else self.address
        self.is_open = True
        self.log.debug(f"DummyStream opened for {self.address}")
        return True

    def close(self) -> bool:
        """Simulates closing the stream."""
        if not self.is_open:
            return True # Closing an already closed stream is fine
        self.is_open = False
        self.log.debug(f"DummyStream closed for {self.address}")
        return True

    def send(self, data: bytes) -> None:
        """Records sent data."""
        if not self.is_open:
             self.log.error("Send called on closed DummyStream")
             raise IOError("Stream is closed")
        self.log.debug(f"Send received data: {data!r}")
        self.sent_data.append(data)

    def readline(self) -> bytes:
        """Simulates no response / timeout by always returning empty bytes."""
        if not self.is_open:
            self.log.error("Readline called on closed DummyStream")
            raise IOError("Stream is closed")
        self.log.debug("Readline returning b'' (simulating timeout/no data)")
        return b''

    def getc(self, size: int, timeout: float = 1.0) -> Optional[bytes]:
        """Simulates timeout for reading specific bytes."""
        if not self.is_open:
            self.log.error("getc called on closed DummyStream")
            return None
        self.log.debug(f"getc called (size={size}, timeout={timeout}), returning None (simulating timeout)")
        return None

    def putc(self, data: bytes, timeout: float = 1.0) -> Optional[int]:
        """Records data intended for putc (similar to send)."""
        if not self.is_open:
            self.log.error("putc called on closed DummyStream")
            return None
        # For testing purposes, just record it like send
        self.log.debug(f"Putc received data: {data!r}")
        self.sent_data.append(data)
        return len(data) # Simulate successful write

    # --- Test Helper Methods --- #

    def get_sent_data(self, decode: bool = True) -> List[Union[str, bytes]]:
        """Returns a list of data chunks sent via send() or putc()."""
        if decode:
            return [d.decode('utf-8', errors='ignore') for d in self.sent_data]
        else:
            return self.sent_data

    def clear_sent_data(self):
        """Clears the history of sent data."""
        self.sent_data.clear()

    # Removed: program_response, program_raw_response, program_getc_bytes
    # Removed: clear_responses, clear_putc_data
    # Removed internal state: responses, getc_buffer, putc_data 