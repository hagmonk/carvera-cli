"""
Stream Classes for Communication

Provides base Stream class and implementations (USB, WiFi) for
communicating with Carvera CNC devices.
"""

from typing import Protocol, Optional, runtime_checkable

@runtime_checkable
class Stream(Protocol):
    """Protocol defining the interface for communication streams (USB, WiFi)."""

    def open(self, address: str) -> bool:
        """Opens the stream connection."""
        ...

    def close(self) -> bool:
        """Closes the stream connection."""
        ...

    def send(self, data: bytes) -> None:
        """Sends data over the stream."""
        ...

    def readline(self) -> bytes:
        """Reads a line (up to newline character) from the stream."""
        ...

    # Methods primarily for XMODEM
    def getc(self, size: int, timeout: float = 1.0) -> Optional[bytes]:
        """Reads exactly size bytes, with a timeout."""
        ...

    def putc(self, data: bytes, timeout: float = 1.0) -> Optional[int]:
        """Writes data, with a timeout (primarily for XMODEM)."""
        ...


