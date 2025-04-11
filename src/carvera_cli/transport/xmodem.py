"""
XMODEM Protocol Implementation

A simple implementation of the XMODEM file transfer protocol with CRC support.
"""

import time
import sys
import logging
import platform

class XMODEM:
    """
    XMODEM Protocol handler, expects two callables which encapsulate the read
    and write operations on the underlying stream.

    Example functions for reading and writing to a serial line:

    >>> import serial
    >>> ser = serial.Serial('/dev/ttyUSB0', timeout=0.5)
    >>> def getc(size, timeout=0.5):
    ...     return ser.read(size) or None
    ...
    >>> def putc(data, timeout=0.5):
    ...     return ser.write(data) or None
    ...
    >>> modem = XMODEM(getc, putc)

    :param getc: Function to retrieve bytes from a stream. The function takes
        the number of bytes to read from the stream and a timeout in seconds as
        parameters. It must return the bytes which were read, or ``None`` if a
        timeout occured.
    :type getc: callable
    :param putc: Function to transmit bytes to a stream. The function takes the
        bytes to be written and a timeout in seconds as parameters. It must
        return the number of bytes written to the stream, or ``None`` in case of
        a timeout.
    :type putc: callable
    :param mode: XMODEM protocol mode
    :type mode: string
    :param pad: Padding character to make the packets match the packet size
    :type pad: char
    """

    # Protocol bytes for XModem
    SOH = b'\x01'  # Start of header (128 byte blocks)
    STX = b'\x02'  # Start of header (1024 byte blocks)
    EOT = b'\x04'  # End of transmission
    ACK = b'\x06'  # Acknowledge
    DLE = b'\x10'  # Data link escape
    NAK = b'\x15'  # Negative acknowledge
    CAN = b'\x16'  # Cancel
    CRC = b'C'     # 'C' character for CRC mode request

    # crctab calculated by Mark G. Mendel, Network Systems Corporation
    crctable = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
    ]

    def __init__(self, getc, putc, mode='xmodem8k', pad=b'\x1a'):
        self.getc = getc
        self.putc = putc
        self.mode = mode
        self.pad = pad
        self.log = logging.getLogger('xmodem')
        self.mode_set = False
        self.canceled = False
        
        # Verify valid mode at initialization
        if mode not in ['xmodem', 'xmodem1k', 'xmodem8k']:
            self.log.warning(f"Initializing with potentially unsupported mode: {mode}")
        
        # For debugging
        self.verbose_packets = True  # Enable for debugging
        self.received_remote_md5 = None # Add attribute to store received MD5

    def clear_mode_set(self):
        self.mode_set = False

    def abort(self, count=2, timeout=60):
        '''
        Send an abort sequence using CAN bytes.

        :param count: how many abort characters to send
        :type count: int
        :param timeout: timeout in seconds
        :type timeout: int
        '''
        for _ in range(count):
            self.putc(self.CAN, timeout)

    def send(self, stream, md5, crc_mode, retry=16, timeout=5, quiet=False, callback=None):
        """
        Send a stream via the XMODEM protocol, implementing the specific behavior
        expected by the Carvera firmware (based on carveracontroller/XMODEM.py):
        - Sequence starts at 0.
        - Block 0 contains the MD5 hash.
        - Data packets are prefixed with actual length bytes before padding.
        
        Assumes the initial handshake (waiting for NAK/CRC) has already been performed 
        by the caller and crc_mode is correctly determined.

        :param stream: The stream object to send data from.
        :param md5: The MD5 hash of the original file (sent in block 0).
        :param crc_mode: 0 for checksum, 1 for CRC-16.
        :param retry: Max retries for packet transmission.
        :param timeout: Timeout for I/O operations.
        :param quiet: If True, suppress progress messages.
        :param callback: Callback function for progress updates.

        Returns ``True`` upon successful transmission or ``False`` in case of
        failure or None in case of cancellation.
        """

        # initialize protocol
        try:
            packet_size = dict(
                xmodem=128,
                xmodem1k=1024,
                xmodem8k=8192,
            )[self.mode]
        except KeyError:
            raise ValueError("Invalid mode specified: {self.mode!r}"
                             .format(self=self))

        # Determine if STX (1k/8k) or SOH (128) is used based on packet size
        # This affects the number of length bytes prepended to data
        is_stx = 1 if packet_size > 255 else 0

        self.log.debug(f"Starting XMODEM send, mode={self.mode}, packet_size={packet_size}, crc_mode={crc_mode}")
        error_count = 0
        success_count = 0
        total_packets = 0 # Tracks file data packets, not the initial MD5 packet
        sequence = 0      # Sequence starts at 0 for the MD5 packet
        md5_sent = False
        cancel = 0

        while True:
            if self.canceled:
                self.log.info('Transmission canceled by user.')
                self.abort(timeout=timeout)
                self.canceled = False
                return None

            # --- Prepare data for the current packet --- 
            data = b''
            if not md5_sent and sequence == 0:
                # Block 0: Send the MD5 hash
                data = md5.encode() # MD5 hash is expected as bytes
                md5_sent = True
                self.log.debug(f"Preparing packet 0 (MD5): {md5}")
            else:
                # Subsequent blocks: Read file data
                data = stream.read(packet_size) 
                if not data:
                    # End of stream reached
                    self.log.debug('Send: EOF reached after packet %d.', sequence - 1)
                    break
                total_packets += 1 # Only count actual file data packets
                self.log.debug(f"Preparing packet {sequence} (File Data, size: {len(data)})")

            # --- Construct the packet --- 
            header = self._make_send_header(packet_size, sequence)
            
            # Prepend actual data length bytes (non-standard firmware expectation)
            data_len = len(data)
            if is_stx == 0: # 128-byte packets (SOH)
                # Prepend 1 byte for length
                padded_data = bytes([data_len & 0xff]) + data.ljust(packet_size, self.pad)
            else: # 1024/8192-byte packets (STX)
                # Prepend 2 bytes for length (big-endian)
                padded_data = bytes([data_len >> 8, data_len & 0xff]) + data.ljust(packet_size, self.pad)
                
            # Calculate checksum/CRC on the *length-prefixed and padded* data
            checksum = self._make_send_checksum(crc_mode, padded_data)

            # --- Transmit the packet and handle response --- 
            packet_error_count = 0
            while True:
                self.log.debug('Sending block %d', sequence)
                # Send header + length-prefixed/padded data + checksum
                self.putc(header + padded_data + checksum, timeout=timeout)
                char = self.getc(1, timeout)

                if char == self.ACK:
                    self.log.debug('Block %d ACKed', sequence)
                    success_count += 1
                    if callable(callback):
                        # Pass total_packets (file data only) for progress
                        callback(packet_size, total_packets, success_count, error_count + packet_error_count)
                    break # Packet sent successfully
                elif char == self.NAK:
                    self.log.warning('NAK received for block %d, will retry packet.', sequence)
                    packet_error_count += 1
                elif char == self.CAN:
                    if cancel:
                        self.log.info('Transmission canceled: received 2xCAN during block %d.', sequence)
                        self.canceled = False
                        return None
                    else:
                        self.log.debug('Cancellation request received during block %d.', sequence)
                        cancel = 1
                        packet_error_count += 1
                elif char is None:
                    self.log.warning('Timeout waiting for ACK/NAK for block %d.', sequence)
                    packet_error_count += 1
                else:
                    # Unexpected character
                    self.log.error('Send error: expected ACK, NAK, or CAN; got %r for block %d',
                                   char, sequence)
                    packet_error_count += 1

                # Check retry limit for this packet
                if packet_error_count > retry:
                    self.log.error('Send error: Block %d failed after %d retries, aborting.',
                                   sequence, retry)
                    self.abort(timeout=timeout)
                    return False

                # Update overall error count for callback during retries
                if callable(callback):
                   callback(packet_size, total_packets, success_count, error_count + packet_error_count)
                time.sleep(1) # Wait before retrying the packet

            # Increment sequence number for the next packet
            sequence = (sequence + 1) % 256 # Sequence wraps at 256

        # --- End of Transmission --- 
        self.log.debug("End of file reached, sending EOT.")
        eot_retry_count = 0
        while True:
            self.putc(self.EOT, timeout=timeout)
            eot_retry_count += 1
            char = self.getc(1, timeout)

            if char == self.ACK:
                self.log.info('Transmission successful (EOT ACKed).')
                return True

            self.log.warning('EOT not ACKed, received %r. Retrying EOT (%d/%d)...', char, eot_retry_count, retry)
            if eot_retry_count > retry:
                self.log.error('EOT not acknowledged after %d retries, aborting transfer.', retry)
                self.abort(timeout=timeout)
                return False
            time.sleep(1)

    def _make_send_header(self, packet_size, sequence):
        assert packet_size in (128, 1024, 8192), packet_size
        _bytes = []
        if packet_size == 128:
            _bytes.append(ord(self.SOH))
        elif packet_size == 1024:
            _bytes.append(ord(self.STX))
        elif packet_size == 8192:
            _bytes.append(ord(self.STX))
        _bytes.extend([sequence, 0xff - sequence])
        return bytearray(_bytes)

    def _make_send_checksum(self, crc_mode, data):
        _bytes = []
        if crc_mode:
            crc = self.calc_crc(data)
            _bytes.extend([crc >> 8, crc & 0xff])
        else:
            crc = self.calc_checksum(data)
            _bytes.append(crc)
        return bytearray(_bytes)

    def recv(self, stream, md5='', crc_mode=1, retry=16, timeout=1, delay=0.1, quiet=0, callback=None):
        '''
        Receive a stream via the XMODEM protocol.
        Returns the number of bytes received on success or ``None`` in case of
        failure or -1 in case of canceled or 0 in case of md5 equal.
        '''

        # initiate protocol
        success_count = 0
        error_count = 0
        char = 0
        cancel = 0
        
        # First try CRC mode, if this fails, fall back to checksum mode
        while True:
            if error_count >= retry:
                self.log.info('error_count reached %d, aborting.', retry)
                self.abort(timeout=timeout)
                return None
            elif crc_mode and error_count < (retry // 2):
                if not self.putc(self.CRC):
                    self.log.debug('recv error: putc failed, sleeping for %d', delay)
                    time.sleep(0.1)  # time.sleep(delay)
                    error_count += 1
            else:
                crc_mode = 0
                if not self.putc(self.NAK):
                    self.log.debug('recv error: putc failed, sleeping for %d', delay)
                    time.sleep(0.1)  # time.sleep(delay)
                    error_count += 1

            char = self.getc(1, timeout)
            if char is None:
                self.log.warn('recv error: getc timeout in start sequence')
                error_count += 1
                continue
            elif char == self.SOH:
                if not self.mode_set:
                    self.mode = 'xmodem'
                    self.mode_set = True
                self.log.debug('recv: SOH')
                break
            elif char == self.STX:
                if not self.mode_set:
                    self.mode = 'xmodem1k' if self.mode == 'xmodem1k' else 'xmodem8k'
                    self.mode_set = True
                self.log.debug('recv: STX')
                break
            elif char == self.CAN:
                if cancel:
                    self.log.info('Transmission canceled: received 2xCAN at start-sequence')
                    return None
                else:
                    self.log.debug('cancellation at start sequence.')
                    cancel = 1
            else:
                error_count += 1

        # read data
        error_count = 0
        income_size = 0
        
        # initialize protocol
        try:
            packet_size = dict(
                xmodem=128,
                xmodem1k=1024,
                xmodem8k=8192,
            )[self.mode]
        except KeyError:
            raise ValueError(f"Invalid mode specified: {self.mode!r}")
            
        is_stx = 1 if packet_size > 255 else 0

        sequence = 0
        cancel = 0
        retrans = retry + 1
        md5_received = False

        while True:
            if self.canceled:
                self.putc(self.CAN)
                self.putc(self.CAN)
                self.putc(self.CAN)
                while self.getc(1, timeout):
                    pass
                self.log.info('Transmission canceled by user.')
                self.canceled = False
                return -1
                
            while True:
                if char == self.SOH or char == self.STX:
                    break
                elif char == self.EOT:
                    # We received an EOT, so send an ACK and return the received data length
                    self.putc(self.ACK)
                    self.log.info(f"Transmission complete, {income_size} bytes")
                    return income_size
                elif char == self.CAN:
                    # cancel at two consecutive cancels
                    if cancel:
                        self.log.info(f'Transmission canceled: received 2xCAN at block {sequence}')
                        return None
                    else:
                        self.log.debug(f'cancellation at block {sequence}')
                        cancel = 1
                elif char is None:
                    # no data available
                    error_count += 1
                    if error_count > retry:
                        self.log.error(f'error_count reached {retry}, aborting.')
                        self.abort()
                        return None
                    # get next start-of-header byte
                    char = self.getc(1, 0.5)  # char = self.getc(1, timeout)
                    continue
                else:
                    err_msg = f'recv error: expected SOH, EOT; got {char!r}'
                    if not quiet:
                        print(err_msg, file=sys.stderr)
                    self.log.warn(err_msg)
                    error_count += 1
                    if error_count > retry:
                        self.abort()
                        return None
                    else:
                        while True:
                            if self.getc(1, timeout) is None:
                                break
                        self.putc(self.NAK)
                        char = self.getc(1, timeout)
                    continue

            # read sequence
            error_count = 0
            cancel = 0
            self.log.debug(f'recv: data block {sequence}')
            seq1 = self.getc(1, timeout)
            if seq1 is None:
                self.log.warn('getc failed to get first sequence byte')
                seq2 = None
            else:
                seq1 = ord(seq1)
                seq2 = self.getc(1, timeout)
                if seq2 is None:
                    self.log.warn('getc failed to get second sequence byte')
                else:
                    # second byte is the same as first as 1's complement
                    seq2 = 0xff - ord(seq2)

            if not (seq1 == seq2 == sequence):
                # consume data anyway ... even though we will discard it,
                # it is not the sequence we expected!
                self.log.error(f'expected sequence {sequence}, '
                               f'got (seq1={seq1!r}, seq2={seq2!r}), '
                               'receiving next block, will NAK.')
                self.getc(packet_size + 1 + crc_mode)  # Also consume checksum
                self.putc(self.NAK)
                # Get next start-of-header byte
                char = self.getc(1, timeout)
                continue
                
            else:
                # sequence is ok, read packet
                # packet_size + checksum
                data = self.getc(1 + is_stx + packet_size + 1 + crc_mode, timeout)
                if data is None:
                    self.log.warn('recv error: We got a data as None')
                    valid = None
                    self.putc(self.NAK)
                    char = self.getc(1, timeout)
                    continue
                else:
                    # Verify checksum/CRC
                    if crc_mode:
                        _checksum = bytearray(data[-2:])
                        their_sum = (_checksum[0] << 8) + _checksum[1]
                        data = data[:-2]
                        
                        our_sum = self.calc_crc(data)
                        valid = their_sum == our_sum
                        if not valid:
                            self.log.warn(f'recv error: CRC fail (theirs={their_sum:04x}, ours={our_sum:04x})')
                    else:
                        _checksum = bytearray([data[-1]])
                        their_sum = _checksum[0]
                        data = data[:-1]
                        
                        our_sum = self.calc_checksum(data)
                        valid = their_sum == our_sum
                        if not valid:
                            self.log.warn(f'recv error: checksum fail (theirs={their_sum:02x}, ours={our_sum:02x})')
                    
                    if not valid:
                        self.putc(self.NAK)
                        char = self.getc(1, timeout)
                        continue

                # valid data, append chunk
                if valid:
                    retrans = retry + 1
                    if sequence == 0 and not md5_received:
                        md5_received = True
                        if md5.encode() == data[1 + is_stx : 33 + is_stx]:
                            self.putc(self.CAN)
                            self.putc(self.CAN)
                            self.putc(self.CAN)
                            while self.getc(1, timeout):
                                pass
                            return 0
                    else:
                        # Extract data length and actual data
                        if is_stx:  # 1024 or 8192 byte packets
                            data_len = (data[0] << 8) | data[1]
                            actual_data = data[2:(data_len + 2)]
                        else:  # 128 byte packets
                            data_len = data[0]
                            actual_data = data[1:(data_len + 1)]
                            
                        # Write data to stream
                        stream.write(actual_data)
                        income_size += len(actual_data)
                        success_count = success_count + 1
                        
                        if callable(callback):
                            callback(packet_size, success_count, error_count)
                            
                    self.putc(self.ACK)
                    sequence = (sequence + 1) % 0x100
                    # get next start-of-header byte
                    char = self.getc(1, timeout)
                    continue

    def calc_checksum(self, data, checksum=0):
        '''
        Calculate the checksum for a given block of data, can also be used to
        update a checksum.

            >>> csum = modem.calc_checksum('hello')
            >>> csum = modem.calc_checksum('world', csum)
            >>> hex(csum)
            '0x3c'

        '''
        if platform.python_version_tuple() >= ('3', '0', '0'):
            return (sum(data) + checksum) % 256
        else:
            return (sum(map(ord, data)) + checksum) % 256

    def calc_crc(self, data, crc=0):
        '''
        Calculate the Cyclic Redundancy Check for a given block of data, can
        also be used to update a CRC.

            >>> crc = modem.calc_crc('hello')
            >>> crc = modem.calc_crc('world', crc)
            >>> hex(crc)
            '0x4ab3'

        '''
        # Implement crc16_ccitt exactly as it appears in Player.cpp
        crc_table = [
            0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
            0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
            0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
            0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
            0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
            0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
            0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
            0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
            0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
            0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
            0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
            0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
            0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
            0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
            0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
            0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
            0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
            0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
            0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
            0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
            0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
            0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
            0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
            0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
            0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
            0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
            0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
            0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
            0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
            0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
            0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
            0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
        ]
        
        # Following the exact implementation in Player.cpp (crc16_ccitt function)
        crc = 0  # Always start with 0 as per Player.cpp
        for byte in bytearray(data):
            tmp = ((crc >> 8) ^ byte) & 0xff
            crc = ((crc << 8) ^ crc_table[tmp]) & 0xffff
        
        return crc & 0xffff 