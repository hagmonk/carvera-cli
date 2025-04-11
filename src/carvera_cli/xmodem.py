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
        # Set default log level to WARNING to suppress INFO messages
        self.log.setLevel(logging.INFO)  # Change to INFO for debugging
        self.mode_set = False
        self.canceled = False
        
        # For debugging
        self.verbose_packets = True  # Enable for debugging

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

    def send(self, stream, md5, retry=16, timeout=5, quiet=False, callback=None):
        '''
        Send a stream via the XMODEM protocol.

            >>> stream = open('/etc/issue', 'rb')
            >>> print(modem.send(stream))
            True

        Returns ``True`` upon successful transmission or ``False`` in case of
        failure or None incase of canceled.

        :param stream: The stream object to send data from.
        :type stream: stream (file, etc.)
        :param retry: The maximum number of times to try to resend a failed
                      packet before failing.
        :type retry: int
        :param timeout: The number of seconds to wait for a response before
                        timing out.
        :type timeout: int
        :param quiet: If True, write transfer information to stderr.
        :type quiet: bool
        :param callback: Reference to a callback function that has the
                         following signature.  This is useful for
                         getting status updates while a xmodem
                         transfer is underway.
                         Expected callback signature:
                         def callback(total_packets, success_count, error_count)
        :type callback: callable
        '''

        # initialize protocol
        try:
            packet_size = dict(
                xmodem=128,
                xmodem8k=8192,
            )[self.mode]
        except KeyError:
            raise ValueError("Invalid mode specified: {self.mode!r}"
                             .format(self=self))

        is_stx = 1 if packet_size > 255 else 0

        self.log.debug('Begin start sequence, packet_size=%d', packet_size)
        error_count = 0
        crc_mode = 0
        cancel = 0
        # Wait for handshake - expect 'C' character requesting CRC mode
        start_time = time.time()
        received_handshake = False
        
        # Continue trying for up to 30 seconds to receive handshake
        while time.time() - start_time < 30:
            char = self.getc(1)
            if char:
                if char == self.NAK:
                    self.log.debug('standard checksum requested (NAK).')
                    crc_mode = 0
                    received_handshake = True
                    break
                elif char == self.CRC:
                    self.log.debug('16-bit CRC requested (CRC).')
                    crc_mode = 1
                    received_handshake = True
                    break
                elif char == self.CAN:
                    if not quiet:
                        print('received CAN', file=sys.stderr)
                    if cancel:
                        self.log.info('Transmission canceled: received 2xCAN '
                                      'at start-sequence')
                        return None
                    else:
                        self.log.debug('cancellation at start sequence.')
                        cancel = 1
                elif char == self.EOT:
                    self.log.info('Transmission canceled: received EOT '
                                  'at start-sequence')
                    return False
                else:
                    char_bytes = bytes([b for b in char]) if char else b''
                    char_desc = ', '.join([f'0x{b:02x}' for b in char_bytes])
                    self.log.error('send error: expected NAK, CRC, EOT or CAN; '
                                   'got %r (bytes: %s)', char, char_desc)
            
            # Wait a bit before trying again
            time.sleep(0.1)
        
        # Check if we received handshake
        if not received_handshake:
            self.log.info('Timed out waiting for handshake (CRC/NAK), aborting')
            self.abort(timeout=timeout)
            return False

        # Calculate total packets for progress callback
        stream_size = 0
        current_pos = stream.tell()
        try:
            stream.seek(0, 2) # Seek to end
            stream_size = stream.tell()
            stream.seek(current_pos) # Return to original position
        except Exception as e:
            self.log.warning(f"Could not determine stream size: {e}")
            total_packets = 0 # Cannot calculate if size unknown
        else:
            if stream_size > 0:
                total_packets = (stream_size + packet_size - 1) // packet_size
                # Add 1 for the initial MD5 packet
                total_packets += 1
            else:
                total_packets = 1 # Just the MD5 packet if stream is empty
        self.log.debug(f"Calculated total packets: {total_packets} (stream size: {stream_size})")

        # send data
        error_count = 0
        success_count = 0
        sequence = 0 # 0 for md5 upload
        md5_sent = False

        while True:
            if self.canceled:
                self.putc(self.CAN)
                self.putc(self.CAN)
                self.putc(self.CAN)
                while self.getc(1, timeout):
                    pass
                self.log.info('Transmission canceled by user.')
                self.canceled = False
                return None

            data = []
            if not md5_sent and sequence == 0:
                data = md5.encode()
                md5_sent = True
                self.log.debug('send: MD5 data type: %s', type(data).__name__)
            else:
                data = stream.read(packet_size)
                if data:
                    self.log.debug('send: File data type: %s, size: %d', type(data).__name__, len(data))
            if not data:
                # end of stream
                self.log.debug('send: at EOF')
                break

            # Create packet header with sequence numbers
            header = self._make_send_header(packet_size, sequence)
            
            # Prepare data packet with size information
            if is_stx == 0:  # 128-byte packets (SOH)
                # Format: [data length byte] + [data padded to packet_size]
                # Ensure data is bytes - for binary transfer
                if isinstance(data, bytes):
                    data_bytes = data
                else:
                    # Only for string data like MD5
                    data_bytes = data.encode('utf-8')
                data = bytes([len(data_bytes) & 0xff]) + data_bytes.ljust(packet_size, self.pad)
            else:  # 1024/8192-byte packets (STX)
                # Format: [data length high byte, data length low byte] + [data padded to packet_size]
                # Ensure data is bytes - for binary transfer
                if isinstance(data, bytes):
                    data_bytes = data
                else:
                    # Only for string data like MD5
                    data_bytes = data.encode('utf-8')
                data = bytes([len(data_bytes) >> 8, len(data_bytes) & 0xff]) + data_bytes.ljust(packet_size, self.pad)
            
            # Calculate checksum or CRC based on mode
            checksum = self._make_send_checksum(crc_mode, data)

            # emit packet
            packet_attempt = 0
            while packet_attempt < retry:
                self.log.debug('send: block %d', sequence)
                self.putc(header + data + checksum)
                char = self.getc(1, timeout)
                if char == self.ACK:
                    success_count += 1
                    if callable(callback):
                        callback(packet_size, total_packets, success_count, error_count)
                    error_count = 0
                    break
                elif char == self.CAN:
                    if cancel:
                        self.log.info('Transmission canceled: received 2xCAN.')
                        return False
                    else:
                        self.log.debug('Cancellation at Transmission.')
                        cancel = 1
                        packet_attempt += 1
                # Special case: Handle NAK (negative acknowledge)
                elif char == self.NAK:
                    self.log.debug('NAK received, retrying block %d', sequence)
                    packet_attempt += 1
                    error_count += 1
                    if callable(callback):
                        callback(packet_size, total_packets, success_count, error_count)
                    continue
                # Special case: Handle CRC request during transmission
                elif char == self.CRC:
                    self.log.debug('CRC requested during transmission for block %d', sequence)
                    packet_attempt += 1
                    continue
                else:
                    # Handle other responses or errors
                    char_bytes = bytes([b for b in char]) if char else b''
                    char_desc = ', '.join([f'0x{b:02x}' for b in char_bytes]) if char else 'None'
                    self.log.info('send error: expected ACK; got %r (%s) for block %d',
                                char, char_desc, sequence)
                    packet_attempt += 1
                    error_count += 1
                    if callable(callback):
                        callback(packet_size, total_packets, success_count, error_count)
                    continue
            
            # Check if we exceeded retry attempts for this packet
            if packet_attempt >= retry:
                self.log.error('send error: retry count exceeded (%d) for block %d, aborting',
                            retry, sequence)
                self.abort(timeout=timeout)
                return False

            # keep track of sequence
            sequence = (sequence + 1) % 0x100

        # End of transmission
        eot_attempt = 0
        while eot_attempt < retry:
            self.log.debug('sending EOT, awaiting ACK (attempt %d)', eot_attempt + 1)
            self.putc(self.EOT)
            
            # Wait for ACK response
            char = self.getc(1, timeout)
            if char == self.ACK:
                return True
            else:
                # Log but continue trying
                char_bytes = bytes([b for b in char]) if char else b''
                char_desc = ', '.join([f'0x{b:02x}' for b in char_bytes]) if char else 'None'
                # Downgrade the severity for the retry loop
                self.log.debug('EOT debug: expected ACK; got %r (%s) on attempt %d', char, char_desc, eot_attempt + 1)
                eot_attempt += 1
                time.sleep(0.5)  # Wait a bit before trying again
        
        # If we get here, EOT failed after retry attempts
        self.log.error('EOT was not acknowledged after %d attempts, aborting transfer', retry)
        self.abort(timeout=timeout)
        return False

    def _make_send_header(self, packet_size, sequence):
        assert packet_size in (128, 8192), packet_size
        _bytes = []
        if packet_size == 128:
            _bytes.append(ord(self.SOH))
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

            >>> stream = open('/etc/issue', 'wb')
            >>> print(modem.recv(stream))
            2342

        Returns the number of bytes received on success or ``None`` in case of
        failure or -1 in case of canceled or 0 in case of md5 equal.

        :param stream: The stream object to write data to.
        :type stream: stream (file, etc.)
        :param crc_mode: XMODEM CRC mode
        :type crc_mode: int
        :param retry: The maximum number of times to try to resend a failed
                      packet before failing.
        :type retry: int
        :param timeout: The number of seconds to wait for a response before
                        timing out.
        :type timeout: int
        :param delay: The number of seconds to wait between resend attempts
        :type delay: int
        :param quiet: If ``True``, write transfer information to stderr.
        :type quiet: bool
        :param callback: Reference to a callback function that has the
                         following signature.  This is useful for
                         getting status updates while a xmodem
                         transfer is underway.
                         Expected callback signature:
                         def callback(success_count, error_count)
        :type callback: callable

        '''

        # For WiFi transfers, we need a longer timeout
        if self.mode == 'xmodem8k':
            timeout = max(timeout, 2.0)  # Use at least 2 seconds for WiFi

        # initiate protocol
        success_count = 0
        error_count = 0
        char = 0
        cancel = 0
        
        # Start the protocol
        while True:
            # first try CRC mode, if this fails,
            # fall back to checksum mode
            if error_count >= retry:
                self.log.info('error_count reached %d, aborting.', retry)
                self.abort(timeout=timeout)
                return None
            elif crc_mode and error_count < (retry // 2):
                if not self.putc(self.CRC):
                    self.log.debug('recv error: putc failed, '
                                'sleeping for %d', delay)
                    time.sleep(0.1)   #time.sleep(delay)
                    error_count += 1
            else:
                crc_mode = 0
                if not self.putc(self.NAK):
                    self.log.debug('recv error: putc failed, '
                                'sleeping for %d', delay)
                    time.sleep(0.1)   #time.sleep(delay)
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
                    self.mode = 'xmodem8k'
                    self.mode_set = True
                self.log.debug('recv: STX')
                break
            elif char == self.CAN:
                if cancel:
                    self.log.info('Transmission canceled: received 2xCAN '
                               'at start-sequence')
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
        packet_size = 128
        try:
            packet_size = dict(
                xmodem=128,
                xmodem8k=8192,
            )[self.mode]
        except KeyError:
            raise ValueError("Invalid mode specified: {self.mode!r}"
                             .format(self=self))
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
                    # We received an EOT, so send an ACK and return the
                    # received data length.
                    self.log.debug("EOT received after %d/%d bytes of expected size",
                                 income_size, stream.tell())
                    self.putc(self.ACK)
                    return income_size
                elif char == self.CAN:
                    # cancel at two consecutive cancels
                    if cancel:
                        self.log.info('Transmission canceled: received 2xCAN '
                                   'at block %d', sequence)
                        return None
                    else:
                        self.log.debug('cancellation at block %d', sequence)
                        cancel = 1
                elif char is None:
                    # no data available
                    error_count += 1
                    if error_count > retry:
                        self.log.error('error_count reached %d, aborting.',
                                     retry)
                        self.abort()
                        return None
                    # get next start-of-header byte
                    # Use a longer timeout here to be more resilient
                    char = self.getc(1, timeout * 2)
                    if char is None:
                        # Try NAK to prompt for retransmission
                        self.putc(self.NAK)
                        char = self.getc(1, timeout * 2)
                    continue
                else:
                    err_msg = ('recv error: expected SOH, EOT; '
                              'got {0!r}'.format(char))
                    if not quiet:
                        print(err_msg, file = sys.stderr)
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
            self.log.debug('recv: data block %d', sequence)
            seq1 = self.getc(1, timeout)
            if seq1 is None:
                self.log.warn('getc failed to get first sequence byte')
                seq2 = None
            else:
                seq1 = ord(seq1) if isinstance(seq1, bytes) or isinstance(seq1, str) else seq1
                seq2 = self.getc(1, timeout)
                if seq2 is None:
                    self.log.warn('getc failed to get second sequence byte')
                else:
                    # second byte is the same as first as 1's complement
                    seq2 = 0xff - (ord(seq2) if isinstance(seq2, bytes) or isinstance(seq2, str) else seq2)

            if not (seq1 == seq2 == sequence):
                # consume data anyway ... even though we will discard it,
                # it is not the sequence we expected!
                self.log.error('expected sequence %d, '
                             'got (seq1=%r, seq2=%r), '
                             'receiving next block, will NAK.',
                             sequence, seq1, seq2)
                data = self.getc(1 + is_stx + packet_size + 1 + crc_mode, timeout)
                if data:
                    self.log.debug('consumed bad data, requesting resend')
            else:
                # sequence is ok, read packet
                # packet_size + checksum
                data = self.getc(1 + is_stx + packet_size + 1 + crc_mode, timeout)
                if data is None:
                    self.log.warn('recv error: data is None')
                    # Recommended to use NAK instead of CAN with Carvera firmware
                    self.putc(self.NAK)
                    char = self.getc(1, timeout)
                    continue
                    
                # Debug: dump packet if verbose_packets mode enabled
                if self.verbose_packets:
                    hex_data = ' '.join(f'{b:02x}' for b in data[:20]) + '...' if len(data) > 20 else ' '.join(f'{b:02x}' for b in data)
                    self.log.debug(f"PACKET[{sequence}] data ({len(data)} bytes): {hex_data}")
                
                # Verify data integrity
                valid = False
                
                if crc_mode:
                    if len(data) < 2 + is_stx + packet_size:
                        self.log.warn('recv error: data too short for CRC')
                        self.putc(self.NAK)
                        char = self.getc(1, timeout)
                        continue
                        
                    # CRITICAL: Calculate CRC exactly like the Carvera firmware does in Player.cpp
                    
                    # Use the Player.cpp algorithm for CRC calculation
                    data_with_length = data[:packet_size+1+is_stx]  # Length byte(s) + actual data
                    calculated_crc = self.calc_crc(data_with_length)
                    
                    # Log detailed CRC calculation data only in verbose mode
                    if self.verbose_packets:
                        hex_data = ' '.join(f'{b:02x}' for b in data_with_length[:20]) + '...' if len(data_with_length) > 20 else ' '.join(f'{b:02x}' for b in data_with_length)
                        self.log.debug(f"CRC calculation input ({len(data_with_length)} bytes): {hex_data}")
                        self.log.debug(f"Calculated CRC: 0x{calculated_crc:04x}")
                    
                    received_crc_hi = data[-2]
                    received_crc_lo = data[-1]
                    
                    if isinstance(received_crc_hi, str):
                        received_crc_hi = ord(received_crc_hi)
                    if isinstance(received_crc_lo, str):
                        received_crc_lo = ord(received_crc_lo)
                        
                    received_crc = (received_crc_hi << 8) + received_crc_lo
                    
                    if self.verbose_packets:
                        self.log.debug(f"Received CRC: 0x{received_crc:04x} ({received_crc_hi:02x} {received_crc_lo:02x})")
                    
                    valid = calculated_crc == received_crc
                    
                    if not valid:
                        self.log.warn('recv error: CRC mismatch (expected 0x%04x, got 0x%04x)',
                                     calculated_crc, received_crc)
                        if self.verbose_packets:
                            hex_data = ' '.join(f'{b:02x}' for b in data_with_length[:20]) + '...' if len(data_with_length) > 20 else ' '.join(f'{b:02x}' for b in data_with_length)
                            self.log.debug(f"CRC calculation data: {hex_data}")
                            
                        self.putc(self.NAK)
                        char = self.getc(1, timeout)
                        continue
                    else:
                        # Valid CRC - remove CRC bytes for further processing
                        data = data[:-2]
                else:
                    if len(data) < 1 + is_stx + packet_size:
                        self.log.warn('recv error: data too short for checksum')
                        self.putc(self.NAK)
                        char = self.getc(1, timeout)
                        continue
                        
                    # Calculate checksum exactly like the Carvera firmware does
                    # The firmware calculates checksum on: length byte(s) + data
                    data_with_length = data[:packet_size+1+is_stx]
                    calculated_checksum = self.calc_checksum(data_with_length)
                    
                    received_checksum = data[-1]
                    
                    if isinstance(received_checksum, str):
                        received_checksum = ord(received_checksum)
                        
                    valid = calculated_checksum == received_checksum
                    
                    if not valid:
                        self.log.warn('recv error: checksum mismatch (expected 0x%02x, got 0x%02x)',
                                     calculated_checksum, received_checksum)
                        # Debug info for checksum issues
                        if self.verbose_packets:
                            hex_data = ' '.join(f'{b:02x}' for b in data_with_length[:20]) + '...' if len(data_with_length) > 20 else ' '.join(f'{b:02x}' for b in data_with_length)
                            self.log.debug(f"Checksum calculation data: {hex_data}")
                            
                        self.putc(self.NAK)
                        char = self.getc(1, timeout)
                        continue
                    else:
                        # Valid checksum - remove checksum byte for further processing
                        data = data[:-1]

                # Valid data, process it
                if valid:
                    # Send ACK *before* writing to stream
                    self.putc(self.ACK)

                    # Handle the first packet (sequence 0) - Log MD5 info but don't write it
                    if not md5_received and sequence == 0:
                        md5_data = data[1 + is_stx : 1 + is_stx + 32]
                        md5_string = md5_data.decode('utf-8', errors='ignore')
                        self.log.debug("First packet (seq 0) received, contains MD5 info")
                        self.log.debug(f"MD5 data in packet 0: {md5_data}")
                        md5_received = True
                        # Skip writing packet 0 data to the stream
                    else:
                        # Write the actual file data (excluding length bytes) for packets > 0
                        actual_data_len = (data[0] << 8 | data[1]) if is_stx else data[0]
                        stream.write(data[1 + is_stx : 1 + is_stx + actual_data_len])
                        income_size += actual_data_len

                    # Keep track of sequence number
                    sequence = (sequence + 1) % 0x100
                    
                    success_count = success_count + 1
                    if callable(callback):
                        callback(packet_size, success_count, error_count)
                    
                    # Expect next packet
                    retrans = retry + 1
                    
                    # Get next byte
                    char = self.getc(1, timeout)
                    continue
                else:
                    # Invalid checksum/CRC
                    self.putc(self.NAK)
                    error_count += 1
                    if error_count > retry:
                        self.log.error('too many invalid packets, aborting')
                        self.abort()
                        return None
            
            # Request retransmission
            self.log.warn('recv error: requesting retransmission (NAK)')
            self.putc(self.NAK)
            
            # Clear input buffer
            while True:
                if self.getc(1, timeout) is None:
                    break
                    
            # Reset counter for next block
            error_count = 0
            
            # Get next packet
            char = self.getc(1, timeout)

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