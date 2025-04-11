import unittest
import logging
from unittest.mock import patch # Import patch

# Configure logging for tests (optional, helps debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') # Changed level to INFO for less noise

# Relative imports for sibling modules
from ..streams.dummy import DummyStream
from .manager import DeviceManager, CMD_DELIMITER

class TestDeviceManagerCommands(unittest.TestCase):

    def setUp(self):
        """Set up a DummyStream and DeviceManager for each test."""
        self.dummy_stream = DummyStream(address="test_dummy")
        self.dummy_stream.open()
        # Initialize DeviceManager, skipping info query and enabling verbose logs if needed
        self.dm = DeviceManager(self.dummy_stream, address="test_dummy", verbose=False)
        self.dummy_stream.clear_sent_data()

    def tearDown(self):
        """Clean up by closing the stream."""
        if self.dummy_stream:
            self.dummy_stream.close()

    def test_gcode_command_G0(self):
        """Test sending G0 X10 Y20. Mocks readline to return 'ok' immediately."""
        # G-code waits for 'ok', typically no payload for G0
        mock_responses = [b"ok\n"]

        with patch.object(self.dm.stream, 'readline', side_effect=mock_responses) as mock_readline:
            # Execute command with args
            success, response = self.dm.G0("X10", "Y20")

        self.assertTrue(success, "G0 command should succeed with mocked 'ok'")
        # G0 usually returns no payload, just 'ok' which is consumed
        self.assertEqual(response, "", "Response should be empty for G0")

        # Verify sent data (as bytes)
        sent = self.dummy_stream.get_sent_data(decode=False)
        self.assertEqual(len(sent), 1, "Should send exactly one command chunk for G-code")
        self.assertEqual(sent[0], b"G0 X10 Y20\n", "Sent command bytes should be correct")
        mock_readline.assert_called() # Verify readline was called

    def test_gcode_command_multiple_codes(self):
        """Test sending G90 G0 X10 Y20. Mocks readline to return 'ok' immediately."""
        mock_responses = [b"ok\n"]

        # Use __getattr__ for the base command (G90), pass others as args
        with patch.object(self.dm.stream, 'readline', side_effect=mock_responses) as mock_readline:
             # The dispatcher joins the command name and args
            success, response = self.dm.G90("G0", "X10", "Y20")

        self.assertTrue(success, "G90 G0 command should succeed with mocked 'ok'")
        self.assertEqual(response, "", "Response should be empty")

        # Verify sent data (as bytes)
        sent = self.dummy_stream.get_sent_data(decode=False)
        self.assertEqual(len(sent), 1, "Should send exactly one command chunk")
        self.assertEqual(sent[0], b"G90 G0 X10 Y20\n", "Sent command bytes should be correct")
        mock_readline.assert_called()

    def test_simpleshell_command_mem(self):
        """Test sending 'mem'. Mocks readline to return delimiter echo immediately."""
        mock_responses = [
            b"Memory: Used=100 Free=200\n",              # Example payload
            f"echo: {CMD_DELIMITER}\n".encode('utf-8') # Terminator
        ]

        with patch.object(self.dm.stream, 'readline', side_effect=mock_responses) as mock_readline:
            success, response = self.dm.mem()

        self.assertTrue(success, "Command should succeed with mocked delimiter echo")
        self.assertEqual(response, "Memory: Used=100 Free=200", "Response should contain payload before delimiter")

        # Verify sent data (as bytes)
        sent = self.dummy_stream.get_sent_data(decode=False)
        self.assertEqual(len(sent), 2, "Should send command and delimiter for SimpleShell")
        self.assertEqual(sent[0], b"mem\n", "Sent command bytes should be correct")
        self.assertEqual(sent[1], f"echo {CMD_DELIMITER}\n".encode('utf-8'), "Sent delimiter bytes should be correct")
        mock_readline.assert_called()

    def test_simpleshell_command_with_args_ls(self):
        """Test sending 'ls /sd/gcodes -l'. Mocks readline for delimiter echo."""
        target_dir = "/sd/gcodes"
        mock_responses = [
            b"file1.gcode\n",
            b"file2.cnc\n",
            f"echo: {CMD_DELIMITER}\n".encode('utf-8')
        ]

        with patch.object(self.dm.stream, 'readline', side_effect=mock_responses) as mock_readline:
            success, response = self.dm.ls(target_dir, "-l")

        self.assertTrue(success, "Command should succeed with mocked delimiter echo")
        self.assertEqual(response, "file1.gcode\nfile2.cnc", "Response should contain payload before delimiter")

        # Verify sent data (as bytes)
        sent = self.dummy_stream.get_sent_data(decode=False)
        self.assertEqual(len(sent), 2, "Should send command and delimiter")
        expected_sent_cmd = f"ls {target_dir} -l\n".encode('utf-8')
        self.assertEqual(sent[0], expected_sent_cmd, "Sent command bytes should include args")
        self.assertEqual(sent[1], f"echo {CMD_DELIMITER}\n".encode('utf-8'), "Sent delimiter bytes should be correct")
        mock_readline.assert_called()

    # TODO: Add test for GRBL command (e.g., $$)
    # TODO: Add test for command failure (e.g., mock readline to return error response)

if __name__ == '__main__':
    unittest.main() 