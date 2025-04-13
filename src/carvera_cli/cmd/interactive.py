from carvera_cli.device.manager import DeviceManager

import atexit
import logging
import os
import sys

# Get a logger specific to this module
logger = logging.getLogger(__name__)

try:
    import readline
    readline_available = True
except ImportError:
    readline_available = False
    # Use the specific logger
    logger.warning("readline library not found. History functionality will be disabled.")

# Only import platformdirs if readline is available, as it's only used for history
if readline_available:
    try:
        import platformdirs
    except ImportError:
        # Use the specific logger
        logger.warning("platformdirs not found. History functionality will be disabled.")
        readline_available = False # Treat as unavailable if platformdirs is missing

def setup_history():
    """Sets up readline history file in a platform-specific user data directory."""
    if not readline_available:
        print("Note: Readline library not available. Command history disabled.")
        return

    try:
        data_dir = platformdirs.user_data_dir("carvera-cli", "Carvera")
        history_file = os.path.join(data_dir, "history")
    except Exception as e:
        print(f"Warning: Could not determine user data directory: {str(e)}. History disabled.")
        return

    try:
        os.makedirs(data_dir, exist_ok=True)
        # Use the specific logger
        logger.info(f"Ensured history directory exists: {data_dir}")
    except Exception as e:
        print(f"Warning: Could not create history directory: {str(e)}. History disabled.")
        return

    # Check if the history file exists *before* trying to create it
    history_file_existed = os.path.exists(history_file)

    # Ensure the history file exists (needed by read_history_file/write_history_file)
    if not history_file_existed:
        try:
            # Create it if it doesn't exist
            with open(history_file, 'a'):
                pass
            # Use the specific logger
            logger.info(f"Created history file: {history_file}")
        except Exception as e:
            print(f"Warning: Could not create history file: {str(e)}. History disabled.")
            return # Stop if we can't even create the file

    # Only read history if the file existed before this run
    if history_file_existed:
        try:
            readline.read_history_file(history_file)
        except Exception as e: # Catch broad exceptions
            # This might include the Errno 22 if the file is corrupt/empty
            print(f"Warning: Could not read history file '{history_file}': {str(e)}")
            # Don't return here, we can still try to save history

    # Set history length and register saving regardless of whether we read history
    try:
        readline.set_history_length(1000)
    except Exception as e:
        # This might fail on some readline implementations/platforms
        print(f"Note: Could not set history length: {str(e)}")

    try:
        atexit.register(readline.write_history_file, history_file)
    except Exception as e:
        print(f"Warning: Failed to register history saving: {str(e)}")

def interactive_mode(manager: DeviceManager) -> int:
    """
    Run an interactive shell for communicating with the Carvera device

    Args:
        manager: DeviceManager instance connected to a device

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    setup_history()

    # Print welcome message and device info
    print("\nEntering interactive mode. Type 'help' for commands, 'exit' to quit.")
    # Only print device details if info was actually queried (not skipped)
    if manager.device_info:
        print(f"Connected to: {manager.device_info.get('model', 'Unknown')} - {manager.device_info.get('version', 'Unknown')}")
    else:
        print("Connected")

    def print_help():
        """Print help information for interactive mode"""
        print("\nAvailable commands:")
        print("  help     - Show this help information")
        print("  exit     - Exit interactive mode")
        print("  quit     - Same as exit")
        print("  status   - Get device status")
        print("  clear    - Clear the screen")
        print("\nAny other input will be sent as a command to the Carvera device.")
        print("\nCommon device commands:")
        print("  version  - Show device firmware version")
        print("  model    - Show device model information")
        print("  ls -e -s /sd/gcodes/  - List files in directory")
        print("  cat file.nc -e        - Display file contents")
        print("  rm file.nc -e         - Remove file")
        print("  config-get-all -e     - Show all device settings")
        print("\nPress up/down arrows to navigate command history")

    # Command loop
    while True:
        try:
            # Get user input
            cmd_input = input("carvera> ").strip()

            # Skip empty lines
            if not cmd_input:
                continue

            # Handle special commands
            if cmd_input.lower() in ('exit', 'quit'):
                break
            elif cmd_input.lower() == 'help':
                print_help()
                continue
            elif cmd_input.lower() == 'status':
                success, response = manager.execute("?")
                if success:
                    print(f"Device status:\n{response}")
                else:
                     print(f"Error getting status: {response}")
                continue
            elif cmd_input.lower() == 'clear':
                try:
                    os.system('cls' if os.name == 'nt' else 'clear')
                except Exception as e:
                    print(f"Error clearing screen: {str(e)}")
                continue

            # Execute the command on the device using the new manager.execute
            # DeviceManager now handles command classification and waiting internally
            success, response = manager.execute(cmd_input)

            # Show the response
            if success:
                if response:
                    print(response)
                # No extra '(Command sent)' needed as DeviceManager handles 'ok' internally
            else:
                print("Error: Command failed")
                if response:
                    print(f"Response: {response}")

        except KeyboardInterrupt:
            print("\nUse 'exit' or 'quit' to exit interactive mode")
        except EOFError:
            # Handle Ctrl+D
            print("\nExiting interactive mode")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

    print("Interactive mode closed")
    return 0