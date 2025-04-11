from carvera_cli.device.manager import DeviceManager

import atexit
import logging
import os
import readline

def interactive_mode(manager: DeviceManager) -> int:
    """
    Run an interactive shell for communicating with the Carvera device

    Args:
        manager: DeviceManager instance connected to a device

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Try to setup command history
    history_file = os.path.expanduser('~/.carvera_history')

    # Create the history file if it doesn't exist
    if not os.path.exists(history_file):
        try:
            # Touch the file to create it
            with open(history_file, 'a'):
                pass
            logging.info(f"Created history file: {history_file}")
        except Exception as e:
            print(f"Warning: Could not create history file: {str(e)}")

    try:
        readline.read_history_file(history_file)
        # Set history length
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Warning: Could not read history file: {str(e)}")

    # Save history on exit
    try:
        atexit.register(readline.write_history_file, history_file)
    except Exception as e:
        print(f"Note: Error setting up command history: {str(e)}")

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