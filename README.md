# Carvera CLI

A command-line tool for managing Carvera CNC machines.

## Features

- **Firmware Updates:** Upload firmware (`.bin`) files, verify checksums, move to the correct location, and optionally reset the device.
- **File Uploads:** Upload G-code or other files to specified directories or full paths on the device.
- **File Downloads:** Download files from the device to your local machine.
- **Direct Commands:** Execute arbitrary commands directly on the Carvera device.
- **Configuration:** Download and display (or save) the device's configuration settings.
- **Device Discovery:** Scan the network (WiFi) or USB ports to find connected Carvera devices.
- **Interactive Mode:** Enter an interactive shell for sending multiple commands, with history support.
- **Connection Control:** Specify connection via WiFi or USB, or use auto-detection.
- **Flexible Output:** Control logging verbosity (`--verbose`, `--quiet`).
- **Timeout Control:** Set timeouts for device operations.

## Installation

**(Note:** Until this package is published on PyPI, you can install it directly from the Git repository or by cloning the repository locally.)

### From Git Repository (Recommended)

This method installs the package directly from GitHub.

```bash
# Using uv
uv pip install git+https://github.com/hagmonk/carvera-cli.git

# Using standard pip
pip install git+https://github.com/hagmonk/carvera-cli.git
```

### From Local Clone

If you have cloned the `carvera-cli` repository locally:

```bash
# Navigate to the root directory of your cloned repository
cd /path/to/your/clone/carvera-cli

# Install using uv (recommended)
uv pip install .

# Or install in editable mode (for development)
uv pip install -e .

# Install using standard pip
pip install .

# Or install in editable mode with pip
pip install -e .
```

## Usage

The tool uses subcommands for different actions. Global options like `--device`, `--wifi`, `--usb`, `--verbose`, `--quiet`, `--skip-info`, `--timeout` should be placed *before* the subcommand.

**Examples:**

### Scanning for Devices

```bash
# Scan for available devices (WiFi and USB)
uv run carvera-cli scan
```

### Firmware Updates

```bash
# Upload firmware, verify, move, and prompt for manual reset
uv run carvera-cli firmware path/to/firmware.bin

# Upload firmware, verify, move, and automatically send reset command
uv run carvera-cli firmware path/to/firmware.bin --reset

# Specify device address for firmware update
uv run carvera-cli --device 192.168.1.100 firmware path/to/firmware.bin
```

### Uploading Files

```bash
# Upload a G-code file to the default directory (/sd/gcodes)
uv run carvera-cli upload path/to/file.nc

# Upload to a specific directory
uv run carvera-cli upload path/to/file.nc --target-dir /sd/gcodes/my_projects

# Upload with a specific remote filename/path
uv run carvera-cli upload path/to/local_file.gcode --remote-path /sd/gcodes/renamed_file.gcode

# Upload and allow overwriting (if firmware supports it)
uv run carvera-cli upload path/to/file.nc --overwrite

# Upload using a specific USB device
uv run carvera-cli --usb --device /dev/ttyACM0 upload path/to/file.nc
```

### Downloading Files

```bash
# Download a file from the device to the current directory
uv run carvera-cli download /sd/gcodes/existing_file.nc

# Download to a specific local path
uv run carvera-cli download /sd/config.txt --local-path my_config_backup.txt
```

### Running Commands

```bash
# Execute a command and wait for "ok"
uv run carvera-cli command "ls -s /sd/gcodes"

uv run carvera-cli command "version"

# Send command without waiting for "ok" (useful for commands like 'reset')
uv run carvera-cli command "reset" --no-wait
```

### Device Configuration

```bash
# Get device configuration and display it
uv run carvera-cli config

# Get config and save to a file
uv run carvera-cli config --output my_carvera_config.txt

# Get config quietly (only errors shown)
uv run carvera-cli -q config 
```

### Interactive Mode

```bash
# Auto-detect device and enter interactive mode
uv run carvera-cli interactive

# Force WiFi and enter interactive mode 
uv run carvera-cli --wifi interactive

# Alias 'i' also works
uv run carvera-cli i 
```

## Dependencies

- PySerial: Required for USB connections.
- PyQuickLZ: (Currently optional, compression feature not fully implemented).
- GNUReadline: Recommended for command history in interactive mode on Linux/macOS.

## License

[MIT License](LICENSE)
