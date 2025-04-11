# Carvera CLI

A command-line tool for managing Carvera CNC machines. Very beta. Much beta!

## Features

- **Firmware Updates:** Upload firmware (`.bin`) files, verify checksums, move to the correct location, and optionally reset the device using the `upload-firmware` command.
- **File Management:**
    - Upload G-code or other files to specified directories or full paths (`upload`).
    - Download files from the device (`download`).
    - List files and directories (`ls`).
    - Get detailed file status (`stat`).
    - Calculate MD5 checksum of remote files (`md5`).
- **Direct Commands:** Execute arbitrary commands directly on the Carvera device (`command`).
- **Configuration:** Download and display (or save) the device's configuration settings (`config`).
- **Device Discovery:** Scan the network (WiFi) or USB ports to find connected Carvera devices (`scan`).
- **Interactive Mode:** Enter an interactive shell for sending multiple commands, with history support (`interactive` or `i`).
- **Connection Control:** Specify connection via WiFi or USB, or use auto-detection (`--wifi`, `--usb`).
- **Flexible Output:** Control logging verbosity (`--verbose`, `--quiet`). Some commands like `stat` and `ls` support `--json`.
- **Timeout Control:** Set timeouts for device operations (`--timeout`).

Note: some commands like `interactive` still need a lot of work.

Send me your feature requests!

## Installation

**(Note:** Until this package is published on PyPI, you can install it directly
from the Git repository or by cloning the repository locally.)

I am a complete Python newb, and so I am using [uv](https://docs.astral.sh/uv/)
for my Python stuff. There are probably ways to make this work with Poetry, pip,
etc, but that is left as an exercise for the reader.

You should be able to do:

```bash
uv tool install git+https://github.com/hagmonk/carvera-cli.git
```

After which you can do:

```bash
uvx carvera-cli
```
## Usage

The tool uses subcommands for different actions. Global options like `--device`, `--wifi`, `--usb`, `--verbose`, `--quiet`, `--skip-info`, `--timeout` should be placed *before* the subcommand.

**Examples:**

### Scanning for Devices

```bash
# Scan for available devices (WiFi and USB)
uvx carvera-cli scan

# Scan only WiFi devices
uvx carvera-cli scan --scan-wifi

# Scan only USB devices
uvx carvera-cli scan --scan-usb

# Set WiFi scan timeout to 5 seconds (default is 3)
uvx carvera-cli scan --scan-timeout 5
```

### Firmware Updates

```bash
# Upload firmware, verify, move, and prompt for manual reset
uvx carvera-cli upload-firmware path/to/firmware.bin

# Upload firmware, verify, move, and automatically send reset command
uvx carvera-cli upload-firmware path/to/firmware.bin --reset

# Specify device address for firmware update
uvx carvera-cli --device 192.168.1.100 upload-firmware path/to/firmware.bin
```

### Uploading Files

```bash
# Upload a G-code file to the default directory (/sd/gcodes)
# The remote name will be the same as the local name (file.nc)
uvx carvera-cli upload path/to/file.nc

# Upload to a specific directory (remote name implicitly file.nc)
uvx carvera-cli upload path/to/file.nc /sd/gcodes/my_projects/

# Upload with a specific remote filename/path
uvx carvera-cli upload path/to/local_file.gcode --remote-path /sd/gcodes/renamed_file.gcode

# Upload and allow overwriting remote file
uvx carvera-cli upload path/to/file.nc --overwrite

# Upload using a specific USB device
uvx carvera-cli --usb --device /dev/ttyACM0 upload path/to/file.nc
```

### Downloading Files

```bash
# Download a file from the device to the current directory (local name will be existing_file.nc)
uvx carvera-cli download /sd/gcodes/existing_file.nc

# Download to a specific local path/filename
uvx carvera-cli download /sd/config.txt --local-path my_config_backup.txt

# Download and overwrite local file if it exists
uvx carvera-cli download /sd/important.gcode --overwrite
```

### Running Commands

```bash
# Execute a simple command
uvx carvera-cli command version

# Execute a command with arguments (quotes may be needed by your shell)
uvx carvera-cli command ls -s /sd/gcodes

# Use --timeout for potentially long-running commands
uvx carvera-cli --timeout 30 command M600
```

### Listing Files (`ls`)

```bash
# List files in the default directory (/sd/gcodes)
uvx carvera-cli ls

# List files in a specific directory
uvx carvera-cli ls /sd/

# List files with JSON output
uvx carvera-cli ls /sd/ --json
```

### Getting File Status (`stat`)

```bash
# Get status information for a file
uvx carvera-cli stat /sd/gcodes/myfile.nc

# Get status information in JSON format
uvx carvera-cli stat /sd/config.txt --json
```

### Calculating MD5 (`md5`)

```bash
# Calculate the MD5 checksum of a remote file
uvx carvera-cli md5 /sd/firmware.bin
```

### Device Configuration

```bash
# Get device configuration and display it
uvx carvera-cli config

# Get config and save to a file
uvx carvera-cli config --output my_carvera_config.txt

# Get config quietly (only errors shown)
uvx carvera-cli -q config 
```

### Interactive Mode

```bash
# Auto-detect device and enter interactive mode
uvx carvera-cli interactive

# Force WiFi and enter interactive mode
uvx carvera-cli --wifi interactive

# Alias 'i' also works
uvx carvera-cli i 
```

## Dependencies

- PySerial: Required for USB connections.
- PyQuickLZ: Required for compressed uploads (which is the default).
- GNUReadline: Recommended for command history in interactive mode on Linux/macOS.

## License

[MIT License](LICENSE)
