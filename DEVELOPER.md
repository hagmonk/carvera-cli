# Carvera Controller/Firmware Protocol Idiosyncrasies (Discovered)

This document details specific, sometimes non-standard, behaviors observed in
the communication between `carvera-cli` and the Carvera firmware, based on
analysis of the original `Carvera Controller` source (`Controller.py`,
`main.py`) and the firmware code (`Player.cpp`), as well as direct testing.

## Command Formatting & `-e` Flag

- The `-e` flag is unreliable, it does not always result in the EOT byte
  (`0x04`) being output. Even if it did, commands like `ls`, `rm`, `mv`,
  `mkdir`, `wlan`, `config-get-all` all have different places where they want
  it.

- The convention is to upload files with spaces converted into `0x01`. However,
  `md5sum`, `load`, and `save` are bugged and expect instead a string
  **without** spaces substituted.

- Commands are completely inconsistent in how they signal that they're done.
  It's a complete free-for-all and I expect many bugs to be the result of this.

- As a result of all this, sending raw commands via `command` can be a bit hit
  and miss depending on the command.

## File transfer

- Files need to be lz compressed. Except firmware files.

- The command for upload is `upload <remote_path>`, where `<remote_path>` is the
  *final intended path* on the device (e.g., `/sd/gcodes/myfile.cnc`), even if
  compression is used.

- Before any file data, the *first XMODEM packet* (packet 0) contains the
  32-byte hexadecimal MD5 hash of the *original, uncompressed* file. This is
  non-standard XMODEM.

- The firmware (`Player.cpp::upload_command`) only calls its internal
  `decompress` function if the `<remote_path>` provided in the `upload` command
  string ends with `.lz`. 

