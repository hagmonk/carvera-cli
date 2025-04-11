import logging
from pathlib import Path
from typing import Optional
from carvera_cli.device.manager import DeviceManager

def config_get_all(manager: DeviceManager, timeout: float, output: Optional[Path]) -> None:
    """
    Retrieves and displays the full device configuration.
    
    Uses the -e flag to get all configuration at once with EOT termination.
    A follow-up echo command is sent to ensure EOT delivery.
    """
    log = logging.getLogger("Config")
    log.debug("Retrieving device configuration...")
    log.debug("Sending config-get-all -e command")
    success, response = manager.execute("config-get-all -e", timeout=timeout)

    if not success:
        log.error(f"Failed to retrieve configuration. Error: {response}")
        return 1
    
    log.debug(f"Configuration retrieved successfully, response length: {len(response)} chars")

    # Parse the response string into a dictionary
    config_dict = {}
    if response:
        lines = response.strip().split('\n')
        for line in lines:
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key:
                    config_dict[key] = value
    
    # Format and print/save the dictionary
    grouped_config = {}
    if config_dict:
        for key in sorted(config_dict.keys()):
            prefix = key.split('.')[0] if '.' in key else 'general'
            if prefix not in grouped_config:
                grouped_config[prefix] = []
            grouped_config[prefix].append(key)
        
        config_lines = []
        max_key_len = max((len(key) for key in config_dict.keys()), default=0)
        
        for prefix in sorted(grouped_config.keys()):
            config_lines.append(f"\n[{prefix}]") # Add newline before group
            for key in sorted(grouped_config[prefix]):
                value = config_dict[key]
                config_lines.append(f"  {key.ljust(max_key_len + 2)}: {value}")
            
        config_output = "\n".join(config_lines)
        total_items_info = f"Total: {len(config_dict)} configuration items in {len(grouped_config)} groups"
    else:
        config_output = "(No configuration items received or failed to parse)"
        total_items_info = ""

    print("\nDevice Configuration:")
    print("-" * 50)
    print(config_output)
    print("-" * 50)
    print(total_items_info)
    
    if output:
        try:
            with open(output, 'w') as f:
                f.write(config_output.strip()) 
                f.write(f"\n\n# {total_items_info}\n")
            log.info(f"Configuration saved to: {output}")
        except Exception as e:
            log.error(f"Error saving configuration: {str(e)}")
    
    return 0
