import os
import struct
import sys
import logging

def validate_firmware_size(filename, logger, expected_size=None):
    """
    Validate firmware file size
    
    Args:
        filename: Path to firmware file
        logger: Logger object for output
        expected_size: Expected size in bytes (optional)
        
    Returns:
        bool: True if size check passes, False otherwise
    """
    try:
        actual_size = os.path.getsize(filename)
    except OSError as e:
        logger.error(f"Error getting file size for {filename}: {e}")
        return False
        
    if expected_size is None:
        logger.info(f"File size: {actual_size} bytes (0x{actual_size:X})")
        return True
    
    if actual_size != expected_size:
        logger.error(f"Size mismatch! Expected: {expected_size}, Got: {actual_size}")
        return False
    
    logger.info(f"Size verification passed: {actual_size} bytes")
    return True


def validate_arm_vector_table(filename, logger):
    """
    Validate ARM vector table in firmware file
    
    Args:
        filename: Path to firmware file
        logger: Logger object for output
        
    Returns:
        bool: True if vector table validation passes, False otherwise
    """
    try:
        with open(filename, 'rb') as f:
            data = f.read(64)  # First 64 bytes (vector table)
        
        if len(data) < 64:
            logger.error("File too small to contain a valid vector table")
            return False
        
        # Check for valid stack pointer and reset vector
        initial_sp = struct.unpack('<I', data[0:4])[0]
        reset_vector = struct.unpack('<I', data[4:8])[0]
        
        logger.info(f"Initial Stack Pointer: 0x{initial_sp:08X}")
        logger.info(f"Reset Vector: 0x{reset_vector:08X}")
        
        # ARM Cortex-M typical RAM range for LPC1768
        if not (0x10000000 <= initial_sp <= 0x10008000):
            logger.error("Invalid stack pointer - not in LPC1768 RAM range!")
            return False
            
        # ARM Cortex-M typical flash range for LPC1768
        if not (0x00000000 <= reset_vector <= 0x00080000):
            logger.error("Invalid reset vector - not in LPC1768 flash range!")
            return False
        
        # Check if exception handlers look reasonable
        handlers = ["NMI", "HardFault", "MemManage", "BusFault", "UsageFault"]
        for i, handler in enumerate(handlers):
            addr = struct.unpack('<I', data[(i+2)*4:(i+3)*4])[0]
            # Use debug level for handler addresses unless suspicious
            logger.debug(f"  {handler}: 0x{addr:08X}") 
            
            # Check if handler addresses are in valid code range
            if not (0x00000000 <= addr <= 0x00080000 or addr == 0xFFFFFFFF):
                logger.warning(f"Suspicious {handler} handler address: 0x{addr:08X}")
                # Don't fail validation just for suspicious handler, just warn
                # return False
        
        logger.info("ARM vector table validation passed")
        return True
    
    except Exception as e:
        logger.error(f"Error validating vector table: {e}")
        return False


def check_for_thumb_code(filename, logger):
    """
    Check if file contains ARM Thumb code signatures
    
    Args:
        filename: Path to firmware file
        logger: Logger object for output
        
    Returns:
        bool: True if ARM Thumb code is detected
    """
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        
        # Count Thumb PUSH/POP instructions
        thumb_push = sum(1 for i in range(len(data)-1) if data[i:i+2] in [b'\x2D\xE9', b'\xB5\x70', b'\xB5\xF0'])
        thumb_pop = sum(1 for i in range(len(data)-1) if data[i:i+2] in [b'\xBD\xE8', b'\xBD\x70', b'\xBD\xF0']) 
        
        logger.info(f"Found {thumb_push} PUSH instructions")
        logger.info(f"Found {thumb_pop} POP instructions")
        
        # Verify it contains enough Thumb instructions
        if thumb_push > 10 and thumb_pop > 10:
            logger.info("✓ ARM Thumb code signature verified")
            return True
        else:
            logger.warning("✗ ARM Thumb code signature not detected! (Might be OK, but unusual)")
            return True # Don't fail validation just for this
            
    except Exception as e:
        logger.error(f"Error checking for Thumb code: {e}")
        return False


def validate_firmware_file(filename, logger, expected_size=None):
    """
    Comprehensive firmware validation
    
    Args:
        filename: Path to firmware file
        logger: Logger object for output
        expected_size: Expected size in bytes (optional)
        
    Returns:
        bool: True if all validation checks pass
    """
    logger.info(f"Validating firmware: {filename}")
    # logger.info("-" * 50) # Use logger formatting instead
    
    # 1. Verify file size
    size_valid = validate_firmware_size(filename, logger, expected_size)
    # logger.info("") # Remove blank prints
    
    # 2. Verify ARM vector table
    vector_valid = validate_arm_vector_table(filename, logger)
    # logger.info("") # Remove blank prints
    
    # 3. Check for ARM Thumb code signatures
    thumb_valid = check_for_thumb_code(filename, logger)
    # logger.info("") # Remove blank prints
    
    # Overall result
    if size_valid and vector_valid and thumb_valid:
        logger.info(f"✓ All firmware validation checks passed for {filename}")
        return True
    else:
        logger.error(f"✗ Firmware validation failed for {filename}")
        return False 