#!/usr/bin/env python3
"""
Firmware Image Extraction and Analysis Tool
This script extracts and analyzes partitions from a firmware image file.
Original Chinese script translated to English with detailed comments.
"""

import struct
import os
import sys

# Configuration constants
FILE_NAME = 'HIFIEC20.IMG'                    # Name of the firmware image file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Script's directory
FILE_PATH = os.path.join(BASE_DIR, FILE_NAME)          # Full path to firmware image
OUTPUT_DIR = os.path.join(BASE_DIR, 'extracted_parts') # Directory for extracted files

def ensure_dir(path):
    """
    Create directory if it doesn't exist.
    
    Args:
        path (str): Directory path to create if missing
    """
    if not os.path.exists(path):
        os.makedirs(path)

def analyze_hybrid_headers(data):
    """
    Parse partition table using discovered hybrid header structure.
    
    The firmware image uses two different header formats:
    - Type A: Linked List format (Part 0, 1, 2, 3, 5) - contains offset, size, next_offset
    - Type B: Absolute Pointer format (Part 4/DSP) - contains type, start_offset, size
    
    Args:
        data (bytes): Complete firmware image data
        
    Returns:
        dict: Dictionary containing partition information with keys: offset, size, data
    """
    print("-" * 80)
    print(f"{'Name':<20} {'Strategy':<10} {'Offset':<10} {'Size':<10} {'End':<10} {'Next/Meta'}")
    print("-" * 80)

    parts = {}  # Dictionary to store partition information
    
    # 1. Standard Linked List Partitions (Type A)
    # Header format: [Offset:4 bytes] [Size:4 bytes] [Next_Offset:4 bytes] [Unknown:4 bytes]
    # Each entry is 16 bytes total (4 uint32 values)
    standard_entries = [
        (0x70, "part_0_flag"),           # Flag/configuration partition
        (0x78, "part_1_firmware_a"),     # Primary firmware image
        (0x80, "part_2_firmware_b"),     # Secondary/backup firmware image
        (0xCC, "part_3_resource"),       # Resource/LUT partition
        (0x14C, "part_5_main_fs")        # Main filesystem partition
    ]

    # Process each standard linked list partition
    for header_pos, name in standard_entries:
        # Extract 16-byte header chunk
        chunk = data[header_pos : header_pos + 16]
        
        # Unpack 4 uint32 values (little-endian)
        offset, size, next_offset, _ = struct.unpack('<IIII', chunk)
        
        strategy = "Standard"
        parts[name] = {'offset': offset, 'size': size, 'data': None}
        
        # Display partition information
        print(f"{name:<20} {strategy:<10} 0x{offset:08X} 0x{size:08X} "
              f"0x{offset+size:08X} 0x{next_offset:08X}")

    # 2. Special Partition - Audio DSP (Type B, The Anomaly)
    # Header format at 0xF4: [Type?:4] [Start_Offset:4] [Size:4] [Unknown:4]
    # Based on empirical evidence: 01 00 00 00 | 1A 25 76 00 | 2A 34 25 00
    p4_pos = 0xF4  # Position of Part 4 header
    chunk = data[p4_pos : p4_pos + 16]
    
    # Unpack 4 uint32 values
    val1, val2, val3, _ = struct.unpack('<IIII', chunk)
    
    # DSP partition uses different structure: val2=Start_Offset, val3=Size
    p4_offset = val2
    p4_size = val3
    name = "part_4_audio_dsp"
    strategy = "Special"
    
    parts[name] = {'offset': p4_offset, 'size': p4_size, 'data': None}
    
    # Display DSP partition info with special type field
    print(f"{name:<20} {strategy:<10} 0x{p4_offset:08X} 0x{p4_size:08X} "
          f"0x{p4_offset+p4_size:08X} Type:{val1}")
    
    return parts

def extract_and_verify(file_data, parts):
    """
    Extract partition data and perform integrity checks.
    
    Args:
        file_data (bytes): Complete firmware image data
        parts (dict): Dictionary containing partition information
        
    Returns:
        dict: Updated parts dictionary with 'data' field populated
    """
    print(f"\n[Extraction & Verification]")
    
    # Verify continuity between Part 3 (Resource) and Part 4 (DSP)
    p3_end = parts['part_3_resource']['offset'] + parts['part_3_resource']['size']
    p4_start = parts['part_4_audio_dsp']['offset']
    
    if p3_end == p4_start:
        print(f"PASS: Part 3 immediately precedes Part 4 (0x{p3_end:X})")
    else:
        print(f"WARN: Gap between Part 3 and 4: {p4_start - p3_end} bytes")

    # Verify continuity between Part 4 (DSP) and Part 5 (Main FS)
    p4_end = parts['part_4_audio_dsp']['offset'] + parts['part_4_audio_dsp']['size']
    p5_start = parts['part_5_main_fs']['offset']
    
    if p4_end == p5_start:
        print(f"PASS: Part 4 perfectly bridges to Part 5 (0x{p4_end:X})")
    else:
        print(f"WARN: Gap between Part 4 and 5: {p5_start - p4_end} bytes")

    # Extract each partition
    for name, info in parts.items():
        off = info['offset']
        sz = info['size']
        
        # Check bounds to prevent reading past file end
        if off + sz > len(file_data):
            print(f"ERR : {name} out of bounds!")
            continue
            
        # Extract partition data from firmware image
        info['data'] = file_data[off : off + sz]
        
        # Write extracted data to file
        out_name = os.path.join(OUTPUT_DIR, f"{name}.bin")
        with open(out_name, 'wb') as f:
            f.write(info['data'])
            
    print(f"Extracted {len(parts)} partitions to {OUTPUT_DIR}")
    return parts

def analyze_resource_table(part_3_data):
    """
    Analyze Part 3 resource table (Big-Endian Index Table).
    
    Part 3 appears to be a Look-Up Table (LUT) or index table
    stored in big-endian format, containing unsigned 16-bit values.
    
    Args:
        part_3_data (bytes): Data from part_3_resource partition
    """
    print(f"\n[Part 3 Resource Map Analysis]")
    
    # Check size alignment (should be even for 16-bit entries)
    if len(part_3_data) % 2 != 0:
        print("WARN: Part 3 size is not even!")
    
    # Calculate number of 16-bit entries
    count = len(part_3_data) // 2
    print(f"Total Entries: {count}")
    
    # Decode as Big Endian Unsigned Short (16-bit values)
    # '>' indicates big-endian byte order, 'H' indicates unsigned short
    indices = struct.unpack(f'>{count}H', part_3_data)
    
    # Analysis 1: Check if indices are strictly linear/sequential
    is_continuous = True
    broken_at = -1
    for i in range(len(indices)):
        if indices[i] != i:
            is_continuous = False
            broken_at = i
            break
            
    if is_continuous:
        print(f"Structure: STRICTLY LINEAR mapping (0, 1, 2... {count-1})")
        print("Meaning: Part 3 is likely a 1:1 LUT or simple counter array.")
    else:
        print(f"Structure: Non-linear mapping detected at index {broken_at}")
        print(f"Example sequence: {indices[broken_at:broken_at+10]}")

def verify_firmware_execution(part_1_data):
    """
    Verify Firmware A execution parameters and entry point.
    
    ARM Cortex-M processors typically start execution with:
    - First word: Initial Main Stack Pointer (MSP) value
    - Second word: Reset vector (entry point address)
    
    Args:
        part_1_data (bytes): Data from part_1_firmware_a partition
    """
    print(f"\n[Part 1 Execution Context]")
    
    # Extract first 8 bytes: MSP (4 bytes) + Reset vector (4 bytes)
    msp, reset = struct.unpack('<II', part_1_data[0:8])
    
    # Hypothesized base address where firmware loads in memory
    base_addr = 0x80400000  # Typical embedded system memory location
    entry_point = reset
    
    print(f"MSP: 0x{msp:08X}")
    print(f"PC : 0x{entry_point:08X}")
    
    # Check if entry point falls within the loaded binary range
    fw_size = len(part_1_data)
    
    if base_addr <= entry_point < base_addr + fw_size:
        # Calculate file offset corresponding to entry point
        offset = entry_point - base_addr
        
        # For ARM Thumb mode, entry points have LSB=1
        # Clear Thumb bit for file offset calculation
        file_offset = (entry_point & ~1) - base_addr
        
        print(f"Entry Point maps to File Offset: 0x{file_offset:08X}")
        
        # Verify the instruction at entry point (if within bounds)
        if file_offset < fw_size - 4:
            opcode = struct.unpack('<I', part_1_data[file_offset:file_offset+4])[0]
            print(f"Opcode at Reset: {opcode:08X}")
    else:
        print(f"WARN: Entry point 0x{entry_point:08X} is outside "
              f"hypothesized base 0x{base_addr:08X}")

def main():
    """
    Main execution function.
    """
    # Check if firmware file exists
    if not os.path.exists(FILE_PATH):
        print("File not found.")
        sys.exit(1)
        
    # Ensure output directory exists
    ensure_dir(OUTPUT_DIR)
    
    # Read entire firmware image
    with open(FILE_PATH, 'rb') as f:
        data = f.read()
        
    # Analyze headers to identify partitions
    parts = analyze_hybrid_headers(data)
    
    # Extract partitions and verify integrity
    parts = extract_and_verify(data, parts)
    
    # Analyze Part 3 (resource table) if available
    if parts.get('part_3_resource') and parts['part_3_resource']['data']:
        analyze_resource_table(parts['part_3_resource']['data'])
        
    # Verify Firmware A execution context if available
    if parts.get('part_1_firmware_a') and parts['part_1_firmware_a']['data']:
        verify_firmware_execution(parts['part_1_firmware_a']['data'])

if __name__ == "__main__":
    main()
