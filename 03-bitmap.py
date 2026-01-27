#!/usr/bin/env python3
"""
Resource Extraction and Image Processing Tool
Extracts and processes embedded resources (primarily images) from firmware filesystems.
Handles binary data, 16-bit color images with padding, and generates BMP files.
"""

import struct
import os
import sys
import json

# Configuration constants
INPUT_FILE = 'extracted_parts/part_5_main_fs.bin'  # Main filesystem partition
OUTPUT_DIR = 'extracted_parts/resources'           # Output directory for extracted resources
MANIFEST_FILE = os.path.join(OUTPUT_DIR, 'manifest.json')  # Metadata manifest
MAGIC_SIG = b'\x77\x00\x00\x3A\x75'  # Magic signature marking resource metadata entries

def swap_bytes_16bit(data):
    """
    Swap adjacent bytes in 16-bit words (endianness conversion).
    
    Many embedded systems store 16-bit color data in big-endian format
    while desktop systems expect little-endian. This converts between them.
    
    Example: Big-endian AB CD becomes little-endian BA DC
    
    Args:
        data (bytes): Input data with potential byte ordering issues
        
    Returns:
        bytes: Data with adjacent bytes swapped in 16-bit words
    """
    arr = bytearray(data)
    
    # Ensure even length for 16-bit operations
    if len(arr) % 2 != 0:
        arr = arr[:-1]  # Discard last byte if odd length
    
    # Swap adjacent bytes: indices 0↔1, 2↔3, etc.
    arr[0::2], arr[1::2] = arr[1::2], arr[0::2]
    
    return bytes(arr)

def get_stride_info(width):
    """
    Calculate stride and padding information for image data.
    
    Stride refers to the number of bytes per row in an image.
    Many embedded systems use tightly packed rows, while BMP format
    requires 4-byte aligned rows.
    
    Args:
        width (int): Image width in pixels
        
    Returns:
        tuple: (src_stride, dst_stride, padding)
            src_stride: Original row size in bytes (width * bytes_per_pixel)
            dst_stride: BMP-aligned row size (multiple of 4 bytes)
            padding: Additional bytes needed per row for alignment
    """
    # 16-bit color = 2 bytes per pixel
    src_stride = width * 2  # Hardware compact stride
    
    # BMP requires rows to be 4-byte aligned
    dst_stride = (src_stride + 3) & ~3  # Round up to nearest multiple of 4
    padding = dst_stride - src_stride
    
    return src_stride, dst_stride, padding

def restride_to_bmp(raw_data, width, height):
    """
    Convert tightly packed image data to BMP-aligned format.
    
    Adds padding bytes to each row to meet BMP's 4-byte alignment requirement.
    
    Args:
        raw_data (bytes): Original tightly packed pixel data
        width (int): Image width in pixels
        height (int): Image height in pixels
        
    Returns:
        bytes: Image data with proper row padding for BMP format
    """
    src_stride, dst_stride, padding = get_stride_info(width)
    
    # If no padding needed and data length matches, return as-is
    if padding == 0 and len(raw_data) == src_stride * height:
        return raw_data
    
    # Calculate expected data size
    expected_len = src_stride * height
    
    # Pad data if too short (defensive programming)
    if len(raw_data) < expected_len:
        raw_data += b'\x00' * (expected_len - len(raw_data))
    
    # Process each row
    output = bytearray()
    for y in range(height):
        src_start = y * src_stride
        src_end = src_start + src_stride
        
        # Copy original row data
        output.extend(raw_data[src_start:src_end])
        
        # Add padding if needed
        if padding > 0:
            output.extend(b'\x00' * padding)
            
    return bytes(output)

def create_bmp_header(width, height):
    """
    Generate a complete BMP file header for 16-bit color images.
    
    Creates headers for 565 RGB format (5-6-5 bits per color channel).
    
    Args:
        width (int): Image width in pixels
        height (int): Image height in pixels (negative for top-down BMP)
        
    Returns:
        bytes: Complete BMP header (54 bytes total)
    """
    # Calculate stride and image size
    src_stride, dst_stride, padding = get_stride_info(width)
    image_size = dst_stride * height
    
    # Header sizes: BITMAPFILEHEADER(14) + BITMAPINFOHEADER(40) + color masks(12)
    headers_size = 14 + 40 + 12
    file_size = headers_size + image_size
    
    # BITMAPFILEHEADER (14 bytes)
    header = b'BM'                      # Signature
    header += struct.pack('<I', file_size)  # File size
    header += b'\x00\x00\x00\x00'      # Reserved
    header += struct.pack('<I', headers_size)  # Offset to pixel data
    
    # BITMAPINFOHEADER (40 bytes)
    header += struct.pack('<I', 40)    # Header size (DIB header)
    header += struct.pack('<i', width)  # Width
    header += struct.pack('<i', -height)  # Height (negative = top-down image)
    header += struct.pack('<H', 1)     # Planes (must be 1)
    header += struct.pack('<H', 16)    # Bits per pixel
    header += struct.pack('<I', 3)     # Compression (BI_BITFIELDS = 3)
    header += struct.pack('<I', image_size)  # Image size
    header += struct.pack('<i', 2835)  # Horizontal resolution (72 DPI)
    header += struct.pack('<i', 2835)  # Vertical resolution (72 DPI)
    header += struct.pack('<I', 0)     # Colors in palette
    header += struct.pack('<I', 0)     # Important colors
    
    # Color masks for 565 RGB format (12 bytes)
    # Red mask:   0xF800 = 1111100000000000 (5 bits)
    # Green mask: 0x07E0 = 0000011111100000 (6 bits)  
    # Blue mask:  0x001F = 0000000000011111 (5 bits)
    header += struct.pack('<I', 0xF800)  # Red mask
    header += struct.pack('<I', 0x07E0)  # Green mask
    header += struct.pack('<I', 0x001F)  # Blue mask
    
    return header

def decode_raw_name(raw_bytes):
    """
    Decode raw bytes to ASCII string without character substitution.
    
    This preserves the exact string as stored in firmware, including
    any special characters like parentheses or commas.
    
    Args:
        raw_bytes (bytes): Raw name bytes from firmware
        
    Returns:
        str: Decoded string, truncated at first null byte
    """
    try:
        # Find null terminator if present
        null_pos = raw_bytes.find(b'\x00')
        if null_pos != -1:
            raw_bytes = raw_bytes[:null_pos]
        
        # Decode with ASCII, ignore non-ASCII characters
        return raw_bytes.decode('ascii', errors='ignore')
    except:
        return "unknown"

def sanitize_filename(original_name):
    """
    Generate safe filenames for cross-platform filesystem storage.
    
    Allows common characters like parentheses and commas but filters
    path separators and control characters that could cause issues.
    
    Args:
        original_name (str): Original filename from firmware
        
    Returns:
        str: Sanitized filename safe for all major filesystems
    """
    # Replace path separators
    safe = original_name.replace('/', '_').replace('\\', '_')
    
    # Whitelist approach: allow alphanumeric and common safe characters
    return "".join(
        c if (c.isalnum() or c in "._-(), ") else "_" 
        for c in safe
    ).strip()

def main():
    """
    Main extraction and processing workflow.
    
    Process flow:
    1. Scan filesystem for resource metadata using magic signature
    2. Parse metadata to extract image dimensions and offsets
    3. Extract raw resource data from filesystem
    4. Process images (byte swap, add padding, create BMP headers)
    5. Save resources with appropriate filenames
    6. Generate manifest with metadata for potential re-packing
    """
    # Validate input file exists
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Input file not found at {INPUT_FILE}")
        sys.exit(1)
    
    # Create output directory if needed
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Read entire filesystem partition
    with open(INPUT_FILE, 'rb') as f:
        data = f.read()

    file_size = len(data)
    entries = []  # List to store parsed resource metadata

    print("Scanning file table...")
    
    # Scan for magic signatures marking resource entries
    start_pos = 0
    while True:
        # Find next occurrence of magic signature
        pos = data.find(MAGIC_SIG, start_pos)
        if pos == -1:
            break
        
        try:
            # Parse resource metadata structure
            # Layout: [magic:5][unknown:15][offset:4][width:4][height:4][name:64]
            offset = struct.unpack('<I', data[pos + 20:pos + 24])[0]
            width = struct.unpack('<I', data[pos + 24:pos + 28])[0]
            height = struct.unpack('<I', data[pos + 28:pos + 32])[0]
            
            # Extract and decode resource name
            name_bytes = data[pos + 32:pos + 96]  # 64-byte name field
            original_name = decode_raw_name(name_bytes)

            # Validate entry and add to list
            if offset < file_size and len(original_name) > 0:
                entries.append({
                    'meta_pos': pos,          # Position of metadata in file
                    'offset': offset,         # Resource data offset
                    'width': width,           # Image width (0 for non-images)
                    'height': height,         # Image height (0 for non-images)
                    'original_name': original_name  # Original firmware name
                })
        except:
            # Skip malformed entries
            pass
        
        # Continue search after current position
        start_pos = pos + 1

    # Sort entries by data offset for sequential extraction
    entries.sort(key=lambda x: x['offset'])
    
    # Determine end of data section (before metadata starts)
    data_end_limit = min(
        (e['meta_pos'] for e in entries),
        default=file_size
    )
    
    manifest = []  # Metadata for all extracted resources
    print(f"Processing {len(entries)} resources...")
    print("-" * 80)
    print(f"{'Original Name':<40} {'Status'}")
    print("-" * 80)
    
    # Process each resource entry
    for i, entry in enumerate(entries):
        offset = entry['offset']
        width = entry['width']
        height = entry['height']
        original_name = entry['original_name']
        
        # Calculate raw data size
        if i < len(entries) - 1:
            # Size is distance to next resource
            raw_size = entries[i + 1]['offset'] - offset
        else:
            # Last resource: size is distance to metadata section
            raw_size = data_end_limit - offset
            if raw_size < 0:
                raw_size = file_size - offset
        
        # Skip invalid sizes
        if raw_size <= 0:
            continue
        
        # Extract raw resource data
        raw_data = data[offset:offset + raw_size]
        
        # Prepare filename (sanitize but preserve original in manifest)
        save_name_base = sanitize_filename(original_name)
        final_data = raw_data  # Default to raw data
        
        # Initialize metadata structure
        meta = {
            "id": i,
            "original_firmware_name": original_name,  # Original name with all characters
            "original_offset": offset,
            "original_raw_size": raw_size,
            "width": width,
            "height": height,
            "is_image": False,
            "transformations": {
                "byte_swap_applied": False,
                "row_padding_bytes": 0,
                "bmp_header_size": 0
            }
        }
        
        # Image processing pipeline (for entries with valid dimensions)
        if width > 0 and height > 0:
            # Calculate expected size for 16-bit color image
            expected_size = width * height * 2
            
            # Heuristic: if size is close to expected, treat as image
            if abs(raw_size - expected_size) < 4096:  # Allow small discrepancies
                # Get padding info
                _, _, padding = get_stride_info(width)
                
                # Apply transformations for BMP format
                pixel_data = swap_bytes_16bit(raw_data)      # Byte swap
                pixel_data = restride_to_bmp(pixel_data, width, height)  # Add padding
                header = create_bmp_header(width, height)    # Create BMP header
                final_data = header + pixel_data              # Combine
                
                # Update metadata
                meta["is_image"] = True
                meta["transformations"]["byte_swap_applied"] = True
                meta["transformations"]["row_padding_bytes"] = padding
                meta["transformations"]["bmp_header_size"] = len(header)
                
                # Add .bmp extension for easier viewing (not in original name)
                if not save_name_base.lower().endswith('.bmp'):
                    save_name_base += ".bmp"
        
        # Write processed resource to disk
        out_path = os.path.join(OUTPUT_DIR, save_name_base)
        with open(out_path, 'wb') as out_f:
            out_f.write(final_data)
        
        # Update manifest with saved filename
        meta["saved_filename"] = save_name_base
        manifest.append(meta)
        
        # Progress reporting (show first 10 and then every 200th)
        if i < 10 or i % 200 == 0:
            print(f"{original_name:<40} OK")
    
    # Save comprehensive manifest for future reference or re-packing
    with open(MANIFEST_FILE, 'w') as f:
        json.dump(manifest, f, indent=4, ensure_ascii=False)
    
    print("-" * 80)
    print(f"Complete. Manifest file: {MANIFEST_FILE}")
    print("Note: When re-packing firmware, use 'original_firmware_name' with 'original_offset'.")

if __name__ == "__main__":
    main()
