"""Generate valid PNG icons for Chrome Extension using pure Python standard library."""
import os
import struct
import zlib

def create_png(width: int, height: int, filename: str):
    # Generates a navy blue shield icon PNG
    # Color palette: Navy #0b2545, Accent #0284c7
    raw_data = bytearray()
    
    for y in range(height):
        raw_data.append(0)  # Filter type 0 (None)
        ny = (y / (height - 1)) * 2.0 - 1.0
        for x in range(width):
            nx = (x / (width - 1)) * 2.0 - 1.0
            dist_sq = nx * nx + ny * ny
            
            # Simple rounded shield shape
            is_shield = (abs(nx) <= 0.85) and (ny <= 0.85) and (ny >= -0.85) and (ny <= 0.9 - abs(nx) * 0.7)
            
            if is_shield:
                # Shield body (gradient navy to deep cyan)
                r = int(11 + (1 - ny) * 10)
                g = int(37 + (1 - ny) * 45)
                b = int(69 + (1 - ny) * 80)
                a = 255
            else:
                r, g, b, a = 0, 0, 0, 0
                
            raw_data.extend([r, g, b, a])
            
    compressed = zlib.compress(raw_data)
    
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    
    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    png.extend(struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc))
    
    # IDAT chunk
    idat_crc = zlib.crc32(b"IDAT" + compressed)
    png.extend(struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", idat_crc))
    
    # IEND chunk
    iend_crc = zlib.crc32(b"IEND")
    png.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc))
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "wb") as f:
        f.write(png)
    print(f"Generated {filename} ({width}x{height})")

if __name__ == "__main__":
    create_png(16, 16, "extension/icons/icon-16.png")
    create_png(48, 48, "extension/icons/icon-48.png")
    create_png(128, 128, "extension/icons/icon-128.png")
    print("All extension icons created successfully!")
