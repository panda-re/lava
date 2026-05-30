import os


def create_seed(filename, byte_values):
    """
    Creates a binary seed file with the specified byte values.
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    
    with open(filename, "wb") as f:
        f.write(bytes(byte_values))
    print(f"[*] Created seed: {filename} -> {bytes(byte_values).hex()}")


def main():
    # Path matches the LAVA structure you've been using
    base_path = "inputs"
    
    # 1. All Lefts (0 < 128)
    create_seed(f"{base_path}/all_left.bin", [0] * 8)
    
    # 2. All Rights (255 >= 128)
    create_seed(f"{base_path}/all_right.bin", [255] * 8)
    
    # 3. Alternating (LRLRLRLR)
    create_seed(f"{base_path}/zigzag.bin", [0, 255, 0, 255, 0, 255, 0, 255])
    
    # 4. The 'Midpoint' seed (Threshold testing)
    create_seed(f"{base_path}/threshold.bin", [127, 128, 127, 128, 127, 128, 127, 128])

    print("\n[!] Total of 4 seeds generated. Use 'all_left.bin' for initial testing.")


if __name__ == "__main__":
    main()

