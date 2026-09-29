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
    # Next to this script, so it works from any working directory
    base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inputs")
    
    # All Lefts (every byte < 128). One seed is enough: concolic exploration flips each
    # branch from it, reaching all 256 paths.
    create_seed(f"{base_path}/all_left.bin", [0] * 8)


if __name__ == "__main__":
    main()

