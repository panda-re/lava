import struct


def create_command(opcode, payload):
    """
    Creates a Graphland command block.
    Format: [uint16_t opcode][uint16_t size][uint8_t data[size]]
    """
    # Ensure payload is bytes
    if not isinstance(payload, bytes):
        # Default to packing as a 4-byte signed integer if it's an int
        payload = struct.pack('<i', payload)

    size = len(payload)
    # Pack header: < (little-endian), H (uint16_t), H (uint16_t)
    header = struct.pack('<HH', opcode, size)
    return header + payload


# Opcode constants (Ensure these match your C headers)
ADD_NODE = 0
DEL_NODE = 1
SET_METADATA = 2
ADD_EDGE = 3
DEL_EDGE = 4
PRINT_GRAPH = 5
PRINT_NODE = 6


def generate_graphland_seed(filename="seed.bin"):
    """
    Generates a structurally perfect binary seed for Graphland.
    Matches the updated 'while(fread)' C loop in your Canvas.
    """
    commands = []

    # 1. ADD_NODE (ID: 1001) -> size 4
    commands.append(create_command(ADD_NODE, 1001))

    # 2. ADD_NODE (ID: 2002) -> size 4
    commands.append(create_command(ADD_NODE, 2002))

    # 3. SET_METADATA for 1001
    # C handler expects: [int label][int metadata_len][uint8_t metadata...]
    # Total size for this block: 4 + 4 + len(meta_val)
    meta_val = b"KLEE_VALIDATION"
    meta_payload = struct.pack('<ii', 1001, len(meta_val)) + meta_val
    commands.append(create_command(SET_METADATA, meta_payload))

    # 4. ADD_EDGE (1001 -> 2002) -> size 8
    # C handler expects: [int src][int dst]
    commands.append(create_command(ADD_EDGE, struct.pack('<ii', 1001, 2002)))

    # 5. PRINT_NODE (1001) -> size 4
    commands.append(create_command(PRINT_NODE, 1001))

    # 6. PRINT_GRAPH -> size 0 (Tests the new size > 0 check in your loop)
    commands.append(create_command(PRINT_GRAPH, b""))

    try:
        with open(filename, "wb") as f:
            for cmd in commands:
                f.write(cmd)
            f.flush()

        print(f"[*] Successfully generated Graphland seed: {filename}")
        print(f"[*] Total size: {sum(len(c) for c in commands)} bytes")
        print("[*] Sequence: ADD, ADD, METADATA, EDGE, PRINT_NODE, PRINT_GRAPH")
        print("[*] This seed is compatible with the 'Safe Main Loop' in your Canvas.")

    except Exception as e:
        print(f"[!] Error writing seed file: {e}")


if __name__ == "__main__":
    generate_graphland_seed()