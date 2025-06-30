import os
import tarfile
import subprocess


def search_and_extract(keyword: str, source_dir: str) -> str | None:
    """
    Search for a .tar.gz file in 'target_bins/' matching the keyword,
    extract it to 'target_injections/', and run `make install` inside.

    Args:
        keyword: The project name, e.g. 'toy', 'file', etc.
        source_dir: The directory with the tar file to unpack
    Returns:
        Str: The path to the extracted directory if successful, None otherwise.
    """
    dest_dir = os.path.join("target_injections", keyword)
    os.makedirs(dest_dir, exist_ok=True)

    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".tar.gz") and keyword in file:
                file_path = os.path.join(root, file)
                print(f"Found matching file: {file_path}")

                file_name = os.path.basename(file_path)
                base_name = file_name.split('-pre.tar.gz')[0]

                with tarfile.open(file_path, "r:gz") as tar:
                    tar.extractall(dest_dir)
                    print(f"Extracted contents to: {dest_dir}")

                try:
                    # Extend CFLAGS and CXXFLAGS
                    # We need static compilation and debug for Angr to work properly with the binary
                    env = os.environ.copy()
                    extra_flags = "-g"
                    
                    # Build CFLAGS and CXXFLAGS for explicit passing to make
                    cflags = env.get("CFLAGS", "") + " " + extra_flags
                    cxxflags = env.get("CXXFLAGS", "") + " " + extra_flags

                    print(f"[*] Running make with:")
                    print(f"    CFLAGS='{cflags.strip()}'")
                    print(f"    CXXFLAGS='{cxxflags.strip()}'")

                    subprocess.run(
                        ["make", f"CFLAGS={cflags.strip()}", f"CXXFLAGS={cxxflags.strip()}"],
                        cwd=os.path.join(dest_dir, base_name),
                        check=True,
                        env=env,
                    )
                    subprocess.run(
                        ["make", "install", f"CFLAGS={cflags.strip()}", f"CXXFLAGS={cxxflags.strip()}"],
                        cwd=os.path.join(dest_dir, base_name),
                        check=True,
                        env=env,
                    )
                    print("Make command executed successfully.")
                    return os.path.join(dest_dir, base_name)
                except subprocess.CalledProcessError as e:
                    print(f"Error while running 'make': {e}")
                    return None

    print(f"No .tar.gz file with keyword '{keyword}' found in {source_dir}.")
    return None

