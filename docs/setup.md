# Setup LAVA

## Ubuntu 64-bit 16.04.4
The following install steps worked on 6/29/2019 with LAVA commit [c55bf1826ef9855a621f2652b30f16ac75b19cb6](https://github.com/panda-re/lava/commit/c55bf1826ef9855a621f2652b30f16ac75b19cb6).

- Download and install [Ubuntu 64-bit 16.04.4](http://old-releases.ubuntu.com/releases/16.04.4/ubuntu-16.04.4-desktop-amd64.iso).
- `sudo add-apt-repository ppa:phulin/panda`
- `sudo cp /etc/apt/sources.list /etc/apt/sources.list~`
- `sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list`
- `sudo apt-get update`
- `sudo apt-get install python-pip git protobuf-compiler protobuf-c-compiler libprotobuf-c0-dev libprotoc-dev python-protobuf libelf-dev libcapstone-dev libdwarf-dev python-pycparser llvm-3.3 clang-3.3 libc++-dev libwiretap-dev libwireshark-dev odb`
- `sudo apt-get build-dep qemu`
- `pip install colorama`
- `cd ~/Desktop`
- `git clone https://github.com/panda-re/lava.git`
- `cd ~/Desktop/lava`
- `python2 setup.py`
