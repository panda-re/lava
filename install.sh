#!/bin/bash

set -ex

# shellcheck disable=SC2034
sudo=""
if [ $EUID -ne 0 ]; then
  SUDO=sudo
fi

progress() {
  echo
  echo -e "\e[32m[lava_install]\e[0m \e[1m$1\e[0m"
}

if [ -z "${LLVM_DIR}" ]; then
    echo "LLVM_DIR is not set ${LLVM_DIR}, setting it to /usr/lib/llvm-14"
    export LLVM_DIR=/usr/lib/llvm-14
else
    echo "LLVM_DIR is set to '${LLVM_DIR}'"
fi

# This was originally in the docs/setup.md, I removed things starting with 'python-' as that should be installed via pip
# shellcheck disable=SC2046
# libc6 needed for compiling btrace
# libjsoncpp needed for fbi json parsing
# This fixes installing psycopg2
# https://stackoverflow.com/questions/11618898/pg-config-executable-not-found

# Dependencies are for a major version, but the filenames include minor versions
# So take our major version, find the first match in dependencies directory and run with it.
# This will give us "./panda/dependencies/ubuntu:20.04" where ubuntu:20.04_build.txt or 20.04_base.txt exists
version=$(lsb_release -r | awk '{print $2}' | awk -F'.' '{print $1}')
ubuntu_version=$(lsb_release -r | awk '{print $2}')
# Minimum Acceptable version is 1.8.66
PANDA_VERSION="v1.8.78"
CAPSTONE_VERSION="5.0.5"
LAVA_DIR=$(dirname "$(realpath "$0")")
echo "LAVA_DIR: $LAVA_DIR"

# shellcheck disable=SC2086
dep_base=$(find ./dependencies/ubuntu_${version}.* -print -quit | sed  -e "s/_build\.txt\|_base\.txt//")

$SUDO apt-get -qq update
if [ -e "${dep_base}"_build.txt ] || [ -e "${dep_base}"_base.txt ]; then
  echo "Found dependency file(s) at ${dep_base}*.txt"
  # shellcheck disable=SC2046
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get -y install --no-install-recommends $(cat ${dep_base}*.txt | grep -o '^[^#]*')
else
  echo "Unsupported Ubuntu version: $version. Create a list of build dependencies in ${dep_base}_{base,build}.txt and try again."
  exit 1
fi

# Check if capstone is installed
if ! dpkg -l | grep libcapstone; then
  curl -LJ -o /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb https://github.com/capstone-engine/capstone/releases/download/${CAPSTONE_VERSION}/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
  $SUDO dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
  rm -rf /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
fi

# Check if pandare is installed
if ! dpkg -l | grep -q pandare; then
    echo "pandare is not installed. Installing now..."
    # shellcheck disable=SC2086
    curl -LJ -o /tmp/pandare_${ubuntu_version}.deb https://github.com/panda-re/panda/releases/download/${PANDA_VERSION}/pandare_${ubuntu_version}.deb
    # shellcheck disable=SC2086
    $SUDO apt-get -y install /tmp/pandare_${ubuntu_version}.deb
    rm /tmp/*.deb
else
    echo "pandare is already installed."
fi
progress "Installed build dependencies"

pip3 install --upgrade pip
pip3 install -r requirements.txt
progress "Installed Python requirements"

progress "Configure lavaTool"
rm -rf "$LAVA_DIR/tools/build"
cmake -B"${LAVA_DIR}/tools/build" -H"${LAVA_DIR}/tools" -DCMAKE_INSTALL_PREFIX="${LAVA_DIR}/tools/install" -DCMAKE_BUILD_TYPE=Release

progress "Compiling lavaTool"
cmake --build "${LAVA_DIR}/tools/build" --target install --parallel "$(nproc)" --config Release

progress "Installed LAVA"
