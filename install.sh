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

# Dependencies are for a major version, but the filenames include minor versions
# So take our major version, find the first match in dependencies directory and run with it.
# This will give us "./panda/dependencies/ubuntu:20.04" where ubuntu:20.04_build.txt or 20.04_base.txt exists
version=$(lsb_release -r | awk '{print $2}' | awk -F'.' '{print $1}')
CAPSTONE_VERSION="5.0.5"
CMAKE_INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX:-/usr}"
# SKIP_DEPS=1: skip apt/dpkg dependency installs (they need root); use once deps are installed.
SKIP_DEPS="${SKIP_DEPS:-0}"

# shellcheck disable=SC2086
dep_base=$(find ./dependencies/ubuntu_${version}.* -print -quit | sed  -e "s/_build\.txt\|_base\.txt//")

if [ "$SKIP_DEPS" != 1 ]; then
  $SUDO apt-get -qq update
  if [ -e "${dep_base}"_build.txt ] || [ -e "${dep_base}"_base.txt ]; then
    echo "Found dependency file(s) at ${dep_base}*.txt"
    # shellcheck disable=SC2046
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get -y install --no-install-recommends curl jq $(cat ${dep_base}*.txt | grep -o '^[^#]*')
  else
    echo "Unsupported Ubuntu version: $version. Create a list of build dependencies in ${dep_base}_{base,build}.txt and try again."
    exit 1
  fi

  # Check if capstone is installed
  if ! dpkg -l | grep -q libcapstone; then
    curl -LJ -o /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb https://github.com/capstone-engine/capstone/releases/download/${CAPSTONE_VERSION}/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
    $SUDO dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
    rm -rf /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb
  fi

  # Check if pandare is installed
  if ! dpkg -l | grep -q pandare; then
    echo "pandare is not installed. Installing now..."
    ubuntu_version=$(. /etc/os-release && echo "$VERSION_ID")
    # shellcheck disable=SC2086
    curl -LJ -o /tmp/pandare_${ubuntu_version}.deb https://github.com/panda-re/panda/releases/latest/download/pandare_${ubuntu_version}.deb
    # shellcheck disable=SC2086
    $SUDO apt-get -y install /tmp/pandare_${ubuntu_version}.deb
    rm "/tmp/pandare_${ubuntu_version}.deb"
  else
    echo "pandare is already installed."
  fi

  # TODO: Switch to panda-re libhc when available
  # Check if libhc is installed
  if ! dpkg -l | grep -q libhc-dev; then
    echo "libhc-dev is not installed. Installing now..."
    # shellcheck disable=SC2034
    LIBHC_VERSION=$(curl -s https://api.github.com/repos/AndrewQuijano/libhc/releases/latest | jq -r .tag_name)
    LIBHC_TAG=${LIBHC_VERSION#v}
    # shellcheck disable=SC2086
    curl -LJ -o /tmp/libhc-dev_${LIBHC_TAG}_all.deb https://github.com/AndrewQuijano/libhc/releases/download/${LIBHC_VERSION}/libhc-dev_${LIBHC_TAG}_all.deb
    # shellcheck disable=SC2086
    $SUDO apt-get -y install /tmp/libhc-dev_${LIBHC_TAG}_all.deb
    rm "/tmp/libhc-dev_${LIBHC_TAG}_all.deb"
  else
    echo "libhc is already installed."
  fi
  progress "Installed build dependencies"
else
  progress "SKIP_DEPS=1: skipping build dependencies"
fi

progress "Configure lavaTool"
# Start clean: a stale build tree or ODB/protobuf output can get repackaged as-is
rm -rf "./tools/build" "./tools/lavaODB/generated"
cmake -B"./tools/build" \
      -H"./tools" \
      -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLAVA_ENABLE_COVERAGE="${LAVA_ENABLE_COVERAGE:-OFF}"

progress "Compiling lavaTool"
cmake --build "./tools/build" --parallel "$(nproc)" --config Release
if [ "$CMAKE_INSTALL_PREFIX" = /usr ]; then
  pushd ./tools/build
  cpack -G DEB
  # --reinstall: the package version is always 0.0.0, so apt may otherwise skip it
  $SUDO apt-get install --reinstall ./lava*.deb
  popd
else
  # Non-system prefix (e.g. ~/.local): no .deb, no root. Keep the file list outside tools/build
  # (wiped on every run) so this install can be removed later:
  #   xargs rm -f < "$CMAKE_INSTALL_PREFIX/share/lava/install_manifest.txt"
  cmake --install "./tools/build"
  mkdir -p "$CMAKE_INSTALL_PREFIX/share/lava"
  cp "./tools/build/install_manifest.txt" "$CMAKE_INSTALL_PREFIX/share/lava/install_manifest.txt"
fi

progress "Installed LAVA"

# Two installs (the lava .deb in /usr and a prefix install) shadow each other by PATH order.
for tool in lavaTool lavaFnTool lavaInitTool duasan; do
  # readlink -f: /bin is a symlink to /usr/bin on Ubuntu, so which -a lists that copy twice
  copies=$(which -a "$tool" | xargs -r readlink -f | sort -u)
  if [ "$(echo "$copies" | grep -c .)" -gt 1 ]; then
    echo "WARNING: more than one $tool on PATH, using $(command -v "$tool"):"
    echo "$copies"
  fi
done
