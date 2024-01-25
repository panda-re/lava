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

# Step 1: Install panda debian package
wget https://github.com/panda-re/panda/releases/download/v1.6/pandare_22.04.deb
$SUDO apt install pandare_22.04.deb

# Remove the comment to update all debian stuff from sources.list
$SUDO cp /etc/apt/sources.list /etc/apt/sources.list~
$SUDO sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
$SUDO apt-get update

progress "Updates complete"

# This was originally in the docs/setup.md, I removed things starting with 'python-' as that should be installed via pip
# shellcheck disable=SC2046
# libc6 needed for compiling btrace
# libjsoncpp needed for fbi json parsing
# This fixes installing psycopg2
# https://stackoverflow.com/questions/11618898/pg-config-executable-not-found

# Dependencies are for a major version, but the filenames include minor versions
# So take our major version, find the first match in dependencies directory and run with it.
# This will give us "./panda/dependencies/ubuntu:20.04" where ubuntu:20.04_build.txt or 20.04_base.txt exists
version=$(lsb_release -r| awk '{print $2}' | awk -F'.' '{print $1}')
# shellcheck disable=SC2086
dep_base=$(find ./dependencies/ubuntu_${version}.* -print -quit | sed  -e "s/_build\.txt\|_base\.txt//")

if [ -e "${dep_base}"_build.txt ] || [ -e "${dep_base}"_base.txt ]; then
  echo "Found dependency file(s) at ${dep_base}*.txt"
  # shellcheck disable=SC2046
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get -y install --no-install-recommends $(cat ${dep_base}*.txt | grep -o '^[^#]*')
else
  echo "Unsupported Ubuntu version: $version. Create a list of build dependencies in ${dep_base}_{base,build}.txt and try again."
  exit 1
fi
$SUDO apt-get build-dep qemu
progress "Installed build dependencies"

$SUDO pip3 install --upgrade pip

# This seems to be the better replacement to have all python packages
$SUDO pip3 install -r docker/requirements.txt
progress "Installed Python requirements"

# Everything here is everything in setup_container.py
rm -rf tools/build
mkdir -p tools/build
mkdir -p tools/install
cmake -Btools/build -Htools -DCMAKE_INSTALL_PREFIX=tools/install

# Compile lavaTool
make --no-print-directory -j4 install -Ctools/build/lavaTool

# Compile FBI
make --no-print-directory -j4 -C fbi install -Ctools/build

progress "Installed LAVA"
