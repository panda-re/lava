ARG BASE_IMAGE="ubuntu:22.04"
ARG PANDA_VERSION="v1.8.78"
ARG CAPSTONE_VERSION="5.0.5"

### BASE IMAGE
FROM $BASE_IMAGE AS base
ARG BASE_IMAGE
ARG PANDA_VERSION
ARG CAPSTONE_VERSION

ENV DEBIAN_FRONTEND=noninteractive

# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
COPY ./dependencies/* /tmp
COPY . /

RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Install dependencies to compile LAVA
RUN [ -e /tmp/build_dep.txt ] && \
    apt-get -qq update && \
    apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

# Install run-time dependencies
RUN [ -e /tmp/base_dep.txt ] && \
    apt-get -qq update -y && \
    apt-get -qq install -y --no-install-recommends curl jq $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

RUN cd /tmp && \
    curl -LJO https://github.com/capstone-engine/capstone/releases/download/${CAPSTONE_VERSION}/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb && \
    dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb && \
    rm -rf /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb

# Finally: Install panda debian package, the latest version should have all necessary components for LAVA
RUN cd /tmp && \
    apt-get -qq update -y || (sleep 10 && apt-get -qq update -y) && \
    UBUNTU_VERSION=$(echo "$BASE_IMAGE" | awk -F':' '{print $2}') && \
    curl --retry 5 --retry-delay 10 -LJO https://github.com/panda-re/panda/releases/latest/download/pandare_${UBUNTU_VERSION}.deb && \
    apt-get install -qq -y --fix-missing /tmp/pandare_${UBUNTU_VERSION}.deb && \
    rm -f /tmp/pandare_${UBUNTU_VERSION}.deb

# Install libhc for hypercalls
RUN release_url=$(curl --fail --silent --show-error --location --retry 5 \
            --output /dev/null --write-out '%{url_effective}' \
            https://github.com/AndrewQuijano/libhc/releases/latest) && \
        LIBHC_VERSION=${release_url##*/} && \
        LIBHC_TAG=${LIBHC_VERSION#v} && \
        curl --fail --show-error --location --retry 5 \
            --output /tmp/libhc-dev_all.deb \
            "https://github.com/AndrewQuijano/libhc/releases/download/${LIBHC_VERSION}/libhc-dev_${LIBHC_TAG}_all.deb" && \
        apt-get -y install /tmp/libhc-dev_all.deb && \
        rm /tmp/libhc-dev_all.deb

#### Essentially same as install.sh
RUN rm -rf /tools/build && \
    mkdir -p /tools/build
RUN cmake -B"./tools/build" \
          -H"./tools" \
          -DCMAKE_INSTALL_PREFIX="/usr" \
          -DCMAKE_BUILD_TYPE=Release
RUN cmake --build "/tools/build" --target install --parallel "$(nproc)" --config Release

# Isolate LAVA's Python dependencies from Ubuntu-managed Python packages.
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-venv && \
    apt-get clean && \
    python3 -m venv /opt/lava-venv
ENV VIRTUAL_ENV=/opt/lava-venv
ENV PATH="/opt/lava-venv/bin:${PATH}"

# Install the pyroclastic package and fail the build if it is incomplete.
RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir . && \
    python3 -m pip show pyroclastic && \
    python3 -m pip check && \
    command -v lava lava-init && \
    python3 -c 'from importlib.resources import files; assert files("pyroclastic.data").joinpath("lava.sql").is_file()'

# RUN useradd volcana
# RUN chown -R volcana:volcana /tools/
# RUN chown -R volcana:volcana /scripts/
# USER volcana
