ARG BASE_IMAGE="ubuntu:22.04"
ARG PANDA_VERSION="v1.8.78"
ARG CAPSTONE_VERSION="5.0.5"

### BASE IMAGE
FROM $BASE_IMAGE AS base
ARG BASE_IMAGE
ARG PANDA_VERSION
ARG CAPSTONE_VERSION

ENV DEBIAN_FRONTEND=noninteractive
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
COPY ./dependencies/* /tmp
COPY . /

RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN [ -e /tmp/base_dep.txt ] && \
    apt-get -qq update -y && \
    apt-get -qq install -y --no-install-recommends curl $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
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
RUN LIBHC_VERSION=$(curl -s https://api.github.com/repos/AndrewQuijano/libhc/releases/latest | jq -r .tag_name) && \
    LIBHC_TAG=${LIBHC_VERSION#v} && \
    curl -LJ -o /tmp/libhc-dev_${LIBHC_TAG}_all.deb https://github.com/AndrewQuijano/libhc/releases/download/${LIBHC_VERSION}/libhc-dev_${LIBHC_TAG}_all.deb && \
    $SUDO apt-get -y install /tmp/libhc-dev_${LIBHC_TAG}_all.deb && \
    rm "/tmp/libhc-dev_${LIBHC_TAG}_all.deb"

RUN [ -e /tmp/build_dep.txt ] && \
    apt-get -qq update && \
    apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

#### Essentially same as install.sh
RUN rm -rf /tools/build && \
    mkdir -p /tools/build
RUN cmake -B"./tools/build" \
          -H"./tools" \
          -DCMAKE_INSTALL_PREFIX="/usr" \
          -DCMAKE_BUILD_TYPE=Release
RUN cmake --build "/tools/build" --target install --parallel "$(nproc)" --config Release

# Install the pyroclast package
RUN cd python \
    python3 -m pip install .

# RUN useradd volcana
# RUN chown -R volcana:volcana /tools/
# RUN chown -R volcana:volcana /scripts/
# USER volcana
