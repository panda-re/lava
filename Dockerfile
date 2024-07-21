ARG BASE_IMAGE="ubuntu:22.04"
ARG PANDA_VERSION="v1.8.58"
ARG CAPSTONE_VERSION="5.0.5"

### BASE IMAGE
FROM $BASE_IMAGE AS base
ARG BASE_IMAGE
ARG PANDA_VERSION
ARG CAPSTONE_VERSION

ENV DEBIAN_FRONTEND=noninteractive
ENV LLVM_DIR=/usr/lib/llvm-11
ENV PATH="/scripts:${PATH}"
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
COPY ./dependencies/* /tmp
COPY ./requirements.txt /tmp
COPY ./tools/ /tools
COPY ./scripts/ /scripts

RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN [ -e /tmp/base_dep.txt ] && \
    apt-get -qq update && \
    apt-get -qq install -y --no-install-recommends curl $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

RUN cd /tmp && \
    curl -LJO https://github.com/capstone-engine/capstone/releases/download/${CAPSTONE_VERSION}/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb && \
    dpkg -i /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb && \
    rm -rf /tmp/libcapstone-dev_${CAPSTONE_VERSION}_amd64.deb

# Finally: Install panda debian package, you need a version that has the Dwarf2 Plugin
RUN cd /tmp && \
    UBUNTU_VERSION=$(echo "$BASE_IMAGE" | awk -F':' '{print $2}') && \
    curl -LJO https://github.com/panda-re/panda/releases/download/${PANDA_VERSION}/pandare_${UBUNTU_VERSION}.deb && \
    apt-get install -qq -y /tmp/pandare_${UBUNTU_VERSION}.deb
RUN pip install -r /tmp/requirements.txt

### BUILD IMAGE - STAGE 2
RUN [ -e /tmp/build_dep.txt ] && \
    apt-get -qq update && \
    apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
#### Essentially same as setup_container.sh
RUN cd /tools/btrace && ./compile.sh

RUN rm -rf /tools/build
RUN mkdir -p /tools/build
RUN mkdir -p /tools/install

RUN cmake -B"/tools/build" -H"/tools" -DCMAKE_INSTALL_PREFIX="/tools/install"
RUN make --no-print-directory -j4 install -C "/tools/build/lavaTool"
RUN make --no-print-directory -j4 install -C "/tools/build/fbi"

# RUN useradd volcana
# RUN chown -R volcana:volcana /tools/
# RUN chown -R volcana:volcana /scripts/
# USER volcana
