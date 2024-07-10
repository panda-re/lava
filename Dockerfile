ARG BASE_IMAGE="ubuntu:22.04"

### BASE IMAGE
FROM $BASE_IMAGE as base
ARG BASE_IMAGE

ENV DEBIAN_FRONTEND=noninteractive
ENV LLVM_DIR=/usr/lib/llvm-11
ENV PATH="/scripts:${PATH}"
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

# Copy dependencies lists into container. We copy them all and then do a mv because
# we need to transform base_image into a windows compatible filename which we can't
# do in a COPY command.
COPY ./dependencies/* /tmp
COPY ./requirements.txt /tmp

RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN [ -e /tmp/base_dep.txt ] && \
    apt-get -qq update && \
    apt-get -qq install -y --no-install-recommends curl $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

# Finally: Install panda debian package, you need a version that has the Dwarf2 Plugin
RUN curl -LJO https://github.com/panda-re/panda/releases/download/v1.8.23/pandare_22.04.deb
RUN apt install -qq -y ./pandare_22.04.deb
RUN pip install -r /tmp/requirements.txt

### BUILD IMAGE - STAGE 2
FROM base AS builder
ARG BASE_IMAGE

RUN [ -e /tmp/build_dep.txt ] && \
    apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
FROM builder as developer

COPY ./tools/ /tools
COPY ./scripts /scripts

# Essentially same as setup_container.sh
RUN cd /tools/btrace && ./compile.sh

RUN rm -rf /tools/build
RUN mkdir -p /tools/build
RUN mkdir -p /tools/install

RUN cmake -B"/tools/build" -H"/tools" -DCMAKE_INSTALL_PREFIX="/tools/install"
RUN make --no-print-directory -j4 install -C "/tools/build/lavaTool"

RUN make --no-print-directory -j4 install -C "/tools/build/fbi"
