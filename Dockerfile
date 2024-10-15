ARG BASE_IMAGE="ubuntu:22.04"

### BASE IMAGE
FROM $BASE_IMAGE AS base
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
COPY ./tools/ /tools
COPY ./scripts/ /scripts

RUN mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_build.txt /tmp/build_dep.txt && \
    mv /tmp/$(echo "$BASE_IMAGE" | sed 's/:/_/g')_base.txt /tmp/base_dep.txt

# Base image just needs runtime dependencies
RUN [ -e /tmp/base_dep.txt ] && \
    apt-get -qq update && \
    apt-get -qq install -y --no-install-recommends curl $(cat /tmp/base_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

# Finally: Install panda debian package, you need a version that has the Dwarf2 Plugin
RUN curl -LJO https://github.com/panda-re/panda/releases/download/v1.8.23/pandare_22.04.deb
RUN mv ./pandare_22.04.deb /tmp
RUN apt install -qq -y /tmp/pandare_22.04.deb
RUN pip install -r /tmp/requirements.txt

### BUILD IMAGE - STAGE 2
RUN [ -e /tmp/build_dep.txt ] && \
    apt-get -qq update && \
    apt-get install -y --no-install-recommends $(cat /tmp/build_dep.txt | grep -o '^[^#]*') && \
    apt-get clean

RUN cd /tmp && \
    git clone https://github.com/capstone-engine/capstone/ -b v4 && \
    cd capstone/ && ./make.sh && make install && cd /tmp && \
    rm -rf /tmp/capstone && ldconfig

#### Develop setup: panda built + pypanda installed (in develop mode) - Stage 3
#### Essentially same as setup_container.sh
RUN cd /tools/btrace && ./compile.sh

RUN rm -rf /tools/build
RUN mkdir -p /tools/build
RUN mkdir -p /tools/install

RUN cmake -B"/tools/build" -H"/tools" -DCMAKE_INSTALL_PREFIX="/tools/install"
RUN make --no-print-directory -j4 install -C "/tools/build/lavaTool"
RUN make --no-print-directory -j4 install -C "/tools/build/fbi"

# We need 32-bit support inside the container for now
RUN dpkg --add-architecture i386 && apt-get update && apt-get -y install zlib1g-dev:i386 gcc-multilib

# RUN useradd volcana
# RUN chown -R volcana:volcana /tools/
# RUN chown -R volcana:volcana /scripts/
# USER volcana
