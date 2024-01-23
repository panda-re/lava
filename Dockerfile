ARG BASE_REPO=pandare/panda
ARG TAG=latest

FROM ${BASE_REPO}:${TAG}

# From this point, I can imagine, everything up to 'install_ubuntu.sh' is already done.

# Copy the Python requirements

RUN mkdir /lava
ADD . /lava
WORKDIR /lava

RUN chmod +x install.sh
# RUN install.sh
