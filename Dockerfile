FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -qq -y \
    bc \
    build-essential \
    cmake \
    git \
    inotify-tools \
    jq \
    libfdt-dev \
    libjsoncpp-dev \
    libjsoncpp1 \
    libpq-dev \
    postgresql \
    python3-psycopg2 \
    python3-sqlalchemy \
    socat

RUN apt-get update && apt-get install -qq -y \
    wget


# Libodb
RUN cd /tmp && \
    wget http://codesynthesis.com/download/odb/2.4/odb_2.4.0-1_amd64.deb && \
    wget http://codesynthesis.com/download/odb/2.4/libodb-2.4.0.tar.gz && \
    wget http://codesynthesis.com/download/odb/2.4/libodb-pgsql-2.4.0.tar.gz && \
    dpkg -i odb_2.4.0-1_amd64.deb && \
    tar xf libodb-pgsql-2.4.0.tar.gz && \
    tar xf libodb-2.4.0.tar.gz && \
    cd /tmp/libodb-2.4.0 && \
    CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure --enable-shared && \
    make -j $(nproc) && \
    make install && \
    cd /tmp/libodb-pgsql-2.4.0 && \
    CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure --enable-shared && \
    make -j $(nproc) && \
    make install
# TODO in main container
#RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/usr-local-lib.conf
#RUN ldconfig

# Build btrace
COPY tools/btrace /tools/btrace
RUN cd /tools/btrace && \
    bash compile.sh

# Build lavaTool. Depends on headers in lavaODB
COPY tools/lavaODB /tools/lavaODB
COPY tools/lavaTool /tools/lavaTool
ENV LLVM_VERSION=11
RUN cd /tools/lavaTool && \
    echo "LLVM_VERSION=${LLVM_VERSION}" > config.mak && \
    cmake -Bbuild -H. -DCMAKE_INSTALL_PREFIX=/tools/install

RUN cd /tools/lavaTool/build && \
    make && \
    make install V=1