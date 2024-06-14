FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -qq -y \
    bc \
    build-essential \
    clang-tools-11 \
    cmake \
    git \
    inotify-tools \
    jq \
    libclang-11-dev \
    libfdt-dev \
    libjsoncpp-dev \
    libjsoncpp1 \
    libpq-dev \
    llvm-11-dev \
    postgresql \
    python3-psycopg2 \
    python3-sqlalchemy \
    socat \
    wget

# Step 1: Install panda debian package, you need a version that has Dwarf2 Plugin
RUN wget https://github.com/panda-re/panda/releases/download/v1.8.23/pandare_20.04.deb
RUN command apt install -qq -y ./pandare_20.04.deb
RUN pip install pandare

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

# Build lavaTool. Depends on headers in lavaODB and tools/lavaDB
#COPY tools/lavaODB/ tools/lavaDB/ tools/lavaTool/ /tools/
COPY tools/ /tools
COPY setup_container.py /
ENV LLVM_DIR=/usr/lib/llvm-11
RUN python3 setup_container.py

# RUN cd /tools && \
#    cmake -Bbuild -H. -DLLVM_DIR=$LLVM_DIR/lib/cmake/llvm -DClang_DIR=$LLVM_DIR/lib/cmake/clang -DCMAKE_INSTALL_PREFIX=/tools/install

# RUN cd /tools/build && \
#    make && \
#    make install V=1