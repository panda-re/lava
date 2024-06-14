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
ENV LLVM_DIR=/usr/lib/llvm-11
RUN cd /tools && \
    cmake -Bbuild -H. -DLLVM_DIR=$LLVM_DIR/lib/cmake/llvm -DClang_DIR=$LLVM_DIR/lib/cmake/clang -DCMAKE_INSTALL_PREFIX=/tools/install

RUN cd /tools/build && \
    make && \
    make install V=1