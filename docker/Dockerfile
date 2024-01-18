FROM debian:stretch
RUN echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220630T220025Z/ stretch main" > /etc/apt/sources.list
RUN echo "deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220630T220025Z/ stretch main" >> /etc/apt/sources.list
RUN echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220630T220025Z/ stretch-updates main" >> /etc/apt/sources.list
RUN echo "deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220630T220025Z/ stretch-updates main" >> /etc/apt/sources.list
RUN echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220630T220025Z/ stretch-backports main" >> /etc/apt/sources.list
RUN echo "deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian/20220630T220025Z/ stretch-backports main" >> /etc/apt/sources.list
RUN apt-get update && apt-get -y dist-upgrade && \
    apt-get remove -y libnettle6 libelf1 && \
    apt-get install -y --allow-downgrades zlib1g=1:1.2.8.dfsg-5 && \
    apt-get autoremove -y
RUN apt-get install -y sudo build-essential python wget cmake gdb gawk mlocate \
            vim libc++-dev  g++-multilib g++ ninja-build \
            git jq bc python python-colorama zsh \
            python-pexpect python-psutil \
            python-numpy python-argparse python-pip python-dev libpq-dev \
            sudo gdb gawk zlib1g-dev autoconf libtool pkg-config locales \
            genisoimage postgresql-client-9.6 \
            libglib2.0-dev libpixman-1-dev groff-base libdwarf-dev libcapstone-dev wireshark-dev libelf-dev \
            flex bison
ENV release 3.6.2
ENV llvm_version llvm-${release}

RUN wget --no-check-certificate https://llvm.org/releases/$release/$llvm_version.src.tar.xz
RUN tar -xJf $llvm_version.src.tar.xz

RUN mv $llvm_version.src $llvm_version
RUN cd $llvm_version

WORKDIR /$llvm_version/tools
ENV clang_version cfe-$release
RUN wget --no-check-certificate https://llvm.org/releases/$release/$clang_version.src.tar.xz
RUN tar -xJf $clang_version.src.tar.xz
RUN mv $clang_version.src clang

WORKDIR /$llvm_version/tools/clang/tools
RUN wget --no-check-certificate https://llvm.org/releases/$release/clang-tools-extra-$release.src.tar.xz
RUN tar -xJf clang-tools-extra-$release.src.tar.xz
RUN mv clang-tools-extra-$release.src extra

WORKDIR /$llvm_version
#RUN ./configure --enable-optimized --disable-assertions --enable-targets=x86 --enable-shared --enable-pic --host=i486-linux-gnu --build=i486-linux-gnu
RUN mkdir /$llvm_version/build
RUN mkdir /$llvm_version/Release
WORKDIR /$llvm_version/build
RUN cmake ../ -DCMAKE_INSTALL_PREFIX=/$llvm_version/Release -DLLVM_TARGETS_TO_BUILD=X86 \
              -DBUILD_SHARED_LIBS=true -DLLVM_ENABLE_ASSERTIONS=false -DLLVM_ENABLE_RTTI=true \
#-DLLVM_BUILD_32_BITS=true \
              -DLLVM_ENABLE_PIC=true -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGET_ARCH=i486-linux-gnu \
              -DCMAKE_CXX_FLAGS="-D_GLIBCXX_USE_CXX11_ABI=0" \
              -G "Ninja"
RUN ninja install

WORKDIR /
RUN wget http://codesynthesis.com/download/odb/2.4/odb_2.4.0-1_amd64.deb
RUN dpkg -i odb_2.4.0-1_amd64.deb
#RUN wget http://codesynthesis.com/download/odb/2.4/odb-2.4.0.tar.gz
RUN wget http://codesynthesis.com/download/odb/2.4/libodb-2.4.0.tar.gz
RUN tar xf libodb-2.4.0.tar.gz
WORKDIR /libodb-2.4.0
RUN CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure --enable-shared && make -j $(nproc) && make install
WORKDIR /
RUN wget http://codesynthesis.com/download/odb/2.4/libodb-pgsql-2.4.0.tar.gz
RUN tar xf libodb-pgsql-2.4.0.tar.gz
WORKDIR /libodb-pgsql-2.4.0
RUN CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure --enable-shared && make -j $(nproc) && make install

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/usr-local-lib.conf
RUN ldconfig

RUN pip install --upgrade -v pip -i https://pypi.python.org/simple/
RUN pip install subprocess32 lockfile sqlalchemy==1.0.14 -i https://pypi.python.org/simple

RUN pip install pyyaml pycparser psycopg2
RUN updatedb

RUN echo "LLVM_DIR=/$llvm_version/Release/share/llvm/cmake" >> /etc/environment
RUN echo "LD_LIBRARY_PATH=/$llvm_version/Release/lib" >> /etc/environment
RUN echo "LIBRARY_PATH=/usr/local/lib" >> /etc/environment
RUN echo "PATH=$PATH:/$llvm_version/Release/bin" >> /etc/environment

RUN apt-get install -y sudo gdb gawk zlib1g-dev autoconf libtool pkg-config

# Set locale to C.UTF-8 instead of us_EN.UTF-8
RUN apt-get install -y locales
RUN locale-gen C.UTF-8
RUN locale -a
RUN update-locale LANG=C.UTF-8

# Install libjsoncpp
WORKDIR /
RUN wget https://github.com/open-source-parsers/jsoncpp/archive/refs/tags/1.7.4.tar.gz
RUN tar -xzf 1.7.4.tar.gz
WORKDIR jsoncpp-1.7.4
RUN cmake -DCMAKE_CXX_FLAGS="-D_GLIBCXX_USE_CXX11_ABI=0" . && make -j && make install && ldconfig

# Install protobuf
WORKDIR /
RUN git clone https://github.com/protocolbuffers/protobuf.git
WORKDIR protobuf
RUN git checkout 3.6.x
RUN ./autogen.sh && CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure && make -j $(nproc) && make install && ldconfig
WORKDIR /
RUN wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.3.1/protobuf-c-1.3.1.tar.gz && tar -xzf protobuf-c-1.3.1.tar.gz
WORKDIR protobuf-c-1.3.1
RUN CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure && make -j $(nproc) && make install && ldconfig

# Setup PANDA
RUN apt-get install -y libglib2.0-dev libpixman-1-dev groff-base libdwarf-dev libcapstone-dev wireshark-dev libelf-dev flex bison
WORKDIR /
RUN wget https://releases.llvm.org/3.3/llvm-3.3.src.tar.gz
RUN tar -xzf llvm-3.3.src.tar.gz
RUN wget https://releases.llvm.org/3.3/cfe-3.3.src.tar.gz
RUN tar -xzf cfe-3.3.src.tar.gz && mv cfe-3.3.src /llvm-3.3.src/tools/clang
WORKDIR /llvm-3.3.src
RUN CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' ./configure --prefix=/llvm-3.3-install && make -j $(nproc) && make install

# Setting up remote Postgres(host) && PANDA Aux Packages
RUN apt-get install -y genisoimage postgresql-client-9.6
# pg_hba.conf:
# host    all             all             172.17.0.1/16            md5
# postgresql.conf:
# listen_addresses = 'localhost, 172.17.0.1'
