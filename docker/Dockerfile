FROM i386/debian:stretch
RUN echo deb http://archive.debian.org/debian wheezy-backports main >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y sudo build-essential python wget cmake gdb gawk mlocate \
            vim libc++-dev  g++-multilib g++ ninja-build \
            git jq bc python python-colorama zsh libjsoncpp-dev \
            python-psycopg2 python-pexpect python-psutil \
            python-numpy python-argparse python-pip python-dev libpq-dev
ENV release 3.6.2
ENV llvm_version llvm-${release}

RUN wget http://llvm.org/releases/$release/$llvm_version.src.tar.xz
RUN tar -xJf $llvm_version.src.tar.xz

RUN mv $llvm_version.src $llvm_version
RUN cd $llvm_version

WORKDIR /$llvm_version/tools
ENV clang_version cfe-$release
RUN wget http://llvm.org/releases/$release/$clang_version.src.tar.xz
RUN tar -xJf $clang_version.src.tar.xz
RUN mv $clang_version.src clang

WORKDIR /$llvm_version/tools/clang/tools
RUN wget http://llvm.org/releases/$release/clang-tools-extra-$release.src.tar.xz
RUN tar -xJf clang-tools-extra-$release.src.tar.xz
RUN mv clang-tools-extra-$release.src extra

WORKDIR /$llvm_version
#RUN ./configure --enable-optimized --disable-assertions --enable-targets=x86 --enable-shared --enable-pic --host=i486-linux-gnu --build=i486-linux-gnu
RUN mkdir /$llvm_version/build
RUN mkdir /$llvm_version/Release
WORKDIR /$llvm_version/build
RUN cmake ../ -DCMAKE_INSTALL_PREFIX=/$llvm_version/Release -DLLVM_TARGETS_TO_BUILD=X86 \
              -DBUILD_SHARED_LIBS=true -DLLVM_ENABLE_ASSERTIONS=false -DLLVM_ENABLE_RTTI=true \
              -DLLVM_BUILD_32_BITS=true \
              -DLLVM_ENABLE_PIC=true -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGET_ARCH=i486-linux-gnu \
              -G "Ninja"
RUN ninja install

WORKDIR /
RUN wget http://codesynthesis.com/download/odb/2.4/odb_2.4.0-1_i386.deb
RUN dpkg -i odb_2.4.0-1_i386.deb
RUN wget http://codesynthesis.com/download/odb/2.4/libodb-2.4.0.tar.gz
RUN tar xf libodb-2.4.0.tar.gz
WORKDIR /libodb-2.4.0
RUN ./configure --enable-shared && make -j $(nproc) && make install
WORKDIR /
RUN wget http://codesynthesis.com/download/odb/2.4/libodb-pgsql-2.4.0.tar.gz
RUN tar xf libodb-pgsql-2.4.0.tar.gz
WORKDIR /libodb-pgsql-2.4.0
RUN ./configure --enable-shared && make -j $(nproc) && make install

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/usr-local-lib.conf
RUN ldconfig

RUN pip install --upgrade -v pip -i https://pypi.python.org/simple/
RUN pip install subprocess32 lockfile sqlalchemy -i https://pypi.python.org/simple

RUN pip install pyyaml
RUN ln -s /usr/lib/libjsoncpp.so.0 /usr/lib/libjsoncpp.so.1
RUN updatedb

RUN echo "LLVM_DIR=/$llvm_version/Release/share/llvm/cmake" >> /etc/environment
RUN echo "LD_LIBRARY_PATH=/$llvm_version/Release/lib" >> /etc/environment
RUN echo "LIBRARY_PATH=/usr/local/lib" >> /etc/environment
RUN echo "PATH=$PATH:/$llvm_version/Release/bin" >> /etc/environment

RUN apt-get install -y sudo gdb gawk zlib1g-dev

# Set locale to C.UTF-8 instead of us_EN.UTF-8
RUN apt-get install -y locales
RUN locale-gen C.UTF-8
RUN locale -a
RUN update-locale LANG=C.UTF-8

# Having autoconf in the container will make building autotools packages easier
RUN apt-get install -y autoconf libtool m4 automake
