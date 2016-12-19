FROM m4mbr3/lava32

RUN echo deb http://httpredir.debian.org/debian wheezy-backports main >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y build-essential python

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
RUN ./configure --enable-optimized --disable-assertions --enable-targets=x86,arm --enable-shared --enable-pic --host=i486-linux-gnu --build=i486-linux-gnu
RUN REQUIRES_RTTI=1 make -j $(nproc)

RUN apt-get install -y git jq bc python python-colorama zsh libjsoncpp-dev \
    python-sqlalchemy python-psycopg2 python-pexpect python-psutil \
    python-numpy python-argparse python-pip python-dev libpq-dev

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

RUN pip install subprocess32 lockfile
