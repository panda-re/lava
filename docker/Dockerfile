FROM pandare/panda

RUN apt-get install -y sudo build-essential mlocate \
        vim libc++-dev g++-multilib g++ ninja-build \
        jq bc cmake autoconf libtool zlib1g-dev \
        llvm-11-dev libclang-11-dev \
        libpq-dev

ENV release 11
ENV llvm_version llvm-${release}

WORKDIR /
RUN wget http://codesynthesis.com/download/odb/2.4/odb_2.4.0-1_amd64.deb
RUN dpkg -i odb_2.4.0-1_amd64.deb
#RUN wget http://codesynthesis.com/download/odb/2.4/odb-2.4.0.tar.gz
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
RUN pip install subprocess32 lockfile sqlalchemy==1.0.14 -i https://pypi.python.org/simple

RUN pip install pyyaml pycparser psycopg2
RUN updatedb

RUN echo "LLVM_DIR=/usr/lib/$llvm_version/lib/cmake/llvm" >> /etc/environment
RUN echo "LIBRARY_PATH=/usr/local/lib" >> /etc/environment

# Setting up remote Postgres(host) && PANDA Aux Packages
RUN apt-get install -y genisoimage postgresql-client-12
# pg_hba.conf:
# host    all             all             172.17.0.1/16            md5
# postgresql.conf:
# listen_addresses = 'localhost, 172.17.0.1'
