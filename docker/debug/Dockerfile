FROM lava32

RUN apt-get update
RUN apt-get -y install locales

RUN echo en_US.UTF-8 UTF-8 | tee /etc/locale.gen
RUN locale-gen

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US
ENV LC_ALL en_US.utf8

RUN apt-get -y install sudo gdb vim emacs exuberant-ctags hexedit

WORKDIR /$llvm_version
RUN ./configure --disable-optimized --enable-assertions --enable-targets=x86 --enable-shared --enable-pic --host=i486-linux-gnu --build=i486-linux-gnu
RUN REQUIRES_RTTI=1 make -j $(nproc)
