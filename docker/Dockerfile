FROM m4mbr3/lava32

MAINTAINER ricky

WORKDIR /home/lava

RUN apt-get update
RUN apt-get install -y --force-yes gcc bzip2 bison flex libglib2.0-dev libpcap-dev make
RUN wget https://www.wireshark.org/download/src/all-versions/wireshark-1.8.2.tar.bz2
RUN tar -xvf wireshark-1.8.2.tar.bz2
WORKDIR wireshark-1.8.2
RUN ./configure --disable-warnings-as-errors --enable-editcap=no \
--enable-capinfos=no --enable-mergecap=no --enable-text2pcap=no \
--enable-dftest=no --enable-randpkt=no --enable-airpcap=no \
--enable-dumpcap=no --enable-rawshark=no --enable-wireshark=no
RUN make -j32
