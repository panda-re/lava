Introduction
============

This a compilation of memory related bugs.  The intent of this list is to address the question of realism in LAVA.  Primarily, we are looking to see if these bugs result from a usage of data that is "dead."

Bugs
====

Data was gathered from https://nvd.nist.gov and https://cve.mitre.org/

Wireshark
---------
* CVE 2011-1591 - 1.4.x before 1.4.5 - DECT dissector in epan
* CVE 2011-0024 - 1.2 - Heap overflow in pcapng.c
* CVE 2011-0444 - 1.2-1.2.13 and 1.4.2 - Oveflow in packet-mac-lte.c
* CVE 2010-4538 - 1.4.2 - Buffer overflow in sect_enttec_dmx_da packet -enttec.c
* CVE 2012-4297 - 1.6.x and 1.8.x - packet-gsm_rlcmac.c
* CVE 2014-4174 - 1.10.x before 1.10.4 - memory corruption in libpcap file parser in libpcap.c 
* CVE 2015-2188 - 1.10.x before 1.10.13 and 1.12.x before 1.12.4 - out-of-bounds read from failure to initialize a data structure.  In epan/dissectors/packet-wcp.c.
* CVE 2015-0562 - 1.10.x before 1.10.12 and 1.12.x before 1.12.3 - Multiple use-after-free vuln in epan/dissectors/packet-dec-dnart.c in DEC DNA routing protocol dissector

Binutils
--------
* CVE 2005-1704 - gdb < 6.3 - Integer overflow in BFD
* CVE 2005-4807 - binutils < 2.15.97 - as_bad() in messages.c
    *   Uses vsprintf to copy data to a fixed length buffer (2000 bytes) without any bounds checks.  This area of the code is only accessed during error functions.
* CVE 2006-2362 - binutils < 2.15.96  - strings, tekhex.c
    *   Look at /corpora/test.tek for sample tektronix file 
    *   \_hex\_bad (defined as 99) is assigned to len in getsym() when invalid hex characters are put in length fields in .tek format
* CVE 2014-8485 - binutils < 2.24 - setup_group() in bfd/elf.c
* CVE 2014-8503 - binutils < 2.24 - ihex_scan() in bfd/ihex.c
* CVE 2014-8504 - binutils < 2.24 - stack based buffer overflow in srec_scan() in bfd/srec.c
* CVE 2012-3509 - binutils < 2.22 - allow remote attackers to cause a denial of service 

OpenSSH
-------
* CVE 2003-0695 - <3.7.1 - buffer_init() buffer.c, buffer_free() in channels.c
* CVE 2003-0693 - <3.7 - buffer_append_space() in buffer.c
* CVE 2002-0640 - 2.3.1-3.3.0 - sshd buffer overflow PAMAuthenticationViaKdbInt

Eye of Gnome
------------
* libpng
  *   CVE 2015-0973 - < 1.5.21 and 1.6.x before 1.6.16 - buffer overflow in png_read_IDAT_data() in pngrutil.c buffer
  *   CVE 2010-1205 - < 1.2.44 and 1.4.x before 1.4.3  - buffer overflow in pngread.c
  *   CVE 2006-3334 - < 1.2.12 - buffer overflow in png_decompress_chunk() in pngrutil.c
* libjpeg
  *   CVE 2012-2845 - exif 0.6.20 - Integer overflow in jpeg_data_load_data() in jpeg-data.c
