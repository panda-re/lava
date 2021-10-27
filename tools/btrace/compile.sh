
dir=`dirname $0`
cd $dir

gcc -std=c99 -D_POSIX_SOURCE -D_GNU_SOURCE -fPIC -shared btrace.c btrace_linux.c -o libsw-btrace.so
mkdir -p ../libexec
cp lib* ../libexec
