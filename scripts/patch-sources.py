#!/usr/bin/python
import os
import sys
import shutil
import tempfile

def modify_sources_list():
    def replacer_fn(line):
        return line.replace("# deb-src", "deb-src").replace("#deb-src", "deb-src")

    t = tempfile.mktemp()
    with open("/etc/apt/sources.list") as in_file:
        with open(t, "w") as out_file:
            new_lines = map(replacer_fn, (line for line in in_file))
            out_file.write("\n".join(new_lines))

    shutil.copy(t, "/etc/apt/sources.list")
    os.remove(t)

if __name__ == "__main__":
    if os.getuid() != 0:
        print "Must run {} as sudo or root".format(sys.argv[0])
        exit(1)
    modify_sources_list()
