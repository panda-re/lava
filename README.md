# LAVA: Large Scale Automated Vulnerability Addition

Evaluating and improving bug-finding tools is currently difficult due to
a shortage of ground truth corpora (i.e., software that has known bugs
with triggering inputs). LAVA attempts to solve this problem by
automatically injecting bugs into software. Every LAVA bug is
accompanied by an input that triggers it whereas normal inputs are
extremely unlikely to do so. These vulnerabilities are synthetic but, we
argue, still realistic, in the sense that they are embedded deep within
programs and are triggered by real inputs. Our work forms the basis of
an approach for generating large ground-truth vulnerability corpora on
demand, enabling rigorous tool evaluation and providing a high-quality
target for tool developers.

LAVA is the product of a collaboration between MIT Lincoln Laboratory,
NYU, and Northeastern University.

# Quick Start

On a system running Ubuntu 16.04, you should be able to just do `python
setup.py`. Note that this install script is fairly invasive (i.e., it
will install lots of packages and make changes to your system). Once it
finishes, you should have a `panda/build/` directory (LAVA uses
[PANDA](https://github.com/panda-re/panda) with a PANDA install to perform
dynamic taint analysis).

Next, run `init-host.py` to generate a host.json file.
This creates a `host.json` file used by LAVA that describes settings specific
to your host machine. You can edit these settings as necessary, but the default
values should work.

Project configurations are located in the `target_configs` directory, where
every configuration is located at `target_configs/projectname/projectname.json`.
These scripts reference paths relative to values set in your `host.json` file.

Finally, you can run `scripts/lava.sh` to actually inject bugs
into a program. The simplest way to invoke it is to tell it to carry
out all steps (`-a`) and delete old files/directores as needed (`-k`).
After the flags, you should specify a project name in the `target_configs` directory

```
scripts/lava.sh -ak toy
```

You should now have a buggy copy of toy!

Of course, it's rarely this easy. You will likely have to tweak the
build scripts for your program to ensure everything works well with
LAVA.

# Documentation

Check out the [docs](docs/) folder to get started.

# Authors

LAVA is the result of several years of development by many people; a
partial (alphabetical) list of contributors is below:

* Andy Davis
* Brendan Dolan-Gavitt
* Andrew Fasano
* Zhenghao Hu
* Patrick Hulin
* Amy Jiang
* Engin Kirda
* Tim Leek
* Andrea Mambretti
* Wil Robertson
* Aaron Sedlacek
* Rahul Sridhar
* Frederick Ulrich
* Ryan Whelan
