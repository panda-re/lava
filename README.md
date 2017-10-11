Source to Source Transformations
================================

LAVA works by transforming the source of C programs. There are a few basic steps to the process. The idea is that we are looking for input data that does not influence program execution very much (not used in branches). We call this data "dead". We can induce fake dataflow and use dead data to trigger bugs at later program points (we call them "attack points"). But the data needs to be dead, "uncomplicated", and available at the attack point (DUA). Here's how you use our tool:

# Compile a program with inserted taint queries at every function call. These taint queries will allow us to link the source-level information to binary-level information, much like debug symbols do.
# Use PANDA to run the instrumented program on a sample input. The taint queries will record what source variables correspond to tainted data while the program is executing.
# PANDA will record the data to a "pandalog" file. Use our "find_bug_inj" program (aka FBI) to find injectable bugs from the pandalog.
# FBI will put data on injectable bugs into a Postgres database. You can run FBI multiple times on different inputs; the database will automatically reject duplicate bugs.
# inject.py automates the process of actually injecting the bugs and testing whether it actually works (i.e. the program segfaults or otherwise fails when we try to trigger the bug).


Instructions
===========
Read SETUP.md. Currently only works with an old version of PANDA (specifically commit 8724ddf7100f79db9528ade0481d6e8b002af67c).

