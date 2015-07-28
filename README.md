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
experiments/tshark/README contains a detailed description of how to run each step of our tooling on one example (wireshark). But that takes forever and is very complicated. We have mostly automated scripts in the scripts directory:

scripts/add_queries.sh: Untars a tar file and builds it, tracing the execution with btrace. Then it automatically injects taint queries at every function call. This is a lot of code! The resulting instrumented project will take approximately forever to compile. But it's worth it. After adding queries, you will probably need to some manual munging to fix corner cases. Sorry.

scripts/bug_mining.py: Uses PANDA to collect an execution trace against a given input and then runs FBI against the resulting pandalog. 
