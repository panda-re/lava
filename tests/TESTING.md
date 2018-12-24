# TESTING

Run `./test.sh toy` to test LAVA on your `toy` target configured in `../target_configs/toy/toy.json`. Results will be printed to stdout.

Run `./test_all.sh` to run each step of LAVA for each project in `../target_configs`. Results will be saved into `./results.txt`


# Current issues:
* Single threaded
* Simple validation (Passing just means the script ended happily, not that the generated output is correct)
* Must be run from within the tests directory
