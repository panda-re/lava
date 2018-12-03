# TESTING

Running `./test.sh` will run each step of Lava for each project in `../target_configs`
Results will be saved into `./results.txt`


# Current issues:
* Single threaded
* Simple validation (Passing just means the script ended happily, not that the generated output is correct)
* Must be run from within the tests directory
