# Magmalyze
This package works with LAVA to generate new random based inputs. 
For exploration techniques, we used Angr perform concolic execution and utilize [KLEE's random path exploration](https://github.com/degrigis/awesome-angr/blob/main/ExplorationTechniques/KLEERandomSearch/KLEERandomSearch.py).

## Code Coverage
An important aspect of generating new inputs is to measure code coverage. This package uses `coverage.py` to measure code coverage of the C/C++ programs.

To get code coverage for a specific LAVA project, run the following:
```bash
lava-coverage -p <project_name>
```

It will utilize llvm-cov to get code coverage for your project based on the inputs in the `target_configs/<project_name>/inputs` directory.

## Generating new inputs, utilizing concolic execution
An issue about LAVA is that bugs are only injected based on the provided inputs. A [suggestion](https://dspace.mit.edu/bitstream/handle/1721.1/145988/3433210.3453096.pdf?sequence=1) 
was to investigate how to get LAVA to inject bugs outside the "main path". We utilize Angr, using KLEE's random search algorithm to get off the "main path", and plant bug in less frequently tested code. 
This improves bug realism, as bugs are more likely to exist in sparsely tested code.


```bash
magmalyze 
```
