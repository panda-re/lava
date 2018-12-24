#!/bin/bash

# We're forgetting to add data_flow to these two functions which are used as function
# pointers, so the mistake is missed at compile-time and causes a runtime crash
sed -i -e 's/yaml_write_handler_t(void/yaml_write_handler_t(int* data_flow, void/g' $1/src/*.c
sed -i -e 's/yaml_read_handler_t(void/yaml_read_handler_t(int* data_flow, void/g' $1/src/*.c
