#!/usr/bin/env python

import json
import os
import sys

for d in json.load(open(os.path.join(sys.argv[1], 'compile_commands.json'))):
    print os.path.join(d['directory'], d['file'])
