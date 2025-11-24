import json
import os
from os.path import join


# processes compile_commands.json to remove duplicate entries and add extra entries

def process_compile_commands(cc_filename, extra_cc_filename):
    print('Processing compile_commands')
    with open(cc_filename, 'r') as cc_file:
        compile_commands = json.load(cc_file)
    
    file_set = set()
    new_compile_commands = []
    for f in compile_commands:
        if join(f['directory'], f['file']) not in file_set:
            file_set.add(join(f['directory'], f['file']))
            new_compile_commands.append(f)
    
    if os.path.isfile(extra_cc_filename):
        with open(extra_cc_filename, 'r') as extra_cc_file:
            extra_compile_commands = json.load(extra_cc_file)

        for f in extra_compile_commands:
            new_compile_commands.append(f)

    with open(cc_filename, 'w') as cc_file:
        json.dump(new_compile_commands, cc_file)


def get_c_files(bugs_build, cc_filename):
    with open(cc_filename, 'r') as cc_file:
        compile_commands = json.load(cc_file)
    
    c_files = set()
    for f in compile_commands:
        if not (bugs_build == f['directory']):
            c_files.add(os.path.join(os.path.basename(f['directory']), f['file']))
        else:
            c_files.add(f['file'])

    return c_files
