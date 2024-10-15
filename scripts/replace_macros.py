import sys
import shutil


def find_end(line, start_idx_off):
    open_parens = 1
    end_idx = 0
    for idx, char in enumerate(line[start_idx_off:]):
        if char == "(":
            open_parens += 1
        elif char == ")":
            open_parens -= 1

        if open_parens == 0:  # At the end of lava log
            end_idx = idx
            break
    return end_idx


def cleanup(line):
    while "LAVALOG(" in line:
        start_idx = line.index("LAVALOG(")  # start of LAVALOG
        start_idx_off = start_idx + len("LAVALOG(")  # After the LAVALOG(

        # asdf *LAVALOG(1234, LAVALOG(1234, value+valu+value, trigger1), trigger2) bsdf
        # asdf *LAVALOG(1234, value+valu+value, trigger1) bsdf
        # asdf *(value+valu+value) bsdf # TODO - do we have to add the parens?
        end_idx = find_end(line, start_idx_off)

        contents = line[start_idx_off:][:end_idx]

        # Now we have A, VAL...VAL, C
        first = contents.index(", ") + 2
        last = contents.rindex(", ")

        line = line[:start_idx] + contents[first:last] + line[start_idx_off + end_idx + 1:]

    while "DFLOG" in line:
        # DFLOG(115, *(const unsigned int *)ubuf);
        # data_flow[115] = *(const...;
        start_idx = line.index("DFLOG(")
        start_idx_off = start_idx + len("DFLOG(")
        end_idx = find_end(line, start_idx_off)

        contents = line[start_idx_off:][:end_idx]
        parts = contents.split(", ")
        assert (len(parts) == 2)
        contents = "data_flow[{}] = {}".format(parts[0], parts[1])

        line = line[:start_idx] + contents + line[start_idx_off + end_idx + 1:]

    return line


lava_macros = ["#ifdef LAVA_LOGGING", "#ifdef FULL_LAVA_LOGGING", "#ifndef LAVALOG", "#ifdef DUA_LOGGING"]
for filename in sys.argv[1:]:
    scratch = "/tmp/scratch.c"
    with open(filename) as infile:
        lines = infile.readlines()
        if not (len(lines) > 1 and lines[0] == "#ifdef LAVA_LOGGING\n"):
            print("{} is not a LAVALOG'd file".format(infile))
            continue  # No lavalogging here

        with open(scratch, "w") as outfile:
            # Skip past our definitions
            in_lava_macro = False
            for line in lines:
                for macro in lava_macros:
                    if macro in line:
                        in_lava_macro = True
                        break  # Break the macro loop, the in_lava_macro bool will continue

                if in_lava_macro:
                    if "#endif" in line:
                        in_lava_macro = False
                    continue

                if "LAVALOG(" not in line and "DFLOG(" not in line:
                    outfile.write(line)
                else:
                    outfile.write(cleanup(line))

    # os.rename(filename, filename+".bak")
    shutil.copy(scratch, filename)
