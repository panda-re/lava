import re
import sys

src = open(sys.argv[1]).read()

# split on ; first
parts = re.split(";", src)


def consume(i, text, consume_class):
    while text[i] in consume_class:
        i += 1
        if i == len(text):
            break
    return i

def consume_not(i, text, consume_class):
    while not (text[i] in consume_class):
        i += 1
        if i == len(text):
            break
    return i


whitespace = " \n\r\t"

for part in parts:
    i = 0
    # consume final } and or white space
    i = consume(0, part, "}"+whitespace)
    if ("if" == part[i:i+2]):
        pass
    else:
        # no if -- move on to next part
        print part + ";"
        continue
    before_if = part[:i]
    # consume whitespace
    i = consume(i+2, part, whitespace)
    # this must be a '('
    assert (part[i] == '(')
    paren_start = i
    level = 0
    while True:
        if part[i] == '(':
            level += 1
        if part[i] == ')':
            level -= 1
            if level == 0:
                break
        i += 1
    paren_end = i
    cond = part[paren_start+1:paren_end]
    # consume whitespace
    i = consume (i+1, part, whitespace)
    # if this isnt a brace
    if part[i] != '{':
        # consume everything that isnt ';'
        j = consume_not(i+1, part, ";")
        print "%sif (%s) { %s ; } " % (before_if, cond, part[i:j+2]),
    else:
        print "%sif (%s) %s ; " % (before_if, cond, part[i:]),
