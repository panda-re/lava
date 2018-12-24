
What do the numbers that appear in the db tables attackpoint and bug in the type column mean?
They are defined in two places, lava.py and lava.hxx.


attackpoint types:

0: FUNCTION_ARG  (an arg to a fn)
1: POINTER_READ  (read via ptr)
2: POINTER_WRITE (write via ptr)
3: QUERY_POINT   (is this the sentinels ricky puts in after every stmt?)
4: PRINTF_LEAK   (really just a printf)

bug types:

0: PTR_ADD       (corrupt a pointer at attack point)
1: RET_BUFFER    (stack pivot)
2: REL_WRITE     (I think this is a write-what-where)
3: PRINTF_LEAK   (turn printf into a stack / heap leak)