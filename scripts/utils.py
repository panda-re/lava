def bad_bin_search(args, fun, depth=0):
    '''
    Given a list of items and a function that takes a list,
    do a binary search to remove all items that cause fun to fail

    Assumes args starts with > 1 element

    XXX: Runs out of memory if you have lots of failures and ~1000 or more bugs to test

    Returns a list of OK args
    '''
    if len(args) <= 1: # Already failed on this arg, don't retry it
        print("Identified bad bug: {}".format(args[0]))
        return []

    mid = len(args)/2
    left = args[:mid]
    right = args[mid:]

    if len(left):
        try: # If left still fails, reduce farther
            res = fun(left)
            if not len(res): raise RuntimeError("Recurse")
            left = res
        except (AssertionError, RuntimeError):
            left = bad_bin_search(left, fun, depth+1)

    if len(right):
        try: # If right still fails, reduce farther
            #right = fun(right)
            res = fun(right)
            if not len(res): raise RuntimeError("Recurse")
            right = res
        except (AssertionError, RuntimeError):
            right = bad_bin_search(right, fun, depth+1)

    #return left + right
    both =  left + right
    return both

if __name__ == "__main__":
    def test_fn(l):
        for item in l:
            if item % 3 == 0:
                raise RuntimeError("Test_fn: no factors of 3 allowed")
        return l

    orig_list = [1,2,3,4,5,6,7,8,9]
    r = bad_bin_search(orig_list, test_fn)
    assert (r == [1,2,4,5,7,8]), "bad_bin_search is broken"

    print("All utility tests pass")
