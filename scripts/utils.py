def bad_bin_search(args, fun):
    '''
    Given a list of items and a function that takes a list,
    do a binary search to remove all items that cause fun to fail

    Assumes args starts with > 1 element

    Returns a list of OK args
    '''
    if len(args) <= 1: # Already failed on this arg, don't retry it
        return []

    mid = len(args)/2
    left = args[:mid]
    right = args[mid:]

    if len(left):
        try: # If left still fails, reduce farther
            fun(left)
        except (AssertionError, RuntimeError):
            left = bad_bin_search(left, fun)

    if len(right):
        try: # If right still fails, reduce farther
            fun(right)
        except (AssertionError, RuntimeError):
            right = bad_bin_search(right, fun)

    return left + right

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
