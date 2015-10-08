...
protected int
file_trycdf(struct magic_set *ms, 
            ..., size_t nbytes) {
  ...
  if (cdf_read_header
      (( (&info)) + (lava_get()) 
       * (0x6c617661 == (lava_get())
          || 0x6176616c == (lava_get())), &h) == -1)
    return 0;

