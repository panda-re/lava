protected int
file_encoding(struct magic_set *ms, ..., const char **type) {
...
   else if
     (({int rv = looks_extended(buf, nbytes, *ubuf, ulen);
       if (buf) {
         int lava = 0;
         lava |= ((unsigned char *) (buf))[0] << (0*8);
         lava |= ((unsigned char *) (buf))[1] << (1*8);
         lava |= ((unsigned char *) (buf))[2] << (2*8);
         lava |= ((unsigned char *) (buf))[3] << (3*8);
         lava_set(lava);
       }; rv;})) {
...

