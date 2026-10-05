/* ftlava.c - minimal command-line driver for LAVA bug injection.
 * Loads a font file given as argv[1] and renders every glyph,
 * mirroring the coverage of the standard FreeType fuzz harness
 * (FT_New_Memory_Face + FT_Load_Glyph over all glyph indices / character sizes).
 *
 * The font is read with fread() and handed to FT_New_Memory_Face, as
 * ftfuzzer does. FT_New_Face mmaps the file, and PANDA's file_taint only
 * labels bytes that come in through read(), so with FT_New_Face the taint
 * step saw no tainted data at all.
 *
 * freetype2.tar.gz ships no CLI tool that parses a bare font file, and the
 * upstream tarball is kept byte-identical to the linked release for
 * provenance, so this file is not added to the tarball. freetype2.json's
 * "pre_make" copies it into the extracted source tree (cp -n, so an
 * instrumented copy is never clobbered by a later configure), "make"
 * compiles it, and "install" copies the binary to {install_dir}/bin/ftlava.
 */
#include <stdio.h>
#include <stdlib.h>
#include <ft2build.h>
#include FT_FREETYPE_H

int main(int argc, char **argv)
{
    FT_Library library;
    FT_Face face;
    FT_Error error;
    FT_ULong i;
    FILE *fp;
    long size;
    unsigned char *data;

    if (argc < 2) {
        fprintf(stderr, "usage: %s font-file\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) {
        fprintf(stderr, "empty or unreadable font file\n");
        fclose(fp);
        return 1;
    }
    data = (unsigned char *) malloc(size);
    if (!data || fread(data, 1, size, fp) != (size_t) size) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        fclose(fp);
        free(data);
        return 1;
    }
    fclose(fp);

    error = FT_Init_FreeType(&library);
    if (error) {
        fprintf(stderr, "FT_Init_FreeType failed: %d\n", error);
        free(data);
        return 1;
    }

    /* data must stay allocated until FT_Done_Face */
    error = FT_New_Memory_Face(library, data, (FT_Long) size, 0, &face);
    if (error) {
        fprintf(stderr, "FT_New_Memory_Face failed: %d\n", error);
        FT_Done_FreeType(library);
        free(data);
        return 1;
    }

    error = FT_Set_Char_Size(face, 16 * 64, 16 * 64, 100, 100);
    if (error) {
        fprintf(stderr, "FT_Set_Char_Size failed: %d\n", error);
    }

    for (i = 0; i < (FT_ULong) face->num_glyphs; i++) {
        error = FT_Load_Glyph(face, i, FT_LOAD_DEFAULT);
        if (error)
            continue;

        if (face->glyph->format == FT_GLYPH_FORMAT_OUTLINE)
            FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);
    }

    FT_Done_Face(face);
    FT_Done_FreeType(library);
    free(data);

    return 0;
}
