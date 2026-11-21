"""Support the compiler-capture and source-edit steps of a LAVA build.

The build pipeline is:

1. ``funcs.make_and_install()`` runs the project's make command through this
   module's CLI. The third-party ``compiledb`` package records compiler
   arguments and working directories in ``compile_commands.json``. Our
   ``preserve_shell_arguments()`` adapter keeps literal quotes intact, including
   defines such as ``-DSYSCONFDIR='"/prefix/etc"'`` that otherwise become invalid C.
2. ``funcs.preprocess()`` reads that database and invokes the compiler with
   ``-E``, preserving each file's include paths, defines and other build flags.
   That preprocessing remains in ``funcs.py``; the adapter supplies accurate
   arguments rather than choosing the flags itself.
3. ``lavaTool`` analyzes the source and writes YAML replacements: a filename,
   byte offset, byte length and replacement text for each proposed source edit.
   ``funcs.apply_replacements()`` calls ``apply_large_replacements()`` here to
   apply large, unambiguous edit sets efficiently. Small or unsupported sets go
   through LLVM's ``clang-apply-replacements`` instead.
4. LAVA rebuilds the edited source. The same replacement helper is also used
   when applying source edits during bug injection.

These helpers share a module because both support source preparation/building.
Compiler capture happens before preprocessing; replacement application happens
later, after lavaTool has decided which source edits to make.

CLI (the ordinary compiledb arguments are forwarded unchanged)::

    python -m pyroclastic.utils.build_support -- make -j4 target
"""
import os
from pathlib import Path
import shlex
import tempfile

import yaml


def preserve_shell_arguments():
    """Keep shell-quoted compiler arguments exact when compiledb parses make output.

    Some bashlex/compiledb versions drop literal quotes inside a shell-quoted
    word. Recover each word from the original shell text with shlex, then skip
    compiledb's second unescaping pass. This changes the current Python process's
    parser only; installed dependencies are left untouched.
    """
    from compiledb import parser

    original = parser.CommandProcessor

    class ShellCommandProcessor(original):
        def visitword(self, node, word):
            raw = self.line[node.pos[0]:node.pos[1]]
            values = shlex.split(raw)
            if len(values) != 1:
                raise ValueError(f"Expected one compiler argument, got {raw!r}")
            return super().visitword(node, values[0])

    parser.CommandProcessor = ShellCommandProcessor
    # shlex already removed shell escaping, so retain literal backslashes/quotes.
    parser.unescape = lambda value: value


class UnsupportedScalar(ValueError):
    """A YAML scalar whose interpretation can differ between PyYAML and LLVM."""


class ReplacementLoader(getattr(yaml, 'CSafeLoader', yaml.SafeLoader)):
    """Safely load replacements, rejecting ambiguous multiline scalar styles."""

    def construct_scalar(self, node):
        # LLVM's YAML reader and PyYAML disagree on folded multiline scalars.
        # lavaTool emits escaped double-quoted text for multiline insertions.
        if '\n' in node.value and node.style != '"':
            raise UnsupportedScalar()
        return super().construct_scalar(node)


def apply_large_replacements(yamls, directory, allowed_files, minimum=10000):
    """Apply a large set of lavaTool source edits; return whether it was applied.

    ``yamls`` contains lavaTool's replacement files. ``directory`` is the
    compilation working directory used to resolve their relative FilePath
    values; ``allowed_files`` limits which source files may change.

    Offsets and lengths count bytes in each original source file. After checking
    every edit, assemble each output in one pass and replace files atomically,
    preserving their permissions. This avoids the long LLVM edit-application
    pass observed on SQLite's amalgamated source.

    Return True on success. Return False without changing files when there are
    fewer than ``minimum`` edits (10,000 by default), overlapping/same-offset
    edits, non-ASCII replacement text, unsupported YAML scalars, disallowed
    paths or invalid ranges. The caller then uses clang-apply-replacements.
    Formatting requests bypass this helper in funcs.apply_replacements().
    """
    allowed = {Path(p).resolve() for p in allowed_files}
    edits = {}
    count = 0
    for filename in yamls:
        with open(filename, 'rb') as stream:
            try:
                data = yaml.load(stream, Loader=ReplacementLoader)
            except UnsupportedScalar:
                return False
        if not isinstance(data, dict) or set(data) - {'MainSourceFile', 'Replacements'}:
            return False
        for edit in data.get('Replacements', []):
            path = (Path(directory) / edit['FilePath']).resolve()
            offset, length, text = edit['Offset'], edit['Length'], edit['ReplacementText']
            if path not in allowed or type(offset) is not int or type(length) is not int:
                return False
            if not isinstance(text, str) or not text.isascii() or min(offset, length) < 0:
                return False
            edits.setdefault(path, []).append((offset, length, text.encode('ascii')))
            count += 1
    if count < minimum:
        return False
    # Validate every file before changing any. Same-offset edits go to LLVM even
    # when their order might be resolvable: insertion order must never be guessed.
    outputs = {}
    for path, replacements in edits.items():
        source = path.read_bytes()
        chunks = []
        end, previous_offset = 0, -1
        for offset, length, text in sorted(replacements):
            if offset < end or offset == previous_offset or offset + length > len(source):
                return False
            chunks.extend((source[end:offset], text))
            end, previous_offset = offset + length, offset
        chunks.append(source[end:])
        outputs[path] = b''.join(chunks)
    for path, output in outputs.items():
        # Replace atomically, retaining source permissions.
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.replacements-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(output)
            os.chmod(temporary, path.stat().st_mode)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print(f'Applied {count} non-overlapping replacements in {len(outputs)} files')
    return True


def main():
    """Run compiledb's CLI with the quote-preserving argument adapter enabled."""
    from compiledb import cli
    preserve_shell_arguments()
    cli.cli()


if __name__ == '__main__':
    main()
