"""Regression for nginx distclean deleting the parent of a generated source."""
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


def test_make_restores_generated_source_inside_deleted_directory(tmp_path, monkeypatch):
    import pyroclastic.lava as lava
    source = tmp_path/'source'
    generated = source/'objs/ngx_modules.c'
    generated.parent.mkdir(parents=True)
    generated.write_bytes(b'original generated module table\n')
    logs = tmp_path/'logs'
    logs.mkdir()
    paths = SimpleNamespace(source_directory=source, logs_directory=logs)
    monkeypatch.setattr(lava, 'run_local', Mock())
    monkeypatch.setattr(lava, 'read_compile_db', lambda root: (set(), {str(generated)}))
    monkeypatch.setattr(lava, 'deep_clean_target', lambda *args, **kwargs: shutil.rmtree(source/'objs'))
    def configure(*args, **kwargs):
        assert generated.read_bytes() == b'original generated module table\n'
    monkeypatch.setattr(lava, 'configure_project', configure)
    build = Mock()
    monkeypatch.setattr(lava, 'make_and_install', build)
    lava.make_panda(paths)
    build.assert_called_once()
    assert build.call_args.kwargs['environment'] == 'panda'
