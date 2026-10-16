"""Pandalog conversion requires native protobuf without mutating parent settings."""
import pytest
from types import SimpleNamespace
from unittest.mock import patch

from pyroclastic.taint.bug_mining import pandalog_conversion_env


def test_native_backend_overrides_inherited_python_without_mutating_parent(monkeypatch):
    monkeypatch.setenv('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
    with patch('pyroclastic.taint.bug_mining.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
        env = pandalog_conversion_env()
    assert env['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] == 'upb'
    assert run.call_args.kwargs['env']['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] == 'upb'
    import os
    assert os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] == 'python'


def test_old_binding_fails_with_actionable_error():
    with patch('pyroclastic.taint.bug_mining.subprocess.run',
               return_value=SimpleNamespace(returncode=1, stderr='Incompatible binding')):
        with pytest.raises(RuntimeError, match='Rebuild/reinstall PyPANDA') as error:
            pandalog_conversion_env()
    assert 'Incompatible binding' in str(error.value)
