"""Validate PANDA plugin wiring without launching PANDA or tainting anything."""
from unittest.mock import Mock

import pytest

from pyroclastic.taint.input_taint import (
    load_input_taint_plugins, network_plugin_args, validate_input_transport,
)


def test_file_source_keeps_existing_positional_file_plugin():
    panda = Mock()
    load_input_taint_plugins(panda, {'debug': True}, '/work/lava-install')
    panda.load_plugin.assert_called_once_with('file_taint', args={
        'filename': '/work/lava-install/inputs/*', 'pos': True, 'verbose': True})


def test_network_source_uses_actual_local_plugin_argument_name_and_unique_labels():
    panda = Mock()
    project = {'network_taint': True, 'network_taint_options': {
        'max_packet_size': 2047, 'packets': '22:33-40', 'bytes': '54-80',
        'ip_src': '192.0.2.1', 'ip_dst': '192.0.2.2'}}
    load_input_taint_plugins(panda, project, '/unused')
    args = panda.load_plugin.call_args.kwargs['args']
    assert panda.load_plugin.call_args.args == ('tainted_net',)
    assert args['pos'] and args['label_incoming_network']
    assert not args['semantic'] and not args['query_outgoing_network']
    assert args['max_packet_size'] == 2047
    assert 'maximum_packet_size' not in args
    assert args['ip_proto'] == '6' and args['eth_type'] == 2048
    assert args['packets'] == '22:33-40' and args['bytes'] == '54-80'
    assert 'pos' not in project['network_taint_options']  # no configuration mutation


@pytest.mark.parametrize('options', [
    {'maximum_packet_size': 2047}, {'max_packet_size': 1500}, {'max_packet_size': True},
    {'semantic': True}, {'pos': False}, {'packets': ''}, {'packets': '4-2'},
    {'bytes': 'header'}, {'max_packet_size': 2047, 'bytes': '0-2048'}, {'packets': '65536'},
    {'ip_src': 'not-an-ip'}, {'ip_dst': '::1'}, {'ip_proto': '256'}, {'eth_type': True},
])
def test_unsupported_plugin_options_fail_before_loading(options):
    panda = Mock()
    with pytest.raises(ValueError):
        load_input_taint_plugins(panda, {'network_taint': True, 'network_taint_options': options}, '/unused')
    panda.load_plugin.assert_not_called()


def test_transport_preflight_distinguishes_config_checks_from_network_requests():
    validate_input_transport({'network_taint': False})
    with pytest.raises(ValueError, match='nginx -t'):
        validate_input_transport({'network_taint': True, 'command': '/work/nginx -t -c seed.conf'})
    with pytest.raises(NotImplementedError, match='packet-byte to seed-offset'):
        validate_input_transport({'network_taint': True, 'command': '/work/nginx -c server.conf'})


def test_network_pipeline_stops_before_database_or_vm_initialization(monkeypatch):
    from pyroclastic.taint import bug_mining
    database = Mock(side_effect=AssertionError('must not touch the database'))
    vm = Mock(side_effect=AssertionError('must not start PANDA'))
    monkeypatch.setattr(bug_mining, 'LavaDatabase', database)
    monkeypatch.setattr(bug_mining, 'Panda', vm)
    with pytest.raises(ValueError, match='nginx -t'):
        bug_mining.run_taint_pipeline({'network_taint': True, 'command': '/work/nginx -t'})
    database.assert_not_called()
    vm.assert_not_called()


def test_network_import_stops_before_opening_or_discarding_unmapped_logs():
    from pyroclastic.taint.find_bug_injection import parse_panda_log
    with pytest.raises(NotImplementedError, match='packet-byte to seed-offset'):
        parse_panda_log('/does/not/exist', {'network_taint': True, 'command': '/work/nginx'})
