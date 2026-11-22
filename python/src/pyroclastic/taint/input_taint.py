"""Select PANDA's input-labeling plugin without confusing packets with seed bytes.

The local tainted_net implementation labels received NIC buffers. Its positional
labels combine a replay packet counter and a frame-byte offset; they are not
file offsets. This module wires that plugin and validates its options, but does
not invent the recording/session identity or packet-to-seed mapping required by
LAVA's current file-oriented importer and mutator. Until those adapters exist,
validate_input_transport() stops network mining before database/VM side effects.

Plugin options were checked against ~/panda/panda/plugins/tainted_net/tainted_net.cpp.
In particular, the code expects 'max_packet_size', although its README calls it
'maximum_packet_size'. Common PRI/taint2/query/branch plugins remain in replay().
"""
from ipaddress import IPv4Address
from pathlib import Path
import re
import shlex


def uses_network_taint(project):
    value = project.get('network_taint', False)
    if type(value) is not bool:
        raise ValueError('network_taint must be a JSON boolean')
    return value


def network_plugin_args(project):
    """Return positional IPv4/TCP labeling options for the local tainted_net plugin.

    Optional packets/bytes filters use decimal colon-separated ranges, as in
    PANDA's '22:33-40' syntax. Choose them from an observed recording, not guessed
    packet numbers or assumed TCP header lengths. Defaults label whole matching
    frames for diagnostics; they are not a complete LAVA input-label mapping.
    """
    options = project.get('network_taint_options', {})
    if not isinstance(options, dict):
        raise ValueError('network_taint_options must be an object')
    allowed = {'max_packet_size', 'packets', 'bytes', 'ip_proto', 'ip_src', 'ip_dst', 'eth_type'}
    unknown = set(options) - allowed
    if unknown:
        raise ValueError(f'Unsupported tainted_net options: {sorted(unknown)}; use max_packet_size, not maximum_packet_size')
    args = {'label_incoming_network': True, 'query_outgoing_network': False,
            'pos': True, 'semantic': False, 'max_packet_size': 65535,
            'ip_proto': '6', 'eth_type': 2048}
    args.update(options)
    if type(args['max_packet_size']) is not int or args['max_packet_size'] not in (2047,4095,8191,16383,32767,65535):
        raise ValueError('max_packet_size must be one of 2047,4095,8191,16383,32767,65535')
    if type(args['eth_type']) is not int or not 0 <= args['eth_type'] <= 65535:
        raise ValueError('eth_type must be an integer between 0 and 65535')
    for key in ('packets', 'bytes', 'ip_proto'):
        if key not in args:
            continue
        value = args[key]
        if not isinstance(value, str) or not re.fullmatch(r'\d+(?:-\d+)?(?::\d+(?:-\d+)?)*', value):
            raise ValueError(f'{key} must be a nonempty colon-separated decimal range string')
        for item in value.split(':'):
            bounds = [int(v) for v in item.split('-')]
            if len(bounds) == 2 and bounds[0] > bounds[1]:
                raise ValueError(f'{key} contains a reversed range')
            if key == 'bytes' and bounds[-1] > args['max_packet_size']:
                raise ValueError('bytes exceeds the positional-label byte field')
            bits = (args['max_packet_size'] + 1).bit_length() - 1
            if key == 'packets' and bounds[-1] >= (1 << (32 - bits)):
                raise ValueError('packets exceeds the positional-label packet counter field')
            if key == 'ip_proto' and bounds[-1] > 255:
                raise ValueError('ip_proto values must be between 0 and 255')
    for key in ('ip_src', 'ip_dst'):
        if key in args:
            if not isinstance(args[key], str):
                raise ValueError(f'{key} must be an IPv4 address string')
            args[key] = str(IPv4Address(args[key]))
    return args


def load_input_taint_plugins(panda, project, install_directory):
    """Load only the input-source plugin; replay() loads the common analysis plugins."""
    if uses_network_taint(project):
        panda.load_plugin('tainted_net', args=network_plugin_args(project))
    else:
        panda.load_plugin('file_taint', args={'filename': str(Path(install_directory)/'inputs'/'*'),
                                           'pos': True, 'verbose': project.get('debug', False)})


def validate_input_transport(project):
    """Reject unsupported network mining before recording, import or database resets.

    Query/make do not call this guard: building hypercalls is independent of
    selecting the input source. It applies when executing the mining pipeline.
    """
    if not uses_network_taint(project):
        return
    network_plugin_args(project)
    command = shlex.split(project.get('command', ''))
    if command and Path(command[0]).name == 'nginx' and '-t' in command[1:]:
        raise ValueError('network_taint=true requires HTTP request execution; nginx -t only reads configuration files. '
                         'Query/make are supported, but network recording/import needs an adapter first.')
    raise NotImplementedError('Network plugin selection is implemented, but LAVA network mining still needs '
                              'bounded server/client recording, input-session identity, and a verified '
                              'packet-byte to seed-offset mapping. Raw NIC labels cannot be imported as file offsets.')
