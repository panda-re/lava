"""Encode pinned MediaService.ComposeMedia arguments as framed Thrift Binary RPCs.

The field IDs/types come from socialNetwork/social_network.thrift at revision
6ecb09706140f8730b5385c08f1386c654c3c526 (the active pin is in pins.json).
The examples are locally authored fixtures, not an upstream benchmark corpus.
The generator uses only the standard library. The build validation feeds these
bytes through the actual pinned Thrift processor and MediaHandler, checking
returned media IDs/types or the handler's declared length-mismatch exception.
Seeds contain one length-prefixed strict BinaryProtocol RPC, not network headers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def string(value):
    encoded = value.encode('utf-8')
    return struct.pack('!i', len(encoded)) + encoded


def compose_media(request):
    # Strict TBinaryProtocol version 1, CALL, method name, sequence ID.
    message = struct.pack('!I', 0x80010001) + string('ComposeMedia') + struct.pack('!i', 1)
    message += struct.pack('!bhq', 10, 1, request['req_id'])
    media_types = request['media_types']
    message += struct.pack('!bhbi', 15, 2, 11, len(media_types))
    message += b''.join(string(value) for value in media_types)
    media_ids = request['media_ids']
    message += struct.pack('!bhbi', 15, 3, 10, len(media_ids))
    message += b''.join(struct.pack('!q', value) for value in media_ids)
    carrier = request.get('carrier', {})
    message += struct.pack('!bhbbi', 13, 4, 11, 11, len(carrier))
    message += b''.join(string(key) + string(value) for key, value in sorted(carrier.items()))
    message += b'\x00'  # T_STOP ends the argument struct.
    return struct.pack('!I', len(message)) + message


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'inputs')
    parser.add_argument('--validate-binary', type=Path,
                        help='also replay the fixtures through an installed native handler binary')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    records = []
    for source in sorted((Path(__file__).parent / 'examples').glob('*.json')):
        request = json.loads(source.read_text())
        frame = compose_media(request)
        output = args.output / (source.stem + '.bin')
        if output.exists() and output.read_bytes() != frame:
            raise RuntimeError(f'Existing seed differs from its example; move it aside: {output}')
        if not output.exists(): output.write_bytes(frame)
        expected = ({'status': 'service_exception'} if len(request['media_types']) != len(request['media_ids'])
                    else {'status': 'ok', 'media': [{'id': i, 'type_hex': t.encode().hex()}
                          for i,t in zip(request['media_ids'], request['media_types'])]})
        records.append({'file': output.name, 'example': 'examples/' + source.name,
                        'example_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                        'bytes': len(frame), 'sha256': hashlib.sha256(frame).hexdigest(), 'expected': expected})
        print(f'{output}: {len(frame)} bytes')
    manifest = {'origin': 'locally authored fixtures encoded according to pinned upstream IDL',
                'revision': '6ecb09706140f8730b5385c08f1386c654c3c526',
                'protocol': 'framed strict Thrift BinaryProtocol ComposeMedia CALL', 'inputs': records}
    args.output.with_name(args.output.name + '.manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    if args.validate_binary:
        for record in records:
            result = subprocess.run([str(args.validate_binary.resolve()), str((args.output/record['file']).resolve())],
                                    capture_output=True, text=True, timeout=15, check=True)
            actual = json.loads(result.stdout)
            if any(actual.get(key) != value for key,value in record['expected'].items()):
                raise RuntimeError(f'Unexpected handler reply for {record["file"]}: {actual}')
            print(f'Validated real handler response: {record["file"]}: {actual["status"]}')


if __name__ == '__main__':
    main()
