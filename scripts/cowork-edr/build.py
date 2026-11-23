#!/usr/bin/env python3
"""Build the restricted internal ARM64 Cowork test archive. Never prints tokens."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cloud-url', required=True)
    p.add_argument('--token-file', type=Path, required=True)
    p.add_argument('--user-email', default='')
    p.add_argument('--installation-id', default='')
    p.add_argument('--source-revision', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--allow-http-loopback', action='store_true')
    args = p.parse_args()
    if args.token_file.is_symlink() or args.token_file.stat().st_mode & 0o077:
        p.error('test credential must be a private regular file (mode 0600)')
    token = args.token_file.read_bytes().strip()
    if not token or len(token) > 16384:
        p.error('test credential is empty or too long')
    instance = args.installation_id or 'ins_' + base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip('=')
    try:
        valid_id = instance.startswith('ins_') and len(instance) == 36 and len(base64.b64decode(instance[4:], altchars=b'-_', validate=True)) == 24
    except ValueError:
        valid_id = False
    if not valid_id:
        p.error('installation ID must use the CLI generated ins_ + 32-character base64url format')
    args.output.mkdir(parents=True, exist_ok=True)
    os.chmod(args.output, 0o700)
    binary = args.output / 'kontext-linux-arm64'
    version = 'eng1109-' + args.source_revision[:12]
    env = dict(os.environ, GOOS='linux', GOARCH='arm64', CGO_ENABLED='0')
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-tags=nostepsafetymodel',
                    '-ldflags', f'-s -w -X main.version={version}', '-o', str(binary), './cmd/kontext'],
                   cwd=ROOT, env=env, check=True)
    source_hash = hashlib.sha256()
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and (path.suffix == '.go' or path.name in ['go.mod', 'go.sum']):
            source_hash.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + path.read_bytes())
    cfg = dict(cloud_url=args.cloud_url, token_file='/etc/kontext-cowork/test-token',
               installation_id=instance, user_email=args.user_email,
               state_dir='/var/lib/kontext-cowork', runtime_dir='/run/kontext-cowork')
    if args.allow_http_loopback:
        cfg['allow_http_loopback'] = True
    command = '/usr/local/lib/kontext-cowork/kontext hook --agent cowork --mode observe --socket /run/kontext-cowork/sensor.sock'
    hooks = {}
    for name in ['SessionStart', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'SessionEnd']:
        entry = {'hooks': [{'type': 'command', 'command': command, 'timeout': 10}]}
        if name in ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']:
            entry['matcher'] = '*'
        hooks[name] = [entry]
    files = {
        'kontext': (binary.read_bytes(), 0o755),
        'config.json': (json.dumps(cfg, indent=2).encode() + b'\n', 0o600),
        'test-token': (token + b'\n', 0o600),
        'hooks.json': (json.dumps({'hooks': hooks}, indent=2).encode() + b'\n', 0o644),
        'manifest.json': (json.dumps({'base_source_revision': args.source_revision, 'go_source_sha256': source_hash.hexdigest(), 'version': version,
                                   'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                   'target': 'linux/arm64', 'installation_id': instance,
                                   'scope': 'internal observe-only test; restricted credential-bearing artifact'}, indent=2).encode() + b'\n', 0o644),
    }
    for name in ['install.sh', 'uninstall.sh', 'kontext-cowork.service']:
        files[name] = ((HERE / name).read_bytes(), 0o755 if name.endswith('.sh') else 0o644)
    target = args.output / f'kontext-cowork-{version}-linux-arm64.tar.gz'
    with target.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name, (data, mode) in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), mode, 0
                    info.uid = info.gid = 0
                    tar.addfile(info, io.BytesIO(data))
    os.chmod(target, 0o600)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_name(target.name + '.sha256').write_text(f'{digest}  {target.name}\n')
    print(json.dumps({'archive': str(target.resolve()), 'sha256': digest,
                      'installation_id': instance, 'version': version}, indent=2))

if __name__ == '__main__':
    main()
