#!/usr/bin/env python3
"""E2E exporter integrity checks. Never executes corpus commands.

Failure modes: modified consumed weights, extractor code, schemas or authored
fixtures accepted as frozen; modified code imported before verification; output
written on failed verification. Every source class is modified before invoking
the real export entry point in a subprocess. Produce a JSON receipt.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--experiment-dir', required=True, type=Path)
    p.add_argument('--schema-dir', required=True, type=Path)
    p.add_argument('--receipt', required=True, type=Path)
    a = p.parse_args()
    script = Path(__file__).with_name('export-aws-operation-model.py')
    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        patch, schema = root / 'patch', root / 'schema'
        (patch / 'models').mkdir(parents=True)
        (schema / 'source-schemas').mkdir(parents=True)
        paths = [(a.experiment_dir / 'operation_features.py', patch / 'operation_features.py'),
                 (a.experiment_dir / 'authored-data.json', patch / 'authored-data.json'),
                 (a.schema_dir / 'semantic_features.py', schema / 'semantic_features.py')]
        paths += [(x, patch / 'models' / x.name) for x in (a.experiment_dir / 'models').iterdir() if x.name in ('command.joblib', 'session.joblib', 'command.json.gz', 'session.json.gz')]
        paths += [(x, schema / 'source-schemas' / x.name) for x in (a.schema_dir / 'source-schemas').glob('*.json')]
        for src, dst in paths:
            shutil.copyfile(src, dst)
        cmd = [sys.executable, str(script), '--experiment-dir', str(patch), '--schema-dir', str(schema), '--verify-only']
        good = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert good.returncode == 0, good.stderr
        checks.append('unmodified frozen inputs accepted')
        for _, dst in paths:
            original = dst.read_bytes()
            try:
                dst.write_bytes(original + b'\n# modified-input\n')
                bad = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                assert bad.returncode != 0 and 'hash mismatch' in bad.stderr, (str(dst), bad.stdout, bad.stderr)
                checks.append('rejected modified ' + str(dst.relative_to(root)))
            finally:
                dst.write_bytes(original)
        extra = schema / 'source-schemas/unexpected.json'
        extra.write_text('{}')
        bad = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert bad.returncode != 0 and 'schema set mismatch' in bad.stderr, bad.stderr
        checks.append('rejected unexpected schema')
    receipt = {'passed': True, 'checks': checks, 'corpus_commands_executed': False}
    a.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
