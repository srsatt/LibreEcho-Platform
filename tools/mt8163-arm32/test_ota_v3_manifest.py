"""Signed target grammar, exercised with BusyBox and real Ed25519 signatures."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from nacl.signing import SigningKey

TOOLS = Path(__file__).resolve().parent
PARSER = TOOLS / 'initramfs/libreecho-target-manifest'
FEATURES = ('airplay2', 'tts', 'wakeword', 'stt', 'assistant')
DAEMONS = ('libreecho-audio-engine', 'libreecho-ttsd', 'libreecho-waked', 'libreecho-sttd', 'libreecho-agentd')


def manifest(assets=None, tx='test-target'):
    assets = assets or {f: (('payload:' + f).encode(), ('manifest:' + f).encode()) for f in FEATURES}
    rows = [('format', 'libreecho-ota-v3'), ('manifest_version', '1'),
            ('board', 'radar_puffin'), ('soc', 'mt8163'), ('architecture', 'armv7'),
            ('image_profile', 'ota'), ('transaction_type', 'system'), ('transaction_id', tx),
            ('release', 'radar-puffin-v0.14.0-test'), ('version', '0.14.0'),
            ('update_channel', 'dev'), ('service_profile', 'production'),
            ('minimum_updater_schema', '3'), ('commit_policy', 'after-slot-confirm'),
            ('boot_filename', 'boot.img'), ('boot_size', '16777216'),
            ('boot_sha256', 'a' * 64), ('feature_ids', ','.join(FEATURES))]
    for f, daemon in zip(FEATURES, DAEMONS):
        p, m = assets[f]
        ph, mh = hashlib.sha256(p).hexdigest(), hashlib.sha256(m).hexdigest()
        rows.extend((('feature_' + f + '_' + k, str(v)) for k, v in (
            ('asset', f'libreecho-radar-puffin-base-{f}-{ph}.payload.squashfs'),
            ('size', len(p)), ('sha256', ph),
            ('manifest_asset', f'libreecho-radar-puffin-base-{f}-{mh}.manifest.json'),
            ('manifest_size', len(m)), ('manifest_sha256', mh),
            ('daemon_path', 'usr/local/sbin/' + daemon), ('daemon_sha256', 'b' * 64))))
    rows.append(('config_schema', '1'))
    return ''.join(f'{k}={v}\n' for k, v in rows)


class SignedFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = SigningKey.generate()
        (self.root / 'key').write_text(self.key.verify_key.encode().hex())
        (self.root / 'target').write_text('target_id=radar_puffin\n')
        verifier = self.root / 'verify'
        verifier.write_text('#!/usr/bin/env python3\nimport sys\nfrom nacl.signing import VerifyKey\nfrom pathlib import Path\nVerifyKey(bytes.fromhex(Path(sys.argv[1]).read_text().strip())).verify(Path(sys.argv[2]).read_bytes(), bytes.fromhex(Path(sys.argv[3]).read_text().strip()))\n')
        verifier.chmod(0o755)
        self.env = dict(os.environ, TARGET_FILE=str(self.root / 'target'),
                        VERIFY=str(verifier), PUBLIC_KEY=str(self.root / 'key'))

    def signed(self, text):
        p = self.root / 'target.manifest'
        p.write_text(text)
        s = self.root / 'target.manifest.sig'
        s.write_text(self.key.sign(p.read_bytes()).signature.hex() + '\n')
        return p, s

    def check(self, text):
        p, s = self.signed(text)
        return subprocess.run(['/bin/busybox', 'sh', str(PARSER), 'check', str(p), str(s)],
                              env=self.env, text=True, capture_output=True)


class ManifestTests(SignedFixture):
    def test_accepts_canonical_v3(self):
        result = self.check(manifest())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_forbidden_keys(self):
        for key in ('feature_wakeword_action', 'feature_wakeword_base_payload_sha256',
                    'feature_policy', 'runtime_asset', 'feature_tts_activation'):
            with self.subTest(key=key):
                self.assertNotEqual(self.check(manifest() + key + '=bad\n').returncode, 0)

    def test_rejects_missing_asset_fields_for_any_feature(self):
        for f in FEATURES:
            for field in ('asset', 'size', 'sha256', 'manifest_asset', 'manifest_size', 'manifest_sha256'):
                with self.subTest(feature=f, field=field):
                    text = ''.join(line + '\n' for line in manifest().splitlines()
                                   if not line.startswith('feature_' + f + '_' + field + '='))
                    self.assertNotEqual(self.check(text).returncode, 0)

    def test_rejects_noncontent_addressed_name(self):
        self.assertNotEqual(self.check(manifest().replace('base-airplay2-', 'other-airplay2-')).returncode, 0)

    def test_rejects_board_mismatch(self):
        self.assertNotEqual(self.check(manifest().replace('board=radar_puffin', 'board=biscuit')).returncode, 0)

    def test_rejects_inexact_feature_set(self):
        exact = ','.join(FEATURES)
        for wrong in ('airplay2,tts,wakeword,stt', exact + ',extra', ','.join(reversed(FEATURES))):
            self.assertNotEqual(self.check(manifest().replace('feature_ids=' + exact, 'feature_ids=' + wrong)).returncode, 0)

    def test_rejects_v2_format(self):
        result = self.check(manifest().replace('libreecho-ota-v3', 'libreecho-ota-v2'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('legacy_manifest_unsupported', result.stderr)

    def test_rejects_wrong_signature(self):
        p, s = self.signed(manifest())
        p.write_text(p.read_text().replace('version=0.14.0', 'version=0.14.1'))
        result = subprocess.run(['/bin/busybox', 'sh', str(PARSER), 'check', str(p), str(s)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_duplicates_reordering_and_unsafe_transaction(self):
        text = manifest()
        for bad in (text + 'config_schema=1\n', '\n'.join(reversed(text.splitlines())) + '\n',
                    text.replace('transaction_id=test-target', 'transaction_id=../escape'),
                    text.replace('config_schema=1', 'config_schema=1x'), text.rstrip('\n')):
            self.assertNotEqual(self.check(bad).returncode, 0)


class ForkTrustBootstrapTests(SignedFixture):
    """Exercise the immutable legacy exception with test-only signing keys."""

    def setUp(self):
        super().setUp()
        self.good_boot = b'committed-boot'
        legacy_text = (manifest().replace('board=radar_puffin', 'board=biscuit')
                       .replace('boot_sha256=' + 'a' * 64,
                                'boot_sha256=' + hashlib.sha256(self.good_boot).hexdigest())
                       .replace('libreecho-radar-puffin-base-', 'libreecho-biscuit-base-'))
        self.legacy_manifest, self.legacy_sig = self.signed(legacy_text)
        legacy_key = self.root / 'legacy-key'
        legacy_key.write_text(self.key.verify_key.encode().hex() + '\n')
        fork_key = SigningKey.generate()
        primary = self.root / 'fork-key'
        primary.write_text(fork_key.verify_key.encode().hex() + '\n')
        self.fork_key = fork_key
        self.env.update(PUBLIC_KEY=str(primary), LEGACY_PUBLIC_KEY=str(legacy_key))
        (self.root / 'target').write_text('target_id=biscuit\n')
        script = PARSER.read_text()
        script = script.replace(
            'LEGACY_MANIFEST_SHA256=92f3f68a26b9ed1920658e419e1a417aafa9d36d1c0ea8cd90ec8202a832ad0e',
            'LEGACY_MANIFEST_SHA256=' + hashlib.sha256(self.legacy_manifest.read_bytes()).hexdigest())
        script = script.replace(
            'LEGACY_PUBLIC_KEY_SHA256=524c2b6343438b6ccffca8a8c7f0b9f36e6ec9a2ee37424364b6bfeef96d7f40',
            'LEGACY_PUBLIC_KEY_SHA256=' + hashlib.sha256(legacy_key.read_bytes()).hexdigest())
        self.parser = self.root / 'test-target-manifest'
        self.parser.write_text(script)
        self.parser.chmod(0o755)

    def run_check(self, verb, p=None, s=None):
        return subprocess.run(['/bin/busybox', 'sh', str(self.parser), verb,
                               str(p or self.legacy_manifest), str(s or self.legacy_sig)],
                              env=self.env, text=True, capture_output=True, timeout=30)

    def test_fork_primary_and_exact_legacy_installed_are_accepted(self):
        self.assertEqual(self.run_check('check-installed').returncode, 0)
        self.assertNotEqual(self.run_check('check').returncode, 0)
        fork_sig = self.root / 'fork.sig'
        fork_sig.write_text(self.fork_key.sign(self.legacy_manifest.read_bytes()).signature.hex() + '\n')
        for verb in ('check', 'check-installed'):
            with self.subTest(verb=verb):
                self.assertEqual(self.run_check(verb, s=fork_sig).returncode, 0)

    def test_legacy_exception_rejects_changed_manifest_signature_and_key(self):
        changed = self.root / 'changed.manifest'
        changed.write_text(self.legacy_manifest.read_text().replace('version=0.14.0', 'version=0.14.1'))
        changed_sig = self.root / 'changed.sig'
        changed_sig.write_text(self.key.sign(changed.read_bytes()).signature.hex() + '\n')
        self.assertNotEqual(self.run_check('check-installed', changed, changed_sig).returncode, 0)
        bad_sig = self.root / 'bad.sig'
        bad_sig.write_text(SigningKey.generate().sign(self.legacy_manifest.read_bytes()).signature.hex() + '\n')
        self.assertNotEqual(self.run_check('check-installed', s=bad_sig).returncode, 0)
        self.env['LEGACY_PUBLIC_KEY'] = self.env['PUBLIC_KEY']
        self.assertNotEqual(self.run_check('check-installed').returncode, 0)

    def installed_generation(self):
        generation = self.root / 'generations/test-target'
        generation.mkdir(parents=True)
        (generation / 'target.manifest').write_bytes(self.legacy_manifest.read_bytes())
        (generation / 'target.manifest.sig').write_bytes(self.legacy_sig.read_bytes())
        (generation / 'COMPLETE').write_text(hashlib.sha256(self.legacy_manifest.read_bytes()).hexdigest() + '\n')
        for f in FEATURES:
            feature = generation / 'features' / f
            feature.mkdir(parents=True)
            (feature / 'payload.squashfs').write_bytes(('payload:' + f).encode())
            (feature / 'manifest.json').write_bytes(('manifest:' + f).encode())
        update = self.root / 'update'
        update.mkdir()
        (update / 'current').write_text('test-target\n')
        self.env.update(ROOT=str(update), GENERATIONS=str(generation.parent),
                        TARGET_MANIFEST=str(self.parser),
                        GENERATION_TOOL=str(TOOLS / 'initramfs/libreecho-generation'))
        return generation

    def test_installed_readers_accept_legacy_but_assembly_rejects_it(self):
        generation = self.installed_generation()
        generation_tool = TOOLS / 'initramfs/libreecho-generation'
        transaction = TOOLS / 'initramfs/libreecho-generation-transaction'
        def invoke(tool, *args):
            return subprocess.run(['/bin/busybox', 'sh', str(tool), *map(str, args)],
                                  env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(invoke(generation_tool, 'verify', generation).returncode, 0)
        self.assertIn('generation=test-target', invoke(transaction, 'provenance').stdout)
        rejected = invoke(generation_tool, 'assemble', self.legacy_manifest, self.legacy_sig)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('target-invalid', rejected.stderr)
        self.env['MOUNT'] = '/bin/false'
        https = invoke(transaction, 'https-client')
        self.assertNotEqual(https.returncode, 0)
        self.assertIn('https-client-mount', https.stderr)
        bootctl = self.root / 'bootctl'
        bootctl.write_text('#!/bin/sh\nprintf "boot_store_mode=fixed-a\\n"\n')
        bootctl.chmod(0o755)
        boot_a = self.root / 'boot_a'; boot_a.write_bytes(b'uncommitted')
        boot_b = self.root / 'boot_b'; boot_b.write_bytes(b'corrupt-backup')
        self.env.update(BOOTCTL=str(bootctl), BOOT_A=str(boot_a), BOOT_B=str(boot_b))
        failed_restore = invoke(transaction, 'restore-boot-store')
        self.assertNotEqual(failed_restore.returncode, 0)
        self.assertEqual(boot_a.read_bytes(), b'uncommitted')
        boot_b.write_bytes(self.good_boot)
        restored = invoke(transaction, 'restore-boot-store')
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(boot_a.read_bytes(), self.good_boot)
        self.assertEqual(invoke(transaction, 'restore-boot-store').returncode, 0)


if __name__ == '__main__':
    unittest.main()
