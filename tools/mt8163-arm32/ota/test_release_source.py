#!/usr/bin/env python3
"""Behavioral tests of OTA release transport selection (real shell, fake curl).

The device must prefer the project download domain and fall back to GitHub
Releases under the organisation repository whenever the domain is unhealthy, so
that no device depends on a personal account or a single host.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

INITRAMFS = Path(__file__).resolve().parents[1] / 'initramfs'
FETCHER = INITRAMFS / 'libreecho-update-fetch'
GENERATION = INITRAMFS / 'libreecho-generation'
BUSYBOX = shutil.which('busybox') or '/bin/busybox'
TAG = 'radar-puffin-build-' + 'a' * 7 + '-' + 'b' * 16 + '-' + 'c' * 16
SHA256 = 'd' * 64

# Records every requested URL. The health endpoint answers per $HEALTH; the dev
# pointer answers with a valid two-line pointer from either transport.
FAKE_CURL = r'''#!/bin/sh
out=; headers=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out=$2; shift 2 ;;
    --dump-header) headers=$2; shift 2 ;;
    --stderr|--max-time|--connect-timeout|--max-filesize|--cacert|--proto|--proto-redir|--range|--write-out) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "$url" >> "$CURL_LOG"
case "$url" in
  https://dl.libreecho.org/healthz)
    case "$HEALTH" in
      ok) body='libreecho-dl ok' ;;
      wrong) body='captive portal' ;;
      down) exit 7 ;;
      http500) printf 'HTTP/1.1 500 Error\r\n\r\n' > "$headers"; exit 22 ;;
    esac
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "$(( ${#body} + 1 ))" > "$headers"
    printf '%s\n' "$body" > "$out"; exit 0 ;;
  */download/radar-puffin-dev-channel/release-pointer-v3.txt)
    body=$(printf '%s\n%s\n' "$TEST_TAG" "$TEST_SHA")
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "$(printf '%s\n' "$body" | wc -c)" > "$headers"
    printf '%s\n' "$body" > "$out"; exit 0 ;;
esac
exit 22
'''


class ReleaseSourceSelectionTests(unittest.TestCase):
    def run_selection(self, health, channel='dev', release_base=''):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            curl = root / 'fake-curl'
            curl.write_text(FAKE_CURL)
            curl.chmod(0o755)
            update = root / 'data/libreecho/update'
            (update / 'incoming').mkdir(parents=True)
            (root / 'run/libreecho').mkdir(parents=True)
            (root / 'target').write_text('target_id=radar_puffin\n')
            (root / 'source.conf').write_text(f'schema=1\nrelease_base={release_base}\n')
            (root / 'channel').write_text('channel=' + channel + '\n')
            source = FETCHER.read_text()
            source = source[:source.rfind('case "${1:-}" in')]
            source = source.replace('ROOT=/data/libreecho/update', 'ROOT=' + str(update))
            source = source.replace('CURL_STDERR=/run/libreecho/ota-curl.stderr',
                                    'CURL_STDERR=' + str(update / 'curl.stderr'))
            source = source.replace('CURL_HEADERS=/run/libreecho/ota-curl.headers',
                                    'CURL_HEADERS=' + str(update / 'curl.headers'))
            source = source.replace('BB=/bin/busybox', 'BB=' + BUSYBOX, 1)
            source += (
                f'\nCURL={curl}\nCA=/dev/null\nRUN_ROOT={root / "run"}\n'
                f'TARGET_FILE={root / "target"}\nCONFIG={root / "source.conf"}\n'
                f'CHANNEL_FILE={root / "channel"}\n'
                'check_status_write() { :; }\n'
                'die() { echo "ERROR:$1" >&2; exit 1; }\n'
                'fetch_lock\nvalidate_source\nselect_release_source\n'
                'printf "base=%s\\nlatest=%s\\n" "$RELEASE_BASE" "$url"\n'
                'resolve_dev_release || exit 1\nprintf "dev=%s\\n" "$url"\n'
            )
            script = root / 'fetcher'
            script.write_text(source)
            log = root / 'curl.log'
            env = os.environ | dict(HEALTH=health, CURL_LOG=str(log),
                                    TEST_TAG=TAG, TEST_SHA=SHA256)
            result = subprocess.run([BUSYBOX, 'sh', str(script)], env=env,
                                    capture_output=True, text=True, timeout=60)
            requested = log.read_text().splitlines() if log.exists() else []
            leftovers = sorted(p.name for p in update.iterdir() if p.name.startswith('.control-'))
            return result, dict(line.split('=', 1) for line in result.stdout.splitlines()
                                if '=' in line), requested, leftovers

    def test_healthy_domain_is_used_for_every_request(self):
        result, out, requested, leftovers = self.run_selection('ok')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out['base'], 'https://dl.libreecho.org')
        self.assertEqual(out['latest'], 'https://dl.libreecho.org/latest/download/'
                         'libreecho-radar-puffin-dev.ota.tar')
        self.assertEqual(out['dev'], f'https://dl.libreecho.org/download/{TAG}/'
                         f'libreecho-radar-puffin-{TAG[len("radar-puffin-"):]}.ota.tar')
        self.assertEqual(requested, [
            'https://dl.libreecho.org/healthz',
            'https://dl.libreecho.org/download/radar-puffin-dev-channel/release-pointer-v3.txt',
        ])
        self.assertEqual(leftovers, [])

    def test_unhealthy_domain_falls_back_to_published_github_releases(self):
        for health in ('down', 'http500', 'wrong'):
            with self.subTest(health=health):
                result, out, requested, leftovers = self.run_selection(health)
                self.assertEqual(result.returncode, 0, result.stderr)
                github = 'https://github.com/aslater3/LibreEcho/releases'
                self.assertEqual(out['base'], github)
                self.assertEqual(out['latest'], github + '/latest/download/'
                                 'libreecho-radar-puffin-dev.ota.tar')
                self.assertTrue(out['dev'].startswith(github + '/download/' + TAG + '/'))
                self.assertEqual(requested[1], github +
                                 '/download/radar-puffin-dev-channel/release-pointer-v3.txt')
                self.assertEqual(leftovers, [])

    def test_stable_channel_uses_selected_latest_alias(self):
        result, out, requested, _ = self.run_selection('ok', channel='stable')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out['latest'], 'https://dl.libreecho.org/latest/download/'
                         'libreecho-radar-puffin-stable.ota.tar')
        self.assertEqual(requested, ['https://dl.libreecho.org/healthz'])

    def test_fork_transport_uses_only_explicit_repository(self):
        github = 'https://github.com/srsatt/LibreEcho/releases'
        result, out, requested, leftovers = self.run_selection('down', release_base=github)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out['base'], github)
        self.assertEqual(requested, [github + '/download/radar-puffin-dev-channel/release-pointer-v3.txt'])
        self.assertEqual(leftovers, [])
        result, _, requested, _ = self.run_selection('ok', release_base='https://evil.invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('source_repository', result.stderr)
        self.assertEqual(requested, [])

    def test_generation_only_accepts_project_transports(self):
        for given, expected in (
            ('https://dl.libreecho.org', 'https://dl.libreecho.org'),
            ('https://github.com/aslater3/LibreEcho/releases', 'https://github.com/aslater3/LibreEcho/releases'),
            ('https://github.com/LibreEcho/LibreEcho/releases', 'https://github.com/LibreEcho/LibreEcho/releases'),
            ('https://evil.invalid', 'https://github.com/aslater3/LibreEcho/releases'),
            ('', 'https://github.com/aslater3/LibreEcho/releases'),
        ):
            with self.subTest(given=given):
                head = GENERATION.read_text().split('\nfail() {', 1)[0]
                head = head.replace('BB=/bin/busybox', 'BB=' + BUSYBOX, 1)
                result = subprocess.run(
                    [BUSYBOX, 'sh', '-c', head + '\nprintf "%s" "$release_base"'],
                    env=os.environ | dict(RELEASE_BASE=given),
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_generation_fork_configuration_rejects_other_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'ota-source.conf'
            config.write_text('schema=1\nrelease_base=https://github.com/srsatt/LibreEcho/releases\n')
            head = GENERATION.read_text().split('\nfail() {', 1)[0]
            head = head.replace('BB=/bin/busybox', 'BB=' + BUSYBOX, 1)
            for given, valid in (('', True), ('https://github.com/srsatt/LibreEcho/releases', True),
                                 ('https://dl.libreecho.org', False),
                                 ('https://github.com/aslater3/LibreEcho/releases', False)):
                with self.subTest(given=given):
                    result = subprocess.run([BUSYBOX, 'sh', '-c', head + '\nprintf "%s" "$release_base"'],
                                            env=os.environ | dict(OTA_SOURCE_CONFIG=str(config), RELEASE_BASE=given),
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, valid, result.stderr)
                    if valid:
                        self.assertEqual(result.stdout, 'https://github.com/srsatt/LibreEcho/releases')


if __name__ == '__main__':
    unittest.main()
