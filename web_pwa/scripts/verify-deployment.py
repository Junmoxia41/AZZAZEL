#!/usr/bin/env python3
"""Check the REAL public deployment; a Vercel login redirect is a failure.

Usage:
  python scripts/verify-deployment.py https://azzazel-vpn.vercel.app \
      --report ../docs/deployments/mime-http-verification.json

No account, PC credentials, or protection-bypass token is used.
"""
import argparse
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--dist', type=Path, default=Path(__file__).resolve().parents[1] / 'dist')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    base = args.url.rstrip('/')
    checks = []

    def check(path, expected_status, allowed_types, local_file=None, revalidate=False):
        url = base + path
        entry = {'path': path}
        try:
            request = urllib.request.Request(url, headers={
                'User-Agent': 'AZZAZEL-Deployment-Verification/1.0',
                'Cache-Control': 'no-cache', 'Accept-Encoding': 'identity',
            })
            try:
                response = urllib.request.urlopen(request, timeout=30)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = response.read()
                mime = response.headers.get_content_type()
                entry.update(status=response.status, mime=mime,
                             final_url=response.url, bytes=len(body),
                             cache_control=response.headers.get('Cache-Control'),
                             nosniff=response.headers.get('X-Content-Type-Options'),
                             sha256=hashlib.sha256(body).hexdigest())
                errors = []
                if response.status != expected_status:
                    errors.append(f'Expected HTTP {expected_status}, got {response.status}')
                if urllib.parse.urlsplit(response.url).netloc != urllib.parse.urlsplit(base).netloc:
                    errors.append('Redirected away from application origin (possibly Vercel login)')
                if mime not in allowed_types:
                    errors.append(f'Unexpected MIME: {mime}')
                if local_file is not None:
                    expected = hashlib.sha256(local_file.read_bytes()).hexdigest()
                    entry['matches_build'] = expected == entry['sha256']
                    if not entry['matches_build']:
                        errors.append('Response bytes differ from the local build')
                if response.headers.get('X-Content-Type-Options') != 'nosniff':
                    errors.append('Missing nosniff header')
                if revalidate and 'no-cache' not in response.headers.get('Cache-Control', ''):
                    errors.append('Entry point must revalidate its cache')
                entry['errors'] = errors
                entry['passed'] = not errors
        except Exception as exc:
            entry.update(passed=False, errors=[str(exc)])
        checks.append(entry)
        print(('PASS' if entry['passed'] else 'FAIL') + f" {path}: HTTP {entry.get('status')} {entry.get('mime')}")
        if not entry['passed']:
            for error in entry['errors']:
                print('  ' + error)

    html_path = args.dist / 'index.html'
    html = html_path.read_text()
    check('/', 200, {'text/html'}, html_path, revalidate=True)
    refs = sorted(set(m[1] for m in re.finditer(r'(?:src|href)=[\"\'](/[^\"\']+)[\"\']', html)))
    mime_by_suffix = {
        '.js': {'application/javascript', 'text/javascript', 'application/ecmascript', 'text/ecmascript'},
        '.css': {'text/css'},
        '.json': {'application/json', 'application/manifest+json'},
        '.png': {'image/png'},
    }
    for ref in refs:
        local = args.dist / ref.lstrip('/')
        check(ref, 200, mime_by_suffix[local.suffix], local, revalidate=ref == '/manifest.json')
    check('/icon-512.png', 200, {'image/png'}, args.dist / 'icon-512.png')
    check('/sw.js', 200, mime_by_suffix['.js'], args.dist / 'sw.js', revalidate=True)
    check('/ajustes/conexion', 200, {'text/html'}, html_path, revalidate=True)
    for missing in ('/assets/__missing_probe__.js', '/assets/__missing_probe__.css', '/missing-probe.json', '/api/__missing_probe__'):
        check(missing, 404, {'text/html', 'text/plain', 'application/json'})

    report = {'verified_at': datetime.now(timezone.utc).isoformat(),
              'base_url': base, 'authenticated': False, 'checks': checks,
              'passed': all(c['passed'] for c in checks),
              'scope': 'HTTPS routing, MIME, byte-for-byte artifact integrity and cache headers. Not Supabase login or PC connectivity.'}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
