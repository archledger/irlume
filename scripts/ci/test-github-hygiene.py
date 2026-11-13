#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Check the issue chooser's config and the curated documents' links.

.github/ISSUE_TEMPLATE/config.yml decides what the issue chooser offers,
and a YAML mistake there changes what reporters see while everything else
stays green. The curated documents tell people where to go, so one that
links a repository feature which is turned off leads them to a page that
accepts nothing: Discussions was turned off after #1347. The check runs
against the repository's real files and tests itself with fixtures: no
network, no repository changes.

Run: python3 scripts/ci/test-github-hygiene.py
"""
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHOOSER = ROOT / '.github/ISSUE_TEMPLATE/config.yml'

try:
    import yaml
except ImportError:
    # ci.yml installs PyYAML before this runs, so in CI the config cases
    # cannot drop out unnoticed; locally they skip.
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        sys.exit('PyYAML is missing on the CI runner')
    yaml = None

# Links to repository features that are turned off. A curated document
# carrying one points people at a page GitHub shows as unavailable.
# Discussions went off after #1347; add a URL when another feature goes,
# drop one when a feature returns.
TURNED_OFF_URLS = (
    'https://github.com/archledger/irlume/discussions',
)

# Documents whose links direct people. Dated records under docs
# subdirectories (adr, hardware, plans, research) are archives, not
# directions, so they are not scanned.
CURATED_DOCUMENTS = ('README.md', 'CONTRIBUTING.md', 'GOVERNANCE.md', 'SECURITY.md',
                     '.github/pull_request_template.md')


def curated_documents(root=ROOT):
    """The documents the link rule reads: the named pages, docs/*.md and the
    issue templates, .md and .yml alike (the chooser's own contact link is
    one of the links checked)."""
    paths = [root / name for name in CURATED_DOCUMENTS]
    paths += sorted((root / 'docs').glob('*.md'))
    paths += sorted((root / '.github/ISSUE_TEMPLATE').glob('*.md'))
    paths += sorted((root / '.github/ISSUE_TEMPLATE').glob('*.yml'))
    return paths


def config_problems(text, where='config.yml'):
    """Shape problems of an issue-chooser config, [] when it is as GitHub
    documents it: a boolean blank_issues_enabled, and contact links that
    each carry a name, an http(s) URL and about text."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f'{where}: not valid YAML: {str(error).splitlines()[0]}']
    if not isinstance(data, dict):
        return [f'{where}: expected a mapping at the top level']
    problems = []
    if 'blank_issues_enabled' not in data:
        problems.append(f'{where}: blank_issues_enabled is missing')
    elif not isinstance(data['blank_issues_enabled'], bool):
        problems.append(f'{where}: blank_issues_enabled must be a boolean, not '
                        f'{type(data["blank_issues_enabled"]).__name__}')
    links = data.get('contact_links')
    if links is None:
        links = []
    if not isinstance(links, list):
        problems.append(f'{where}: contact_links must be a list')
        links = []
    for n, link in enumerate(links, 1):
        where_link = f'{where}: contact link {n}'
        if not isinstance(link, dict):
            problems.append(f'{where_link}: expected a mapping')
            continue
        for key in ('name', 'url', 'about'):
            value = link.get(key)
            if not isinstance(value, str) or not value.strip():
                problems.append(f'{where_link}: {key} must be a non-empty string')
        url = link.get('url')
        if isinstance(url, str) and url.strip() and not url.startswith(('http://', 'https://')):
            problems.append(f'{where_link}: url must be an http or https URL')
    return problems


def turned_off_links(text):
    """The turned-off feature URLs that appear in `text`, subpages included."""
    return [url for url in TURNED_OFF_URLS if url in text]


@unittest.skipIf(yaml is None, 'PyYAML not installed')
class ConfigShape(unittest.TestCase):
    def test_the_repositorys_config_has_the_documented_shape(self):
        self.assertEqual(config_problems(CHOOSER.read_text(),
                                         str(CHOOSER.relative_to(ROOT))), [])

    def test_a_minimal_config_passes(self):
        self.assertEqual(config_problems('blank_issues_enabled: true\n'), [])
        one_link = ('blank_issues_enabled: false\n'
                    'contact_links:\n'
                    '  - name: Security problem, or not sure whether it is one\n'
                    '    url: https://github.com/archledger/irlume/security/advisories/new\n'
                    '    about: Report it privately here.\n')
        self.assertEqual(config_problems(one_link), [])

    def test_a_broken_config_is_refused(self):
        cases = {
            'indentation': ('blank_issues_enabled: true\n'
                            'contact_links:\n'
                            '  - name: Security problem\n'
                            '   url: https://example.com/report\n'),
            'not a mapping': '- blank_issues_enabled: true\n',
            'missing blank flag': 'contact_links: []\n',
            'blank flag not a boolean': 'blank_issues_enabled: maybe later\n',
            'contact_links not a list': 'blank_issues_enabled: true\ncontact_links: name\n',
            'link not a mapping': ('blank_issues_enabled: true\n'
                                   'contact_links:\n  - https://example.com/report\n'),
            'missing about': ('blank_issues_enabled: true\n'
                              'contact_links:\n'
                              '  - name: Security problem\n'
                              '    url: https://example.com/report\n'),
            'empty name': ('blank_issues_enabled: true\n'
                           'contact_links:\n'
                           '  - name: ""\n'
                           '    url: https://example.com/report\n'
                           '    about: Report it privately.\n'),
            'url without a scheme': ('blank_issues_enabled: true\n'
                                     'contact_links:\n'
                                     '  - name: Security problem\n'
                                     '    url: example.com/report\n'
                                     '    about: Report it privately.\n'),
        }
        for what, text in cases.items():
            with self.subTest(what):
                self.assertNotEqual(config_problems(text, 'fixture.yml'), [])


class CuratedLinks(unittest.TestCase):
    def test_the_curated_documents_exist(self):
        # A renamed or moved file must fail here, not quietly leave the set.
        for name in CURATED_DOCUMENTS:
            self.assertTrue((ROOT / name).is_file(), f'{name} is missing')
        self.assertTrue(list((ROOT / 'docs').glob('*.md')), 'docs/*.md matched nothing')
        self.assertIn(CHOOSER, curated_documents())

    def test_no_curated_document_links_a_turned_off_feature(self):
        for path in curated_documents():
            with self.subTest(path.relative_to(ROOT)):
                self.assertEqual(turned_off_links(path.read_text()), [])

    def test_a_link_to_a_turned_off_feature_is_found(self):
        page = ('Questions and setup help live at\n'
                'https://github.com/archledger/irlume/discussions.')
        self.assertEqual(turned_off_links(page), [TURNED_OFF_URLS[0]])
        subpage = 'https://github.com/archledger/irlume/discussions/new'
        self.assertEqual(turned_off_links(subpage), [TURNED_OFF_URLS[0]])
        self.assertEqual(turned_off_links('https://github.com/archledger/irlume/issues'), [])
        self.assertEqual(turned_off_links('https://github.com/another/project/discussions'), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
