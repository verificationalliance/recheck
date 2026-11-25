"""scripts/queue.py reads the queue of results waiting for our re-check. Every field of an entry
reaches a checkout, an artifact name or a step's environment, so an entry with any field off its
pattern is dropped, and the reason given for a drop holds no text of the entry. An entry counts as
re-checked only by an artifact that a run of queue.yml on this repository's main uploaded. Run
with `python3 -I -m unittest discover -s tests`, or this file alone."""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'scripts', 'queue.py')

# By path, under another name: `queue` is also a module of the standard library.
_spec = importlib.util.spec_from_file_location('recheck_queue', SCRIPT)
q = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(q)

REPO_ID = 1471096694  # verificationalliance/recheck
SHA = 'ba4c212aefe24cded13faa30f781c4197751c8b9'
FIELDS = {
    'repo': 'github.com/verificationalliance/osva-monitor',
    'commit': '62af31fa2373855c2a84db4f8fb13763ff0b12c3',
    'run_id': 45534808080,
    'artifact_id': 14986317770,
    'signer_sha': SHA,
    'manifest': '.verificationalliance.json',
}
# Text that must never reach the log: it would be read as a workflow command.
HOSTILE = '::error::planted'
TAGS = '49cfc97142510641d339b20bac283c894f1ef10e\trefs/tags/workflow-7\n' + SHA + '\trefs/tags/workflow-7^{}\n'


def id_of(repo, run_id, artifact_id=FIELDS['artifact_id']):
    return hashlib.sha256(('%s@%s@%s' % (repo, run_id, artifact_id)).encode()).hexdigest()[:32]


def make(**changes):
    """An entry: FIELDS with the changes, and the id of its repo, run_id and artifact_id unless one is given."""
    e = dict(FIELDS)
    e.update(changes)
    if 'id' not in changes:
        e['id'] = id_of(e.get('repo'), e.get('run_id'), e.get('artifact_id'))
    return e


GOOD = make()


def several(n):
    return [make(run_id=i) for i in range(1, n + 1)]


def doc(*entries):
    return {'generated_at': '2026-11-25T02:00:00Z', 'entries': list(entries)}


class TestQueueValidate(unittest.TestCase):

    def assert_dropped(self, bad, reason):
        first = make(run_id=1)
        kept, reasons = q.validate(doc(first, bad))
        self.assertEqual(kept, [first])
        self.assertEqual(reasons, ['entry 2: ' + reason])

    def test_queue_validate(self):
        # The entry of the end-to-end test: OSVA Monitor's run with workflow-7, and its artifact.
        self.assertEqual(GOOD['id'], '8f4b2e916805a92b9104383c28c8a1f3')
        self.assertEqual(q.validate(doc(GOOD)), ([GOOD], []))
        for repo in ('github.com/verificationalliance/osva;monitor',
                     'github.com/verificationalliance/osva monitor',
                     'github.com/verificationalliance/..',
                     'github.com/verificationalliance/a..b',
                     'github.com/verificationalliance/.',
                     'github.com/../osva-monitor',
                     'github.com/-owner/osva-monitor',
                     'github.com/verificationalliance/osva-monitor/extra',
                     'github.com/verificationalliance/osva-monitor\n',
                     'gitlab.com/verificationalliance/osva-monitor',
                     'github.com.evil.example/verificationalliance/osva-monitor',
                     'https://github.com/verificationalliance/osva-monitor',
                     'verificationalliance/osva-monitor',
                     'github.com/' + 'a' * 40 + '/osva-monitor',
                     'github.com/verificationalliance/' + 'a' * 101,
                     'github.com/verificationalliance/osva-monitor' + HOSTILE,
                     ['github.com/verificationalliance/osva-monitor'], None):
            self.assert_dropped(make(repo=repo), q.R_REPO)
        for commit in (FIELDS['commit'][:39], FIELDS['commit'] + '0', FIELDS['commit'].upper(),
                       'g' * 40, FIELDS['commit'] + '\n', 7):
            self.assert_dropped(make(commit=commit), q.R_COMMIT)
        for run_id in ('1', 0, -1, 2 ** 53 + 1, 10 ** 15, 1.0, True, None):
            self.assert_dropped(make(run_id=run_id), q.R_RUN_ID)
        for run_id in (1, 45534808080, 10 ** 15 - 1):
            self.assertEqual(q.validate(doc(make(run_id=run_id)))[1], [])
        for artifact_id in ('1', '14986317770', 0, -1, 10 ** 15, 1.0, True, None, [1]):
            self.assert_dropped(make(artifact_id=artifact_id), q.R_ARTIFACT_ID)
        for artifact_id in (1, 14986317770, 10 ** 15 - 1):
            self.assertEqual(q.validate(doc(make(artifact_id=artifact_id)))[1], [])
        for id_ in (GOOD['id'].upper(), GOOD['id'][:31], GOOD['id'] + '0', GOOD['id'][:31] + 'g',
                    GOOD['id'] + '\n', 1):
            self.assert_dropped(make(id=id_), q.R_ID)
        for signer in (SHA[:39], SHA.upper(), SHA + '\n', None):
            self.assert_dropped(make(signer_sha=signer), q.R_SIGNER)
        for manifest in ('../x.json', 'a/../x.json', '/etc/passwd', '-x.json', 'a b.json',
                         'a;b.json', 'x.json\n', '', 'a' * 256, None):
            self.assert_dropped(make(manifest=manifest), q.R_MANIFEST)
        for manifest in ('.verificationalliance.json', 'proofs/core.json', './a.json', 'a' * 255):
            self.assertEqual(q.validate(doc(make(manifest=manifest)))[1], [])
        self.assert_dropped(make(note=HOSTILE), q.R_KEYS)
        for key in ('manifest', 'artifact_id'):
            missing = make()
            del missing[key]
            self.assert_dropped(missing, q.R_KEYS)
        self.assert_dropped('not an entry', q.R_NOT_OBJECT)
        self.assert_dropped(make(run_id=1, commit='0' * 40), q.R_DUPLICATE)

    def test_id_is_the_runs(self):
        """The id is sha256("<repo>@<run_id>@<artifact_id>")[:32], as the server makes it: an id of
        another run, of another artifact of the run (an attempt of it again), or of the same run of
        another repository, is not the entry's."""
        self.assert_dropped(make(id=id_of(FIELDS['repo'], 45534808081)), q.R_BINDING)
        self.assert_dropped(make(id=id_of(FIELDS['repo'], FIELDS['run_id'], 14986317771)), q.R_BINDING)
        self.assert_dropped(make(id=hashlib.sha256(('%s@%s' % (FIELDS['repo'], FIELDS['run_id'])).encode()).hexdigest()[:32]), q.R_BINDING)
        self.assert_dropped(make(id=id_of('github.com/verificationalliance/other', FIELDS['run_id'])), q.R_BINDING)
        self.assert_dropped(make(id=id_of(FIELDS['repo'].upper(), FIELDS['run_id'])), q.R_BINDING)
        self.assert_dropped(make(id='0' * 32), q.R_BINDING)
        self.assertEqual(q.entry_id(FIELDS['repo'], FIELDS['run_id'], FIELDS['artifact_id']), GOOD['id'])

    def test_over_50_entries(self):
        kept, reasons = q.validate(doc(*several(53)))
        self.assertEqual(kept, several(50))
        self.assertEqual(reasons, [q.R_OVER])
        # The first 50 count, even when some of them are dropped.
        kept, reasons = q.validate(doc(make(id='x'), *several(52)))
        self.assertEqual(kept, several(49))
        self.assertEqual(reasons, ['entry 1: ' + q.R_ID, q.R_OVER])

    def test_not_a_queue(self):
        for bad in ([], 'x', None, {'entries': []}, {'generated_at': '2026-11-25T02:00:00Z'},
                    dict(doc(), extra=1), dict(doc(), entries={}),
                    dict(doc(), generated_at='2026-11-25 02:00:00'),
                    dict(doc(), generated_at='2026-11-25T02:00:00+00:00'),
                    dict(doc(), generated_at=HOSTILE)):
            self.assertEqual(q.validate(bad), ([], [q.R_NOT_QUEUE]))
        self.assertEqual(q.validate(dict(doc(GOOD), generated_at='2026-11-25T02:00:00.123456Z'))[1], [])

    def test_reasons_hold_no_entry_text(self):
        bad = [make(repo=HOSTILE), make(commit=HOSTILE), make(run_id=HOSTILE), make(id=HOSTILE),
               make(signer_sha=HOSTILE), make(manifest=HOSTILE), make(**{HOSTILE: 1}), HOSTILE]
        _, reasons = q.validate(doc(*bad))
        self.assertEqual(len(reasons), len(bad))
        for reason in reasons:
            self.assertNotIn('planted', reason)
            self.assertFalse(reason.startswith('::'))


class TestLoad(unittest.TestCase):

    def load(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
        self.addCleanup(os.unlink, f.name)
        return q.load_queue(f.name)

    def test_load(self):
        self.assertEqual(self.load(json.dumps(doc(GOOD)).encode()), doc(GOOD))
        # A repeated key: which value counts would be the parser's choice.
        self.assertIsNone(self.load(b'{"generated_at": "2026-11-25T02:00:00Z", "entries": [], "entries": []}'))
        self.assertIsNone(self.load(b'{"generated_at": "2026-11-25T02:00:00Z", "entries": [{"id": 1, "id": 2}]}'))
        self.assertIsNone(self.load(b'{"generated_at": "2026-11-25T02:00:00Z", "entries": [NaN]}'))
        self.assertIsNone(self.load(b'{"generated_at": "\xff", "entries": []}'))
        self.assertIsNone(self.load(b'not json'))
        # Nested deeper than the parser's recursion limit.
        self.assertIsNone(self.load(b'{"generated_at": "2026-11-25T02:00:00Z", "entries": '
                                    + b'[' * 100_000 + b']' * 100_000 + b'}'))
        # Valid JSON either way: one byte over the limit is refused, the limit itself is not.
        at_limit = json.dumps(doc(GOOD)).encode().ljust(q.MAX_BYTES, b' ')
        self.assertEqual(self.load(at_limit), doc(GOOD))
        self.assertIsNone(self.load(at_limit + b' '))


def artifact(entry_id, run_id, **changes):
    """An artifact as GET /repos/verificationalliance/recheck/actions/artifacts?name= lists it."""
    a = {'id': 14987387055, 'name': 'osva-recheck-' + entry_id, 'expired': False,
         'workflow_run': {'id': run_id, 'repository_id': REPO_ID, 'head_repository_id': REPO_ID,
                          'head_branch': 'main', 'head_sha': 'f' * 40}}
    run = changes.pop('workflow_run', {})
    a.update(changes)
    a['workflow_run'].update(run)
    return a


def listing(*artifacts):
    return {'total_count': len(artifacts), 'artifacts': list(artifacts)}


def run(run_id, **changes):
    """A run as GET /repos/verificationalliance/recheck/actions/runs/<id> gives it."""
    r = {'id': run_id, 'name': 'queue', 'path': '.github/workflows/queue.yml', 'event': 'schedule',
         'head_branch': 'main', 'repository': {'id': REPO_ID}, 'head_repository': {'id': REPO_ID}}
    r.update(changes)
    return r


class TestDone(unittest.TestCase):
    """A re-check is done only when queue.yml, run on this repository's main, uploaded its
    artifact. Any workflow of a branch, a pull request from a fork, or another workflow here can
    upload an artifact of that name too."""

    def test_recheck_runs(self):
        i = GOOD['id']
        self.assertEqual(q.recheck_runs(i, listing(artifact(i, 7), artifact(i, 8), artifact(i, 7))), [7, 8])
        for bad in (artifact(i, 7, name='osva-recheck-' + '0' * 32),
                    artifact(i, 7, name='osva-recheck-' + i + 'x'),
                    artifact(i, 7, expired=True),
                    artifact(i, 7, expired=None),
                    artifact(i, 7, workflow_run={'repository_id': 1}),
                    # A pull request from a fork runs in this repository, from the fork's head.
                    artifact(i, 7, workflow_run={'head_repository_id': 2}),
                    artifact(i, 7, workflow_run={'head_branch': 'e2e-queue'}),
                    artifact(i, 7, workflow_run={'head_branch': None}),
                    artifact(i, '7'), artifact(i, True), artifact(i, 0),
                    {'name': 'osva-recheck-' + i}, 'x'):
            self.assertEqual(q.recheck_runs(i, listing(bad)), [], bad)
        for bad in (None, [], {'artifacts': None}, {'artifacts': 'x'}):
            self.assertEqual(q.recheck_runs(i, bad), [])

    def test_queue_run(self):
        self.assertTrue(q.queue_run(run(7)))
        self.assertTrue(q.queue_run(run(7, event='workflow_dispatch')))
        for bad in (run(7, path='.github/workflows/recheck.yml'), run(7, path='.github/workflows/tests.yml'),
                    run(7, path='.github/workflows/queue.yml@refs/heads/x'), run(7, path=None),
                    run(7, event='pull_request'), run(7, event='push'),
                    run(7, head_branch='e2e-queue'), run(7, repository={'id': 1}),
                    run(7, head_repository={'id': 2}), run(7, head_repository=None),
                    run(7, repository=None), {'id': 7}, None, 'x'):
            self.assertFalse(q.queue_run(bad), bad)

    def test_matrix_skips_done(self):
        a, b, c, d = several(4)
        artifacts = {
            a['id']: listing(),
            b['id']: listing(artifact(b['id'], 70)),
            # Planted by a workflow of a branch: not done.
            c['id']: listing(artifact(c['id'], 71, workflow_run={'head_branch': 'planted'})),
            # Its run is tests.yml's: not done.
            d['id']: listing(artifact(d['id'], 72)),
        }
        runs = {70: run(70), 72: run(72, path='.github/workflows/tests.yml', event='push')}
        done = q.done_ids([a, b, c, d], artifacts, runs)
        self.assertEqual(done, {b['id']})
        # A run that could not be read is no proof either.
        self.assertEqual(q.done_ids([b], artifacts, {}), set())
        self.assertEqual(q.done_ids([b], {}, runs), set())
        m = q.matrix([a, b, c, d], done)
        self.assertEqual([e['id'] for e in m], [a['id'], c['id'], d['id']])
        # Strings only: the workflow passes each to a string input, and a run id of 15 digits must
        # not become a float there.
        self.assertEqual(m[0], {k: str(v) for k, v in a.items()})
        self.assertEqual(q.matrix([a], {a['id']}), [])


class TestPages(unittest.TestCase):
    """GitHub lists an entry's artifacts 100 to a page, and others' runs (a fork's pull request)
    can upload artifacts by that name before ours: every page counts, up to the list's count and
    MAX_PAGES pages."""

    def folder(self, pages):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for n, page in enumerate(pages, 1):
            with open(os.path.join(d, 'artifacts-%s-%d.json' % (GOOD['id'], n)), 'w') as f:
                f.write(page if isinstance(page, str) else json.dumps(page))
        return d

    def test_done_on_a_later_page(self):
        i = GOOD['id']
        fork = [artifact(i, 9000 + n, workflow_run={'head_repository_id': 2}) for n in range(150)]
        pages = [{'total_count': 151, 'artifacts': fork[:100]}, {'total_count': 151, 'artifacts': fork[100:] + [artifact(i, 70)]}]
        d = self.folder(pages)
        self.assertTrue(q.more_pages(d, i, 1))
        self.assertFalse(q.more_pages(d, i, 2))
        self.assertEqual(q.recheck_runs(i, q.artifacts_of(d, i)), [70])
        self.assertEqual(q.done_ids([GOOD], {i: q.artifacts_of(d, i)}, {70: run(70)}), {i})
        self.assertEqual(q.recheck_runs(i, q.artifacts_of(self.folder(pages[:1]), i)), [], 'only the first page: not done')

    def test_more_pages(self):
        i = GOOD['id']
        full = {'total_count': 5000, 'artifacts': [artifact(i, 1)] * 100}   # it counts more than 10 pages hold
        d = self.folder([full] * q.MAX_PAGES)
        self.assertEqual([q.more_pages(d, i, n) for n in range(1, q.MAX_PAGES + 1)], [True] * (q.MAX_PAGES - 1) + [False])
        self.assertEqual(q.MAX_PAGES, 10)
        self.assertEqual(len(q.artifacts_of(self.folder([full] * (q.MAX_PAGES + 2)), i)['artifacts']), 100 * q.MAX_PAGES)
        for pages, why in (([{'total_count': 100, 'artifacts': [artifact(i, 1)] * 100}], 'all counted'),
                           ([{'total_count': 500, 'artifacts': []}], 'an empty page'),
                           ([{'artifacts': [artifact(i, 1)] * 100}], 'no count'),
                           ([{'total_count': '500', 'artifacts': [artifact(i, 1)] * 100}], 'a count that is not a number'),
                           (['[1, 2]'], 'not a page'), (['{'], 'not JSON')):
            self.assertFalse(q.more_pages(self.folder(pages), i, 1), why)
        self.assertFalse(q.more_pages(self.folder([full]), i, 2), 'page 2 not saved')
        for page in (0, -1):
            self.assertFalse(q.more_pages(d, i, page))
        broken = self.folder([full, '{', {'total_count': 1000, 'artifacts': [artifact(i, 70)]}])
        self.assertEqual(len(q.artifacts_of(broken, i)['artifacts']), 100, 'a page that is not one ends the list')

    def test_the_workflow_asks_each_page(self):
        text = workflow('queue.yml')
        for line in ('gh api "repos/verificationalliance/recheck/actions/artifacts?name=osva-recheck-$id&per_page=100&page=$page" \\\n',
                     '                > "$dir/artifacts-$id-$page.json"\n',
                     '              python3 -I scripts/queue.py more "$dir" "$id" "$page" || break\n',
                     '              page=$((page + 1))\n'):
            self.assertIn(line, text)

    def test_more_command(self):
        i = GOOD['id']
        d = self.folder([{'total_count': 200, 'artifacts': [artifact(i, 1)] * 100}])
        run_script = lambda *a: subprocess.run([sys.executable, '-I', SCRIPT, *a], capture_output=True, text=True, env={})
        self.assertEqual(run_script('more', d, i, '1').returncode, 0)
        self.assertEqual(run_script('more', d, i, '2').returncode, 1)
        for bad in (('more', d, '../x', '1'), ('more', d, i, '0'), ('more', d, i, 'x'), ('more', d, i)):
            out = run_script(*bad)
            self.assertNotEqual(out.returncode, 0, bad)
            self.assertNotIn('Traceback', out.stderr)


class TestReleases(unittest.TestCase):

    def test_releases(self):
        ls_remote = '\n'.join([
            '49cfc97142510641d339b20bac283c894f1ef10e\trefs/tags/workflow-7',
            SHA + '\trefs/tags/workflow-7^{}',
            '1111111111111111111111111111111111111111\trefs/tags/workflow-8',
            '2222222222222222222222222222222222222222\trefs/tags/other',
            '3333333333333333333333333333333333333333\trefs/tags/workflow-0',
            '4444444444444444444444444444444444444444\trefs/heads/workflow-9',
            '',
        ])
        shas = q.releases(ls_remote)
        # An annotated tag's commit, not the tag object; a lightweight tag's own commit.
        self.assertEqual(shas, {SHA, '1' * 40})
        fork = make(run_id=2, signer_sha='5' * 40)
        kept, reasons = q.released([GOOD, fork], shas)
        self.assertEqual(kept, [GOOD])
        self.assertEqual(reasons, ['1 entry: ' + q.R_RELEASE])


class TestActionPin(unittest.TestCase):

    LINE = '        uses: verificationalliance/verify/.github/actions/check@%s # workflow-7'

    @staticmethod
    def lean(*lines):
        return '\n'.join(['jobs:', '  check:', '    steps:', '      - name: Check the export',
                          *lines, '        with:', '          manifest: x', ''])

    def test_action_pin(self):
        pin = '3762b051c259ce791cf76af48c20ae3f1bbd5476'
        self.assertEqual(q.action_pin(self.lean(self.LINE % pin)), pin)
        self.assertEqual(q.action_pin(self.lean('        uses: verificationalliance/verify/.github/actions/check@' + pin)), pin)
        self.assertIsNone(q.action_pin(self.lean()))
        self.assertIsNone(q.action_pin(self.lean(self.LINE % pin, self.LINE % pin)))
        self.assertIsNone(q.action_pin(self.lean(self.LINE % pin, self.LINE % SHA)))
        # Any second mention counts, in another case or in a comment.
        self.assertIsNone(q.action_pin(self.lean(self.LINE % pin, '# VerificationAlliance/Verify/.github/actions/check@' + SHA)))
        self.assertIsNone(q.action_pin(self.lean(self.LINE % pin[:39])))
        self.assertIsNone(q.action_pin(self.lean(self.LINE % pin.upper())))
        self.assertIsNone(q.action_pin(self.lean('        uses: verificationalliance/verify/.github/actions/check@%s extra' % pin)))


def env_of(e):
    return {'ID': e['id'], 'REPO': e['repo'], 'COMMIT': e['commit'], 'RUN_ID': str(e['run_id']),
            'ARTIFACT_ID': str(e['artifact_id']), 'SIGNER_SHA': e['signer_sha'], 'MANIFEST': e['manifest']}


class TestEntry(unittest.TestCase):

    def env(self, **changes):
        e = env_of(GOOD)
        e.update(changes)
        return {k: v for k, v in e.items() if v is not None}

    def test_entry_from_env(self):
        self.assertEqual(q.entry_from_env(self.env()), GOOD)
        for bad in ({'RUN_ID': '01'}, {'RUN_ID': '1e3'}, {'RUN_ID': '1.0'}, {'RUN_ID': ' 1'},
                    {'RUN_ID': '٣'}, {'RUN_ID': '1' * 16}, {'RUN_ID': None}, {'REPO': HOSTILE},
                    {'MANIFEST': None}, {'ID': ''}, {'RUN_ID': '45534808081'}, {'ARTIFACT_ID': None},
                    {'ARTIFACT_ID': '01'}, {'ARTIFACT_ID': '1' * 16}, {'ARTIFACT_ID': '14986317771'}):
            self.assertIsNone(q.entry_from_env(self.env(**bad)), bad)

    def test_entry_from_env_released(self):
        self.assertEqual(q.entry_from_env(self.env(), {SHA}), GOOD)
        self.assertIsNone(q.entry_from_env(self.env(), {'1' * 40}))
        self.assertIsNone(q.entry_from_env(self.env(), set()))

    def test_canonical(self):
        text = q.canonical(GOOD)
        self.assertEqual(json.loads(text), GOOD)
        self.assertEqual(text, json.dumps(GOOD, sort_keys=True, separators=(',', ':')) + '\n')

    def test_same_entry(self):
        result = {'repo': GOOD['repo'], 'commit': GOOD['commit'], 'claims': []}
        self.assertTrue(q.same_entry(result, GOOD))
        self.assertFalse(q.same_entry(dict(result, repo=GOOD['repo'].upper()), GOOD))
        self.assertFalse(q.same_entry(dict(result, commit='0' * 40), GOOD))
        self.assertFalse(q.same_entry({'commit': GOOD['commit']}, GOOD))
        self.assertFalse(q.same_entry([], GOOD))


def workflow(name):
    with open(os.path.join(ROOT, '.github', 'workflows', name), encoding='utf-8') as f:
        return f.read()


def steps_named(text, prefix):
    """Each step whose name starts with `prefix`, as text, up to the next step or job."""
    found = []
    start = text.find('- name: ' + prefix)
    while start != -1:
        ends = [i for i in (text.find('\n      - name: ', start + 1), text.find('\n  sign:', start + 1)) if i != -1]
        found.append(text[start:min(ends) if ends else len(text)])
        start = text.find('- name: ' + prefix, start + 1)
    return found


class TestPassedThrough(unittest.TestCase):
    """What the developer's run gave lean.yml reaches the check action unchanged: the export's
    artifact is named after the manifest path, and the action writes the repository into
    result.json as given, so any change to either turns an honest result into a pending or a
    refused one."""

    def through_the_workflows(self, e):
        kept, reasons = q.validate(doc(e))
        self.assertEqual((kept, reasons), ([e], []))
        [m] = q.matrix(kept, set())
        # queue.yml hands the matrix values to recheck.yml's inputs, which reach queue.py's
        # environment as they are.
        env = {'ID': m['id'], 'REPO': m['repo'], 'COMMIT': m['commit'], 'RUN_ID': m['run_id'],
               'ARTIFACT_ID': m['artifact_id'], 'SIGNER_SHA': m['signer_sha'], 'MANIFEST': m['manifest']}
        self.assertEqual(q.entry_from_env(env), e)
        self.assertEqual(json.loads(q.canonical(q.entry_from_env(env))), e)
        return m

    def test_manifest_passed_through(self):
        for manifest in ('proofs/Core.verificationalliance.json', './A_b-c.json', FIELDS['manifest']):
            self.assertEqual(self.through_the_workflows(make(manifest=manifest))['manifest'], manifest)
        self.assertIn('      manifest: ${{ matrix.entry.manifest }}\n', workflow('queue.yml'))
        checks = steps_named(workflow('recheck.yml'), 'Check the export')
        self.assertTrue(checks)
        for check in checks:
            self.assertIn('uses: verificationalliance/verify/.github/actions/check@', check)
            self.assertIn('          manifest: ${{ inputs.manifest }}\n', check)

    def test_artifact_id_passed_through(self):
        for artifact_id in (1, 14986317770, 10 ** 15 - 1):
            self.assertEqual(self.through_the_workflows(make(artifact_id=artifact_id))['artifact_id'], str(artifact_id))
        self.assertIn('      artifact-id: ${{ matrix.entry.artifact_id }}\n', workflow('queue.yml'))
        text = workflow('recheck.yml')
        self.assertIn('      artifact-id:\n', text)
        for name in ('Check the entry', 'Validate the result'):
            [step] = steps_named(text, name)
            self.assertIn('          ARTIFACT_ID: ${{ inputs.artifact-id }}\n', step, name)

    def test_repo_case_kept(self):
        repo = 'github.com/VerificationAlliance/OSVA-Monitor.Lean_4'
        m = self.through_the_workflows(make(repo=repo))
        self.assertEqual(m['repo'], repo)
        result = {'repo': repo, 'commit': FIELDS['commit']}
        self.assertTrue(q.same_entry(result, make(repo=repo)))
        self.assertFalse(q.same_entry(dict(result, repo=repo.lower()), make(repo=repo)))
        # recheck.yml cuts the prefix off and changes nothing else, and both of the action's
        # repository inputs take that.
        text = workflow('recheck.yml')
        [entry_step] = steps_named(text, 'Check the entry')
        self.assertIn('          echo "repository=${REPO#github.com/}" >> "$GITHUB_OUTPUT"\n', entry_step)
        for check in steps_named(text, 'Check the export'):
            self.assertIn('          repository: ${{ steps.entry.outputs.repository }}\n', check)
            self.assertIn('          export-repository: ${{ steps.entry.outputs.repository }}\n', check)
        self.assertNotRegex(text + workflow('queue.yml'), r'(?i)lower|upper|,,|\^\^|tr \[')


class TestCommand(unittest.TestCase):
    """The script as the workflows run it: what reaches stdout ($GITHUB_OUTPUT or a file) and
    stderr (the log)."""

    def run_script(self, *args, env=None):
        return subprocess.run([sys.executable, '-I', SCRIPT, *args], capture_output=True, text=True,
                              env=env if env is not None else {})

    def folder(self, files):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for name, data in files.items():
            with open(os.path.join(d, name), 'wb') as f:
                f.write(data if isinstance(data, bytes) else data.encode())
        return d

    def test_plan(self):
        a, b, c = several(3)
        queue = json.dumps(doc(a, b, c, make(repo=HOSTILE), make(run_id=9, signer_sha='5' * 40)))
        d = self.folder({'queue.json': queue, 'releases': TAGS})
        p = lambda name: os.path.join(d, name)
        out = self.run_script('entries', p('queue.json'), p('releases'))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [a, b, c])
        self.assertNotIn('planted', out.stderr)
        self.assertIn('entry 4: ' + q.R_REPO, out.stderr)
        self.assertIn('1 entry: ' + q.R_RELEASE, out.stderr)
        self.assertIn('The queue lists 5 entries: 3 kept, 2 dropped.', out.stderr)
        with open(p('entries.json'), 'w') as f:
            f.write(out.stdout)

        out = self.run_script('ids', p('entries.json'))
        self.assertEqual((out.returncode, out.stdout), (0, ''.join(e['id'] + '\n' for e in (a, b, c))))

        # What the workflow then asks GitHub: each entry's artifacts, and the runs they name.
        for e, listed in ((a, listing()), (b, listing(artifact(b['id'], 70))),
                          (c, listing(artifact(c['id'], 71), artifact(c['id'], 70, workflow_run={'head_branch': 'x'})))):
            with open(p('artifacts-%s-1.json' % e['id']), 'w') as f:
                json.dump(listed, f)
        out = self.run_script('runs', d)
        self.assertEqual((out.returncode, out.stdout), (0, '70\n71\n'))
        with open(p('run-70.json'), 'w') as f:
            json.dump(run(70), f)
        with open(p('run-71.json'), 'w') as f:
            json.dump(run(71, path='.github/workflows/tests.yml'), f)

        out = self.run_script('plan', d)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = out.stdout.split('\n')
        self.assertEqual(lines[1:], [''])
        self.assertTrue(lines[0].startswith('matrix='))
        self.assertEqual([e['id'] for e in json.loads(lines[0][len('matrix='):])], [a['id'], c['id']])
        self.assertIn('Of 3 entries, 1 is re-checked already; 2 to re-check.', out.stderr)

    def test_plan_refuses_a_bad_queue(self):
        d = self.folder({'queue.json': b'{"entries": "' + HOSTILE.encode() + b'"}', 'releases': ''})
        out = self.run_script('entries', os.path.join(d, 'queue.json'), os.path.join(d, 'releases'))
        self.assertEqual((out.returncode, out.stdout), (1, ''))
        self.assertNotIn('planted', out.stderr)

    def test_plan_refuses_entries_it_did_not_write(self):
        d = self.folder({'entries.json': json.dumps([make(repo=HOSTILE)])})
        out = self.run_script('plan', d)
        self.assertEqual((out.returncode, out.stdout), (1, ''))
        self.assertEqual(self.run_script('ids', os.path.join(d, 'entries.json')).returncode, 1)
        self.assertNotIn('planted', out.stderr)

    def test_plan_with_nothing_to_do(self):
        d = self.folder({'queue.json': json.dumps(doc()), 'releases': ''})
        out = self.run_script('entries', os.path.join(d, 'queue.json'), os.path.join(d, 'releases'))
        self.assertEqual((out.returncode, out.stdout), (0, '[]\n'))
        d = self.folder({'entries.json': json.dumps([GOOD]),
                         'artifacts-%s-1.json' % GOOD['id']: json.dumps(listing(artifact(GOOD['id'], 70))),
                         'run-70.json': json.dumps(run(70))})
        out = self.run_script('plan', d)
        self.assertEqual(out.stdout, 'matrix=[]\n')
        self.assertIn('Of 1 entry, 1 is re-checked already; 0 to re-check.', out.stderr)

    def test_entry_and_same_entry(self):
        env = env_of(GOOD)
        out = self.run_script('entry', env=env)
        self.assertEqual((out.returncode, out.stdout), (0, q.canonical(GOOD)))
        out = self.run_script('entry', env=dict(env, REPO=HOSTILE))
        self.assertEqual((out.returncode, out.stdout), (1, ''))
        self.assertNotIn('planted', out.stderr + out.stdout)
        # With the releases, the signer must be one.
        d = self.folder({'releases': TAGS, 'none': '',
                         'result.json': json.dumps({'repo': GOOD['repo'], 'commit': GOOD['commit']}),
                         'deep.json': '[' * 100_000 + ']' * 100_000})
        self.assertEqual(self.run_script('entry', os.path.join(d, 'releases'), env=env).returncode, 0)
        out = self.run_script('entry', os.path.join(d, 'none'), env=env)
        self.assertEqual((out.returncode, out.stdout), (1, ''))
        result = os.path.join(d, 'result.json')
        self.assertEqual(self.run_script('same-entry', result, env=env).returncode, 0)
        self.assertEqual(self.run_script('same-entry', result, env=dict(env, COMMIT='0' * 40)).returncode, 1)
        out = self.run_script('same-entry', os.path.join(d, 'deep.json'), env=env)
        self.assertEqual(out.returncode, 1)
        self.assertNotIn('Traceback', out.stderr)

    def test_pin(self):
        d = self.folder({'lean.yml': TestActionPin.lean(TestActionPin.LINE % SHA),
                         'twice.yml': TestActionPin.lean(TestActionPin.LINE % SHA, TestActionPin.LINE % SHA)})
        out = self.run_script('pin', os.path.join(d, 'lean.yml'))
        self.assertEqual((out.returncode, out.stdout), (0, SHA + '\n'))
        out = self.run_script('pin', os.path.join(d, 'twice.yml'))
        self.assertEqual((out.returncode, out.stdout), (1, ''))


if __name__ == '__main__':
    unittest.main()
