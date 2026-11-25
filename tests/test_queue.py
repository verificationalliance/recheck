"""scripts/queue.py reads the queue of results waiting for our re-check. Every field of an entry
reaches a checkout, an artifact name or a step's environment, so an entry with any field off its
pattern is dropped, and the reason given for a drop holds no text of the entry. Run with
`python3 -I -m unittest discover -s tests`, or this file alone."""
import importlib.util
import json
import os
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

SHA = 'ba4c212aefe24cded13faa30f781c4197751c8b9'
GOOD = {
    'id': '0123456789abcdef0123456789abcdef',
    'repo': 'github.com/verificationalliance/osva-monitor',
    'commit': 'a7804efd7818708b6a1dbccff33fd87c0c0abfc6',
    'run_id': 45534808080,
    'signer_sha': SHA,
    'manifest': '.verificationalliance.json',
}
# Text that must never reach the log: it would be read as a workflow command.
HOSTILE = '::error::planted'


def entry(**changes):
    e = dict(GOOD)
    e.update(changes)
    return e


def doc(*entries):
    return {'generated_at': '2026-11-25T02:00:00Z', 'entries': list(entries)}


def ids(n):
    return ['%032x' % i for i in range(1, n + 1)]


class TestQueueValidate(unittest.TestCase):

    def assert_dropped(self, bad, reason):
        kept, reasons = q.validate(doc(entry(id='f' * 32), bad))
        self.assertEqual([e['id'] for e in kept], ['f' * 32])
        self.assertEqual(reasons, ['entry 2: ' + reason])

    def test_queue_validate(self):
        kept, reasons = q.validate(doc(GOOD))
        self.assertEqual(kept, [GOOD])
        self.assertEqual(reasons, [])
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
            self.assert_dropped(entry(repo=repo), q.R_REPO)
        for commit in (GOOD['commit'][:39], GOOD['commit'] + '0', GOOD['commit'].upper(),
                       'g' * 40, GOOD['commit'] + '\n', 7):
            self.assert_dropped(entry(commit=commit), q.R_COMMIT)
        for run_id in ('1', 0, -1, 2 ** 53 + 1, 10 ** 15, 1.0, True, None):
            self.assert_dropped(entry(run_id=run_id), q.R_RUN_ID)
        for run_id in (1, 45534808080, 10 ** 15 - 1):
            self.assertEqual(q.validate(doc(entry(run_id=run_id)))[1], [])
        for id_ in ('0123456789ABCDEF0123456789ABCDEF', GOOD['id'][:31], GOOD['id'] + '0',
                    GOOD['id'][:31] + 'g', GOOD['id'] + '\n', 1):
            self.assert_dropped(entry(id=id_), q.R_ID)
        for signer in (SHA[:39], SHA.upper(), SHA + '\n', None):
            self.assert_dropped(entry(signer_sha=signer), q.R_SIGNER)
        for manifest in ('../x.json', 'a/../x.json', '/etc/passwd', '-x.json', 'a b.json',
                         'a;b.json', 'x.json\n', '', 'a' * 256, None):
            self.assert_dropped(entry(manifest=manifest), q.R_MANIFEST)
        for manifest in ('.verificationalliance.json', 'proofs/core.json', './a.json', 'a' * 255):
            self.assertEqual(q.validate(doc(entry(manifest=manifest)))[1], [])
        extra = entry(note=HOSTILE)
        self.assert_dropped(extra, q.R_KEYS)
        missing = entry()
        del missing['manifest']
        self.assert_dropped(missing, q.R_KEYS)
        self.assert_dropped('not an entry', q.R_NOT_OBJECT)
        self.assert_dropped(entry(id='f' * 32, commit='0' * 40), q.R_DUPLICATE)

    def test_over_50_entries(self):
        kept, reasons = q.validate(doc(*[entry(id=i) for i in ids(53)]))
        self.assertEqual([e['id'] for e in kept], ids(50))
        self.assertEqual(reasons, [q.R_OVER])
        # The first 50 count, even when some of them are dropped.
        kept, reasons = q.validate(doc(entry(id='x'), *[entry(id=i) for i in ids(52)]))
        self.assertEqual([e['id'] for e in kept], ids(49))
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
        bad = [entry(repo=HOSTILE), entry(commit=HOSTILE), entry(run_id=HOSTILE), entry(id=HOSTILE),
               entry(signer_sha=HOSTILE), entry(manifest=HOSTILE), entry(**{HOSTILE: 1}), HOSTILE]
        _, reasons = q.validate(doc(*bad))
        self.assertEqual(len(reasons), len(bad))
        for reason in reasons:
            self.assertNotIn('planted', reason)
            self.assertFalse(reason.startswith('::'))


def workflow(name):
    with open(os.path.join(ROOT, '.github', 'workflows', name), encoding='utf-8') as f:
        return f.read()


def step(text, name):
    """The step called `name` in a workflow's text, up to the next step."""
    start = text.index('- name: ' + name + '\n')
    end = text.find('\n      - name: ', start + 1)
    return text[start:end if end != -1 else len(text)]


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
               'SIGNER_SHA': m['signer_sha'], 'MANIFEST': m['manifest']}
        self.assertEqual(q.entry_from_env(env), e)
        self.assertEqual(json.loads(q.canonical(q.entry_from_env(env))), e)
        return m

    def test_manifest_passed_through(self):
        for manifest in ('proofs/Core.verificationalliance.json', './A_b-c.json', GOOD['manifest']):
            self.assertEqual(self.through_the_workflows(entry(manifest=manifest))['manifest'], manifest)
        self.assertIn('      manifest: ${{ matrix.entry.manifest }}\n', workflow('queue.yml'))
        check = step(workflow('recheck.yml'), 'Check the export')
        self.assertIn('uses: ./verify-action/.github/actions/check\n', check)
        self.assertIn('          manifest: ${{ inputs.manifest }}\n', check)

    def test_repo_case_kept(self):
        repo = 'github.com/VerificationAlliance/OSVA-Monitor.Lean_4'
        m = self.through_the_workflows(entry(repo=repo))
        self.assertEqual(m['repo'], repo)
        result = {'repo': repo, 'commit': GOOD['commit']}
        self.assertTrue(q.same_entry(result, entry(repo=repo)))
        self.assertFalse(q.same_entry(dict(result, repo=repo.lower()), entry(repo=repo)))
        # recheck.yml cuts the prefix off and changes nothing else, and both of the action's
        # repository inputs take that.
        text = workflow('recheck.yml')
        self.assertIn('          echo "repository=${REPO#github.com/}" >> "$GITHUB_OUTPUT"\n',
                      step(text, 'Check the entry'))
        check = step(text, 'Check the export')
        self.assertIn('          repository: ${{ steps.entry.outputs.repository }}\n', check)
        self.assertIn('          export-repository: ${{ steps.entry.outputs.repository }}\n', check)
        self.assertNotRegex(text + workflow('queue.yml'), r'(?i)lower|upper|,,|\^\^|tr \[')


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
        # Valid JSON either way: one byte over the limit is refused, the limit itself is not.
        at_limit = json.dumps(doc(GOOD)).encode().ljust(q.MAX_BYTES, b' ')
        self.assertEqual(self.load(at_limit), doc(GOOD))
        self.assertIsNone(self.load(at_limit + b' '))


class TestMatrix(unittest.TestCase):

    def test_matrix_skips_done(self):
        a, b, c = (entry(id=i) for i in ('a' * 32, 'b' * 32, 'c' * 32))
        names = '\n'.join(['osva-recheck-' + 'b' * 32, 'osva-recheck-' + 'c' * 32 + 'x',
                           'osva-recheck-' + 'C' * 32, 'x-osva-recheck-' + 'c' * 32, 'export-0123456789abcdef', ''])
        done = q.done_ids(names)
        self.assertEqual(done, {'b' * 32})
        m = q.matrix([a, b, c], done)
        self.assertEqual([e['id'] for e in m], ['a' * 32, 'c' * 32])
        # Strings only: the workflow passes each to a string input, and a run id of 15 digits must
        # not become a float there.
        self.assertEqual(m[0], {k: str(v) for k, v in a.items()})
        self.assertEqual(q.matrix([a], {a['id']}), [])

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
        fork = entry(id=ids(2)[1], signer_sha='5' * 40)
        kept, reasons = q.released([GOOD, fork], shas)
        self.assertEqual(kept, [GOOD])
        self.assertEqual(reasons, ['1 entry: ' + q.R_RELEASE])


class TestActionPin(unittest.TestCase):

    LINE = '        uses: verificationalliance/verify/.github/actions/check@%s # workflow-7'

    def lean(self, *lines):
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


class TestEntry(unittest.TestCase):

    def env(self, **changes):
        e = {'ID': GOOD['id'], 'REPO': GOOD['repo'], 'COMMIT': GOOD['commit'],
             'RUN_ID': str(GOOD['run_id']), 'SIGNER_SHA': GOOD['signer_sha'], 'MANIFEST': GOOD['manifest']}
        e.update(changes)
        return {k: v for k, v in e.items() if v is not None}

    def test_entry_from_env(self):
        self.assertEqual(q.entry_from_env(self.env()), GOOD)
        for bad in ({'RUN_ID': '01'}, {'RUN_ID': '1e3'}, {'RUN_ID': '1.0'}, {'RUN_ID': ' 1'},
                    {'RUN_ID': '٣'}, {'RUN_ID': '1' * 16}, {'RUN_ID': None}, {'REPO': HOSTILE},
                    {'MANIFEST': None}, {'ID': ''}):
            self.assertIsNone(q.entry_from_env(self.env(**bad)), bad)

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


class TestCommand(unittest.TestCase):
    """The script as the workflow runs it: what reaches stdout ($GITHUB_OUTPUT) and stderr (the
    log)."""

    def run_script(self, *args, env=None):
        return subprocess.run([sys.executable, '-I', SCRIPT, *args], capture_output=True, text=True,
                              env=env if env is not None else {})

    def files(self, queue, artifacts, releases):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: [os.unlink(os.path.join(d, f)) for f in os.listdir(d)] and os.rmdir(d))
        paths = []
        for name, data in (('queue.json', queue), ('artifacts', artifacts), ('releases', releases)):
            paths.append(os.path.join(d, name))
            with open(paths[-1], 'wb') as f:
                f.write(data if isinstance(data, bytes) else data.encode())
        return paths

    def test_plan(self):
        a, b, c = (entry(id=i) for i in ids(3))
        queue = json.dumps(doc(a, b, c, entry(repo=HOSTILE), entry(signer_sha='5' * 40, id='e' * 32)))
        tags = '49cfc97142510641d339b20bac283c894f1ef10e\trefs/tags/workflow-7\n' + SHA + '\trefs/tags/workflow-7^{}\n'
        out = self.run_script('plan', *self.files(queue, 'osva-recheck-' + ids(3)[1] + '\n', tags))
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = out.stdout.split('\n')
        self.assertEqual(lines[1:], [''])
        self.assertTrue(lines[0].startswith('matrix='))
        self.assertEqual([e['id'] for e in json.loads(lines[0][len('matrix='):])], [ids(3)[0], ids(3)[2]])
        self.assertNotIn('planted', out.stderr)
        self.assertIn('entry 4: ' + q.R_REPO, out.stderr)
        self.assertIn('1 entry: ' + q.R_RELEASE, out.stderr)
        self.assertIn('The queue lists 5 entries: 3 to re-check, 1 of them done; 2 dropped.', out.stderr)

    def test_plan_refuses_a_bad_queue(self):
        out = self.run_script('plan', *self.files(b'{"entries": "' + HOSTILE.encode() + b'"}', '', ''))
        self.assertEqual(out.returncode, 1)
        self.assertEqual(out.stdout, '')
        self.assertNotIn('planted', out.stderr)

    def test_plan_with_nothing_to_do(self):
        out = self.run_script('plan', *self.files(json.dumps(doc()), '', ''))
        self.assertEqual((out.returncode, out.stdout), (0, 'matrix=[]\n'))

    def test_entry_and_same_entry(self):
        env = {'ID': GOOD['id'], 'REPO': GOOD['repo'], 'COMMIT': GOOD['commit'], 'RUN_ID': str(GOOD['run_id']),
               'SIGNER_SHA': GOOD['signer_sha'], 'MANIFEST': GOOD['manifest']}
        out = self.run_script('entry', env=env)
        self.assertEqual((out.returncode, out.stdout), (0, q.canonical(GOOD)))
        out = self.run_script('entry', env=dict(env, REPO=HOSTILE))
        self.assertEqual((out.returncode, out.stdout), (1, ''))
        self.assertNotIn('planted', out.stderr + out.stdout)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump({'repo': GOOD['repo'], 'commit': GOOD['commit']}, f)
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(self.run_script('same-entry', f.name, env=env).returncode, 0)
        self.assertEqual(self.run_script('same-entry', f.name, env=dict(env, COMMIT='0' * 40)).returncode, 1)

    def test_pin(self):
        with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as f:
            f.write(TestActionPin().lean(TestActionPin.LINE % SHA))
        self.addCleanup(os.unlink, f.name)
        out = self.run_script('pin', f.name)
        self.assertEqual((out.returncode, out.stdout), (0, SHA + '\n'))
        with open(f.name, 'a') as g:
            g.write(TestActionPin.LINE % SHA + '\n')
        out = self.run_script('pin', f.name)
        self.assertEqual((out.returncode, out.stdout), (1, ''))


if __name__ == '__main__':
    unittest.main()
