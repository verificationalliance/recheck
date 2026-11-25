"""The rules every workflow here keeps, read from the files as text (the standard library has no YAML):
- every action is pinned by a full commit SHA with a version comment, or is a local ./ path;
- every checkout has persist-credentials: false;
- no run: script holds an expression: a value reaches a script only through env, as data;
- every job runs on ubuntu-24.04, GitHub's standard runner;
- id-token: write is in recheck.yml's sign job only, and in the queue.yml job that calls it, which
  sets what its jobs may have at most;
- recheck.yml runs the check action from verify-action/, and only from there."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, '.github', 'workflows')
PINNED = re.compile(r'[A-Za-z0-9-]+/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?@[0-9a-f]{40} # v?[0-9][0-9.]*')


def indent(line):
    return len(line) - len(line.lstrip(' '))


def block(lines, i):
    """The lines indented below line i, up to the next line that is not."""
    out = []
    for line in lines[i + 1:]:
        if line.strip() and indent(line) <= indent(lines[i]):
            break
        out.append(line)
    return out


def step_of(lines, i):
    """Line i's step: from the `- ` line that starts it, through the lines below that."""
    j = i
    while not re.match(r' *- ', lines[j]) or indent(lines[j]) > indent(lines[i]):
        j -= 1
    return [lines[j]] + block(lines, j)


def job_of(lines, i):
    for j in range(i, -1, -1):
        m = re.fullmatch(r'  ([a-z-]+):', lines[j])
        if m:
            return m.group(1)
    return None


def workflows():
    names = sorted(f for f in os.listdir(WORKFLOWS) if f.endswith('.yml'))
    found = {}
    for name in names:
        with open(os.path.join(WORKFLOWS, name), encoding='utf-8') as f:
            found[name] = f.read().split('\n')
    return found


class TestWorkflows(unittest.TestCase):

    def test_files(self):
        self.assertEqual(sorted(workflows()), ['queue.yml', 'recheck.yml'])

    def test_actions_pinned(self):
        count = 0
        for name, lines in workflows().items():
            for line in lines:
                m = re.fullmatch(r' *(?:- )?uses: (.*)', line)
                if m:
                    count += 1
                    ok = PINNED.fullmatch(m.group(1)) or re.fullmatch(r'\./[A-Za-z0-9._/-]+', m.group(1))
                    self.assertTrue(ok, '%s: %s' % (name, line))
        self.assertGreater(count, 5)

    def test_checkouts_keep_no_credentials(self):
        count = 0
        for name, lines in workflows().items():
            for i, line in enumerate(lines):
                if re.search(r'uses: actions/checkout@', line):
                    count += 1
                    step = [s.strip() for s in step_of(lines, i)]
                    self.assertIn('persist-credentials: false', step, '%s line %d' % (name, i + 1))
        self.assertEqual(count, 5)

    def test_no_expression_in_a_script(self):
        count = 0
        for name, lines in workflows().items():
            for i, line in enumerate(lines):
                m = re.fullmatch(r' *(?:- )?run: (.*)', line)
                if m:
                    count += 1
                    script = [m.group(1)] + block(lines, i)
                    for s in script:
                        self.assertNotIn('${{', s, '%s line %d' % (name, i + 1))
        self.assertGreater(count, 5)

    def test_runners(self):
        for name, lines in workflows().items():
            runs_on = [line.strip() for line in lines if re.fullmatch(r' *runs-on: .*', line)]
            self.assertTrue(runs_on, name)
            self.assertEqual(set(runs_on), {'runs-on: ubuntu-24.04'}, name)

    def test_id_token_only_where_signing(self):
        found = set()
        for name, lines in workflows().items():
            for i, line in enumerate(lines):
                if re.fullmatch(r' *(id-token|attestations): write', line):
                    found.add((name, job_of(lines, i), line.strip()))
        self.assertEqual(found, {
            ('recheck.yml', 'sign', 'id-token: write'), ('recheck.yml', 'sign', 'attestations: write'),
            ('queue.yml', 'recheck', 'id-token: write'), ('queue.yml', 'recheck', 'attestations: write'),
        })

    def test_jobs_run_only_here(self):
        lines = workflows()['recheck.yml']
        jobs = [i for i, line in enumerate(lines) if re.fullmatch(r'  [a-z-]+:', line) and i > lines.index('jobs:')]
        self.assertEqual([lines[i].strip() for i in jobs], ['check:', 'sign:'])
        for i in jobs:
            self.assertIn("    if: github.repository == 'verificationalliance/recheck'", block(lines, i))

    def test_check_action(self):
        text = '\n'.join(workflows()['recheck.yml'])
        self.assertEqual(re.findall(r'^ *(?:- )?uses: (\./.*)$', text, re.M), ['./verify-action/.github/actions/check'])
        self.assertEqual(text.count('path: verify-action'), 1)


if __name__ == '__main__':
    unittest.main()
