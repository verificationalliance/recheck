"""The rules the workflows here keep, read from the files as text (the standard library has no YAML):
- every action is pinned by a full commit SHA with a version comment;
- every checkout has persist-credentials: false;
- no run: script holds an expression: a value reaches a script only through env, as data;
- every job runs on ubuntu-24.04, GitHub's standard runner, and only in this repository;
- id-token: write is in recheck.yml's sign job only, and in the queue.yml job that calls it, which
  sets what its jobs may have at most;
- recheck.yml runs the check action of each workflow release it knows by a step of its own, pinned
  to the commit that release's lean.yml pins, and runs no other;
- the steps that keep the trust boundary are there: the entry's checks, the result's validation,
  and sign taking the result from check's output only;
- sign signs under the predicate type of the result's own schema (v2), and a check of ours that
  stopped is counted and failed, never signed;
- queue.yml dispatches its own next run (GitHub's scheduler does not run it), with actions: write
  only, from main only, and never beside another run of it waiting or running.
With RECHECK_ONLINE=1, as in tests.yml, queue.py's RELEASES and recheck.yml's checker are checked
against verificationalliance/verify."""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The runs of queue.yml besides this one that wait or run, as the next job counts them.
OTHERS = '[.workflow_runs[] | select(.id != ($ENV.GITHUB_RUN_ID | tonumber) and .status != "completed")] | length'
WORKFLOWS = os.path.join(ROOT, '.github', 'workflows')
PINNED = re.compile(r'[A-Za-z0-9-]+/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?@[0-9a-f]{40} # \S+')
GUARD = "if: github.repository == 'verificationalliance/recheck'"
LS_REMOTE = "git ls-remote --tags https://github.com/verificationalliance/verify 'refs/tags/workflow-*'"

_spec = importlib.util.spec_from_file_location('recheck_queue', os.path.join(ROOT, 'scripts', 'queue.py'))
q = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(q)

# The workflow releases recheck.yml re-checks (queue.py's): each release's commit, and the commit of
# the check action that its lean.yml pins. Adding a release adds a line there and a step to
# recheck.yml.
RELEASES = q.RELEASES
VACHECK = ('https://github.com/verificationalliance/verify/releases/download/v2.0.2/vacheck.pyz',
           'b98de62f3e813c89f1f31224ad226db0b2bc916d9202edd06676c6eba1c9f905')


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


def workflows():
    found = {}
    for name in sorted(f for f in os.listdir(WORKFLOWS) if f.endswith('.yml')):
        with open(os.path.join(WORKFLOWS, name), encoding='utf-8') as f:
            found[name] = f.read().split('\n')
    return found


def jobs(lines):
    """Each job's name and lines, below `jobs:`."""
    start = lines.index('jobs:')
    return {m.group(1): block(lines, i) for i, line in enumerate(lines) if i > start
            for m in [re.fullmatch(r'  ([A-Za-z0-9_-]+):', line)] if m}


def job_of(lines, i):
    for j in range(i, -1, -1):
        m = re.fullmatch(r'  ([A-Za-z0-9_-]+):', lines[j])
        if m:
            return m.group(1)
    return None


def steps(job_lines):
    """Each step of a job: its name, and its lines."""
    found = []
    for i, line in enumerate(job_lines):
        m = re.fullmatch(r'      - name: (.*)', line)
        if m:
            found.append((m.group(1), [line] + block(job_lines, i)))
    return found


def step(job_lines, name):
    [found] = [s for n, s in steps(job_lines) if n == name]
    return found


def script(step_lines):
    """A step's run: script, as lines."""
    i = [k for k, line in enumerate(step_lines) if line.strip().startswith('run:')][0]
    return [step_lines[i]] + block(step_lines, i)


def value(step_lines, key):
    found = [line.strip()[len(key) + 2:] for line in step_lines if line.strip().startswith(key + ': ')]
    return found[0] if len(found) == 1 else None


class TestWorkflows(unittest.TestCase):

    def test_files(self):
        self.assertEqual(sorted(workflows()), ['queue.yml', 'recheck.yml', 'tests.yml'])

    def test_actions_pinned(self):
        count = 0
        for name, lines in workflows().items():
            for line in lines:
                m = re.fullmatch(r' *(?:- )?uses: (.*)', line)
                if m:
                    count += 1
                    ok = PINNED.fullmatch(m.group(1)) or (name == 'queue.yml' and m.group(1) == './.github/workflows/recheck.yml')
                    self.assertTrue(ok, '%s: %s' % (name, line))
        self.assertGreater(count, 5)

    def test_checkouts_keep_no_credentials(self):
        count = 0
        for name, lines in workflows().items():
            for i, line in enumerate(lines):
                if re.search(r'uses: actions/checkout@', line):
                    count += 1
                    self.assertIn('persist-credentials: false', [s.strip() for s in step_of(lines, i)],
                                  '%s line %d' % (name, i + 1))
        self.assertEqual(count, 5)

    def test_no_expression_in_a_script(self):
        count = 0
        for name, lines in workflows().items():
            for i, line in enumerate(lines):
                m = re.fullmatch(r' *(?:- )?run: (.*)', line)
                if m:
                    count += 1
                    for s in [m.group(1)] + block(lines, i):
                        self.assertNotIn('${{', s, '%s line %d' % (name, i + 1))
        self.assertGreater(count, 5)

    def test_runners(self):
        for name, lines in workflows().items():
            runs_on = [line.strip() for line in lines if re.fullmatch(r' *runs-on: .*', line)]
            self.assertTrue(runs_on, name)
            self.assertEqual(set(runs_on), {'runs-on: ubuntu-24.04'}, name)

    def test_jobs_run_only_here(self):
        """A workflow of another repository can call recheck.yml, and a fork runs copies of them all:
        every job's condition starts with this repository, which GitHub evaluates, not the runner."""
        found = {}
        for name, lines in workflows().items():
            for job, body in jobs(lines).items():
                conditions = [line for line in body if line.startswith('    if: ')]
                found[name, job] = len(conditions)
                self.assertEqual(len(conditions), 1, (name, job))
                self.assertTrue(conditions[0] == '    ' + GUARD or conditions[0].startswith('    ' + GUARD + ' && '),
                                (name, job, conditions[0]))
        self.assertEqual(sorted(found), [('queue.yml', 'next'), ('queue.yml', 'plan'), ('queue.yml', 'recheck'),
                                         ('recheck.yml', 'check'), ('recheck.yml', 'sign'), ('tests.yml', 'unit')])

    def test_jobs_regex_reads_every_name(self):
        lines = ['jobs:', '  upload_2:', '    if: x', '  a-b:', '    runs-on: y']
        self.assertEqual(sorted(jobs(lines)), ['a-b', 'upload_2'])
        self.assertEqual(job_of(lines, 2), 'upload_2')

    def test_id_token_only_where_signing(self):
        found = set()
        for name, lines in workflows().items():
            for i, line in enumerate(lines):
                if re.fullmatch(r' *(id-token|attestations|actions|contents|packages|pull-requests|statuses'
                                r'|checks|deployments|issues|pages|security-events|discussions|repository-projects): write',
                                line):
                    found.add((name, job_of(lines, i), line.strip()))
        self.assertEqual(found, {
            ('recheck.yml', 'sign', 'id-token: write'), ('recheck.yml', 'sign', 'attestations: write'),
            ('queue.yml', 'recheck', 'id-token: write'), ('queue.yml', 'recheck', 'attestations: write'),
            ('queue.yml', 'next', 'actions: write'),
        })

    def permissions(self, job_lines):
        i = job_lines.index('    permissions:')
        return [line.strip() for line in block(job_lines, i) if line.strip()]

    def test_permissions(self):
        w = workflows()
        recheck, queue, tests = jobs(w['recheck.yml']), jobs(w['queue.yml']), jobs(w['tests.yml'])
        self.assertEqual(self.permissions(recheck['check']), ['contents: read', 'actions: read'])
        self.assertEqual(self.permissions(recheck['sign']), ['contents: read', 'id-token: write', 'attestations: write'])
        self.assertEqual(self.permissions(queue['plan']), ['contents: read', 'actions: read'])
        self.assertEqual(self.permissions(queue['next']), ['actions: write'])
        self.assertEqual(self.permissions(tests['unit']), ['contents: read'])
        for name, lines in w.items():
            top = lines.index('permissions:')
            self.assertEqual([line.strip() for line in block(lines, top) if line.strip()], ['contents: read'], name)

    def test_ls_remote_reads_verify_only(self):
        count = 0
        for name, lines in workflows().items():
            for line in lines:
                if 'ls-remote' in line:
                    count += 1
                    self.assertRegex(line.strip(), r'^' + re.escape(LS_REMOTE) + r' (>|\\$)', name)
        self.assertEqual(count, 2)


class TestRecheck(unittest.TestCase):
    """recheck.yml's two jobs."""

    def setUp(self):
        self.lines = workflows()['recheck.yml']
        self.text = '\n'.join(self.lines)
        self.jobs = jobs(self.lines)

    def test_check_steps_are_the_releases(self):
        check = self.jobs['check']
        statics = [(n, s) for n, s in steps(check) if n.startswith('Check the export')]
        self.assertEqual([n for n, _ in statics], ['Check the export (workflow-%d)' % n for n in sorted(RELEASES)])
        for (_, s), n in zip(statics, sorted(RELEASES)):
            pin = RELEASES[n][1]
            self.assertEqual(value(s, 'id'), 'result_%d' % n)
            self.assertEqual(value(s, 'if'), "steps.pin.outputs.pin == '%s'" % pin)
            self.assertEqual(value(s, 'uses'), 'verificationalliance/verify/.github/actions/check@%s # workflow-%d-action' % (pin, n))
        # A pin of none of them fails the job.
        pin_step = step(check, "Read the check action's pin")
        self.assertEqual(value(pin_step, 'KNOWN'), '"%s"' % ' '.join(RELEASES[n][1] for n in sorted(RELEASES)))
        run = '\n'.join(script(pin_step))
        self.assertIn('pin=$(python3 -I recheck/scripts/queue.py pin signer/.github/workflows/lean.yml)', run)
        self.assertIn('if [[ " $KNOWN " != *" $pin "* ]]; then', run)
        self.assertIn('  exit 1\n', run)
        # The job's result is the output of the step that ran.
        outputs = block(check, check.index('    outputs:'))
        self.assertEqual([line.strip() for line in outputs],
                         ['result: ${{ %s }}' % ' || '.join('steps.result_%d.outputs.result' % n for n in sorted(RELEASES))])
        # No action from the workspace: the runner would read it again after the developer's
        # checkout replaced it.
        self.assertNotRegex(self.text, r'uses: \./|verify-action')

    def test_timeouts(self):
        # The release's own check job: the kernels' replay, then the sanity step's 30-minute
        # safety net, which must not be what stops the job.
        self.assertIn('    timeout-minutes: 240', self.jobs['check'])
        self.assertIn('    timeout-minutes: 15', self.jobs['sign'])
        self.assertEqual(sorted(RELEASES), [10])

    def test_check_checks_the_entry(self):
        check = self.jobs['check']
        names = [n for n, _ in steps(check)]
        self.assertEqual(names[:4], ["Check out the re-check's scripts", 'Check the entry',
                                     'Check out the release that signed the result', "Read the check action's pin"])
        run = '\n'.join(script(step(check, 'Check the entry')))
        self.assertIn(LS_REMOTE + ' > "$RUNNER_TEMP/releases"', run)
        self.assertIn('python3 -I recheck/scripts/queue.py entry "$RUNNER_TEMP/releases" > /dev/null', run)
        checkout = step(check, 'Check out the release that signed the result')
        self.assertEqual(value(checkout, 'repository'), 'verificationalliance/verify')
        self.assertEqual(value(checkout, 'ref'), '${{ inputs.signer-sha }}')
        # Nothing of ours stays in the workspace: vacheck hashes every file of the checkout.
        self.assertIn('rm -rf recheck signer', '\n'.join(script(step(check, "Read the check action's pin"))))

    def test_sign_takes_the_result_from_check_only(self):
        sign = self.jobs['sign']
        self.assertIn('    needs: check', sign)
        self.assertNotIn('download-artifact', self.text)
        validate = step(sign, 'Validate the result')
        self.assertEqual(value(validate, 'RESULT'), '${{ needs.check.outputs.result }}')
        self.assertEqual(re.findall(r'\$\{\{ needs\.[^}]*\}\}', self.text), ['${{ needs.check.outputs.result }}'])
        run = '\n'.join(script(validate))
        for line in ('if (( ${#RESULT} > MAX_RESULT_B64 )) || ! [[ "$RESULT" =~ ^[A-Za-z0-9+/]+=*$ ]]; then',
                     'python3 -I recheck/scripts/queue.py entry > entry.json',
                     'printf \'%s\' "$RESULT" | base64 -d > "$va/received.json"',
                     'python3 -I "$va/vacheck.pyz" validate "$va/received.json" > result.json',
                     'if ! cmp -s "$va/received.json" result.json; then',
                     'python3 -I recheck/scripts/queue.py same-entry result.json',
                     'python3 -I recheck/scripts/queue.py result result.json >> "$GITHUB_OUTPUT"'):
            self.assertIn(line, run)
        self.assertEqual(value(validate, 'id'), 'validate')
        names = [n for n, _ in steps(sign)]
        self.assertEqual(names, ['Require a standard GitHub-hosted runner', "Check out the re-check's scripts",
                                 'Get the checker', 'Validate the result', 'Count a stopped check',
                                 'Stop on a stopped check', 'Sign the result', 'Keep the bundle', 'Upload the re-check'])
        self.assertIn('echo "$VACHECK_SHA256  $va/vacheck.pyz" | sha256sum -c -', '\n'.join(script(step(sign, 'Get the checker'))))
        top = block(self.lines, self.lines.index('env:'))
        self.assertIn('  VACHECK_URL: ' + VACHECK[0], top)
        self.assertIn('  VACHECK_SHA256: ' + VACHECK[1], top)

    def test_a_stopped_check_is_counted_and_failed(self):
        """Our check stopped before every pair had a verdict: nothing to compare. sign uploads a
        marker that queue.yml counts, fails before signing, and so uploads no result."""
        sign = self.jobs['sign']
        stopped = "steps.validate.outputs.sanity == 'stopped'"
        count = step(sign, 'Count a stopped check')
        self.assertEqual(value(count, 'if'), stopped)
        self.assertEqual(value(count, 'uses'), 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2')
        self.assertEqual(value(count, 'name'), 'osva-recheck-stopped-${{ inputs.id }}')
        self.assertEqual(value(count, 'path'), 'entry.json')
        self.assertEqual(value(count, 'retention-days'), '14')
        fail = step(sign, 'Stop on a stopped check')
        self.assertEqual(value(fail, 'if'), stopped)
        self.assertIn('  exit 1', '\n'.join(script(fail)))
        # Every step after them runs only if they did not fail: none has a condition of its own.
        names = [n for n, _ in steps(sign)]
        for name in names[names.index('Stop on a stopped check') + 1:]:
            self.assertIsNone(value(step(sign, name), 'if'), name)

    def test_sign_attests_result_and_entry(self):
        attest = step(self.jobs['sign'], 'Sign the result')
        i = [k for k, line in enumerate(attest) if line.strip() == 'subject-path: |'][0]
        self.assertEqual([line.strip() for line in block(attest, i)], ['result.json', 'entry.json'])
        self.assertEqual(value(attest, 'predicate-path'), 'result.json')
        # The result's own schema, which queue.py result requires to be v2.
        self.assertEqual(value(attest, 'predicate-type'), '${{ steps.validate.outputs.predicate-type }}')
        self.assertEqual(q.SCHEMA, 'https://verificationalliance.org/attestations/proof-check/v2')
        upload = step(self.jobs['sign'], 'Upload the re-check')
        self.assertEqual(value(upload, 'name'), 'osva-recheck-${{ inputs.id }}')
        self.assertEqual(value(upload, 'retention-days'), '7')
        i = [k for k, line in enumerate(upload) if line.strip() == 'path: |'][0]
        self.assertEqual([line.strip() for line in block(upload, i)], ['result.json', 'result.sigstore.json', 'entry.json'])


class TestQueue(unittest.TestCase):
    """queue.yml's plan job."""

    def setUp(self):
        self.lines = workflows()['queue.yml']
        self.plan = jobs(self.lines)['plan']
        self.run = '\n'.join(script(step(self.plan, 'Read the queue')))

    def test_queue_url_is_strict(self):
        m = re.search(r"^ *test='(.*)'$", self.run, re.M)
        self.assertEqual(m.group(1), r'^https://raw\.githubusercontent\.com/verificationalliance/recheck/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$')
        self.assertIn('if [[ $url != "$DEFAULT_URL" ]] && ! [[ $url =~ $test && $url != *..* ]]; then', self.run)
        self.assertEqual(value(step(self.plan, 'Read the queue'), 'DEFAULT_URL'),
                         'https://verificationalliance.org/data/recheck-pending.json')
        test = re.compile(m.group(1))

        def allowed(url):
            return bool(test.search(url)) and '..' not in url
        self.assertTrue(allowed('https://raw.githubusercontent.com/verificationalliance/recheck/e2e-queue/e2e-queue.json'))
        for url in ('http://raw.githubusercontent.com/verificationalliance/recheck/main/q.json',
                    'https://raw.githubusercontent.com/verificationalliance/recheck-x/main/q.json',
                    'https://raw.githubusercontent.com/verificationalliance/other/main/q.json',
                    'https://raw.githubusercontent.com/verificationalliance/recheck/main/../../x/main/q.json',
                    'https://raw.githubusercontent.com/verificationalliance/recheck/main/q.json?x=1',
                    'https://raw.githubusercontent.com/verificationalliance/recheck/main/q.json#x',
                    'https://raw.githubusercontent.com.evil.example/verificationalliance/recheck/main/q.json',
                    'https://raw.githubusercontent.com@evil.example/verificationalliance/recheck/main/q.json',
                    'https://raw.githubusercontent.com/verificationalliance/recheck/main',
                    'https://evil.example/https://raw.githubusercontent.com/verificationalliance/recheck/main/q.json'):
            self.assertFalse(allowed(url), url)
        self.assertIn("curl -fsS --proto '=https' --tlsv1.2 --retry 3 --max-time 60 --max-filesize 1000000", self.run)

    def test_done_is_queue_yml_on_main(self):
        for line in ('python3 -I scripts/queue.py entries "$dir/queue.json" "$dir/releases" > "$dir/entries.json"',
                     'for kind in artifacts stops; do',
                     'if [[ $kind == stops ]]; then name=osva-recheck-stopped-$id; else name=osva-recheck-$id; fi',
                     'gh api "repos/verificationalliance/recheck/actions/artifacts?name=$name&per_page=100&page=$page" \\',
                     '> "$dir/$kind-$id-$page.json"',
                     'python3 -I scripts/queue.py more "$dir" "$id" "$page" "$kind" || break',
                     'done < <(python3 -I scripts/queue.py ids "$dir/entries.json")',
                     'gh api "repos/verificationalliance/recheck/actions/runs/$run" > "$dir/run-$run.json"',
                     'done < <(python3 -I scripts/queue.py runs "$dir")',
                     'python3 -I scripts/queue.py plan "$dir" >> "$GITHUB_OUTPUT"'):
            self.assertIn(line, self.run)
        self.assertEqual(q.REPO_ID, 1471096694)
        self.assertEqual(q.QUEUE_WORKFLOW, '.github/workflows/queue.yml')

    def test_schedule(self):
        """Every 5 minutes, off the hour: GitHub delays and may drop scheduled runs at the start of
        every hour."""
        text = '\n'.join(self.lines)
        self.assertIn('on:\n', text)
        self.assertEqual(re.findall(r'^ *- cron: (.*)$', text, re.M), ['"2-59/5 * * * *"'])

    def test_chain(self):
        """Each run dispatches the next, 5 minutes after its work, whatever became of that work, but
        not after a cancel; only from main and this repository; with no inputs, so a test queue is
        never carried on; and only when no other run of queue.yml waits or runs: the concurrency
        group keeps one run going and one waiting, and a new waiting run replaces the old."""
        text = '\n'.join(self.lines)
        self.assertIn('concurrency:\n  group: recheck\n  cancel-in-progress: false\n', text)
        self.assertEqual(re.findall(r'^ *- cron: (.*)$', text, re.M), ['"2-59/5 * * * *"'], 'the schedule stays')
        nxt = jobs(self.lines)['next']
        self.assertIn('    needs: [plan, recheck]', nxt)
        self.assertIn("    if: github.repository == 'verificationalliance/recheck' && github.ref == 'refs/heads/main'"
                      " && !cancelled()", nxt)
        self.assertIn('    runs-on: ubuntu-24.04', nxt)
        self.assertIn('    timeout-minutes: 10', nxt)
        self.assertEqual([n for n, _ in steps(nxt)], ['Dispatch the next run'])
        dispatch = step(nxt, 'Dispatch the next run')
        self.assertEqual(value(dispatch, 'GH_TOKEN'), '${{ github.token }}')
        self.assertNotIn('uses:', '\n'.join(dispatch))
        run = '\n'.join(script(dispatch))
        lines = [line.strip() for line in script(dispatch)]
        self.assertEqual(lines[1], 'sleep 300')
        self.assertIn("others=$(gh api 'repos/verificationalliance/recheck/actions/workflows/queue.yml/runs?per_page=30' \\", run)
        self.assertIn('--jq \'%s\') || others=unknown' % OTHERS, run)
        self.assertIn('if [[ $others =~ ^[1-9][0-9]*$ ]]; then', run)
        self.assertEqual(re.findall(r'gh api -X POST (.*)', run),
                         ['repos/verificationalliance/recheck/actions/workflows/queue.yml/dispatches -f ref=main; then'])
        self.assertNotIn('inputs', run)
        self.assertLess(run.index('if [[ $others =~'), run.index('gh api -X POST'))

    @unittest.skipUnless(shutil.which('jq'), 'needs jq')
    def test_others(self):
        """OTHERS, as jq runs it on GitHub's list of queue.yml's runs: the runs besides this one that
        are not completed."""
        def others(statuses, me=7):
            runs = {'total_count': len(statuses),
                    'workflow_runs': [{'id': i, 'status': st} for i, st in enumerate(statuses, 7)]}
            out = subprocess.run(['jq', OTHERS], input=json.dumps(runs), capture_output=True, text=True,
                                 env={'GITHUB_RUN_ID': str(me), 'PATH': os.environ.get('PATH', '')}, check=True)
            return int(out.stdout)
        self.assertEqual(others(['in_progress']), 0, 'only this run')
        self.assertEqual(others(['in_progress', 'completed', 'completed']), 0)
        for status in ('queued', 'pending', 'waiting', 'requested', 'in_progress'):
            self.assertEqual(others(['in_progress', status]), 1, status)
        self.assertEqual(others(['completed', 'queued'], me=8), 0, 'the waiting one is this run')
        self.assertEqual(others([]), 0)

    def test_recheck_job(self):
        recheck = jobs(self.lines)['recheck']
        self.assertIn("    if: github.repository == 'verificationalliance/recheck' && needs.plan.outputs.matrix != '[]'", recheck)
        self.assertIn('    uses: ./.github/workflows/recheck.yml', recheck)


class TestReadme(unittest.TestCase):

    def test_verify_command(self):
        """The README's command checks what our server checks: without --predicate-type,
        gh looks for SLSA provenance and finds none."""
        with open(os.path.join(ROOT, 'README.md'), encoding='utf-8') as f:
            text = f.read()
        command = text[text.index('gh attestation verify'):]
        command = command[:command.index('```')].replace('\\\n', ' ').split()
        self.assertEqual(command, [
            'gh', 'attestation', 'verify', 'result.json', '--bundle', 'result.sigstore.json',
            '--repo', 'verificationalliance/recheck',
            '--signer-workflow', 'verificationalliance/recheck/.github/workflows/recheck.yml',
            '--signer-digest', '<commit>', '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners',
            '--predicate-type', 'https://verificationalliance.org/attestations/proof-check/v2'])


class TestTests(unittest.TestCase):

    def test_tests_workflow(self):
        lines = workflows()['tests.yml']
        text = '\n'.join(lines)
        self.assertIn('on:\n  push:\n  pull_request:\n', text)
        unit = jobs(lines)['unit']
        run = '\n'.join(script(step(unit, 'Run the tests')))
        self.assertIn('python3 -I -m unittest discover -s tests -v', run)
        self.assertEqual(value(step(unit, 'Run the tests'), 'RECHECK_ONLINE'), '"1"')


@unittest.skipUnless(os.environ.get('RECHECK_ONLINE') == '1', 'reads verificationalliance/verify; set RECHECK_ONLINE=1')
class TestReleasesOnline(unittest.TestCase):

    def test_releases_are_verifys(self):
        tags = subprocess.run(['git', 'ls-remote', '--tags', 'https://github.com/verificationalliance/verify',
                               'refs/tags/workflow-*'], capture_output=True, text=True, check=True).stdout
        for n, (release, pin) in RELEASES.items():
            self.assertIn('%s\trefs/tags/workflow-%d^{}' % (release, n), tags.split('\n'))
            url = 'https://raw.githubusercontent.com/verificationalliance/verify/%s/.github/workflows/lean.yml' % release
            with urllib.request.urlopen(url, timeout=30) as r:
                lean = r.read().decode('utf-8')
            self.assertEqual(q.action_pin(lean), pin, n)
            # sign validates with the release's own checker.
            self.assertIn('  VACHECK_URL: %s\n' % VACHECK[0], lean)
            self.assertIn('  VACHECK_SHA256: %s\n' % VACHECK[1], lean)

    def test_checker_is_the_release_asset(self):
        import hashlib
        with urllib.request.urlopen(VACHECK[0], timeout=60) as r:
            self.assertEqual(hashlib.sha256(r.read()).hexdigest(), VACHECK[1])


if __name__ == '__main__':
    unittest.main()
