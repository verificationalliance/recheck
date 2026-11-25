"""The queue of results waiting for our re-check: reads it, checks every field, and says what to do.

Our server lists each signed result it holds pending in
https://verificationalliance.org/data/recheck-pending.json:

  {"generated_at": "<UTC time>Z",
   "entries": [{"id": "<32 hex>", "repo": "github.com/<owner>/<name>", "commit": "<40 hex>",
                "run_id": <int>, "signer_sha": "<40 hex>", "manifest": "<path>"}]}

`run_id` is the developer's run, whose build job made the export; `signer_sha` is the commit of
verificationalliance/verify whose lean.yml signed the result; `manifest` is the path lean.yml's
`manifest` input had in that run. Every field reaches a checkout, an artifact name or a step's
environment, so each must match its pattern exactly, or the entry is dropped. Only the first 50
entries are read, oldest first. A reason for a drop is a fixed text with the entry's number: nothing
of an entry is ever printed, since the runner reads workflow commands in the log.

  queue.py plan QUEUE ARTIFACTS RELEASES
      prints `matrix=<JSON>` for $GITHUB_OUTPUT: the entries to re-check, every value a string.
      QUEUE is the queue file. ARTIFACTS lists this repository's artifacts, a name per line: an
      entry whose osva-recheck-<id> is there is done. RELEASES is `git ls-remote --tags` of
      verificationalliance/verify: an entry whose signer_sha is no workflow-<n> tag's commit is
      dropped, since a commit of a fork can be fetched through the repository too. The reasons go to
      stderr; a file that is not the queue fails.
  queue.py entry
      checks the one entry given by the variables ID, REPO, COMMIT, RUN_ID, SIGNER_SHA and MANIFEST,
      and prints it as entry.json.
  queue.py pin LEAN_YML
      prints the commit at which lean.yml pins the check action.
  queue.py same-entry RESULT
      checks that a validated result.json is for that entry's repository and commit.
"""
import json
import os
import re
import sys

MAX_BYTES = 1_000_000
MAX_ENTRIES = 50
# The check action takes a run id of at most 15 digits: download-artifact reads it as a JavaScript
# number, which is exact only up to 2**53.
MAX_RUN_ID = 10 ** 15 - 1
KEYS = frozenset({'id', 'repo', 'commit', 'run_id', 'signer_sha', 'manifest'})

GENERATED = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z')
ID = re.compile(r'[0-9a-f]{32}')
SHA = re.compile(r'[0-9a-f]{40}')
# GitHub's names: an owner of 1 to 39 letters, digits and hyphens, not starting with a hyphen; a
# repository of 1 to 100 letters, digits, '.', '_' and '-', which may not be '.' or hold '..' here.
REPO = re.compile(r'github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}')
# lean.yml's manifest_path.py: a relative path, and no part of it '..'.
MANIFEST = re.compile(r'[A-Za-z0-9_.][A-Za-z0-9_./-]{0,254}')
RUN_ID = re.compile(r'[1-9][0-9]{0,14}')
DONE = re.compile(r'osva-recheck-([0-9a-f]{32})')
TAG = re.compile(r'([0-9a-f]{40})\trefs/tags/(workflow-[1-9][0-9]*)(\^\{\})?')
PIN_MENTION = 'verificationalliance/verify/.github/actions/check@'
PIN = re.compile(r' *(?:- )?uses: verificationalliance/verify/\.github/actions/check@([0-9a-f]{40})(?: +#.*)?')

R_NOT_QUEUE = 'The queue is not a JSON object of at most 1,000,000 bytes with generated_at and entries only.'
R_NOT_OBJECT = 'not a JSON object'
R_KEYS = 'keys other than id, repo, commit, run_id, signer_sha and manifest'
R_ID = 'id is not 32 lowercase hex digits'
R_REPO = 'repo is not github.com/<owner>/<name>'
R_COMMIT = 'commit is not 40 lowercase hex digits'
R_RUN_ID = 'run_id is not a whole number from 1 to 999,999,999,999,999'
R_SIGNER = 'signer_sha is not 40 lowercase hex digits'
R_MANIFEST = 'manifest is not a relative path without ..'
R_DUPLICATE = 'its id is listed before'
R_OVER = 'Entries after the 50th dropped.'
R_RELEASE = 'signer_sha is not the commit of a workflow release of verificationalliance/verify'


def _is(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def problem(entry):
    """Why an entry is not one, as a fixed text; None if it is."""
    if not isinstance(entry, dict):
        return R_NOT_OBJECT
    if set(entry) != KEYS:
        return R_KEYS
    if not _is(ID, entry['id']):
        return R_ID
    repo = entry['repo']
    if not _is(REPO, repo) or '..' in repo or repo.endswith('/.'):
        return R_REPO
    if not _is(SHA, entry['commit']):
        return R_COMMIT
    run_id = entry['run_id']
    if type(run_id) is not int or not 1 <= run_id <= MAX_RUN_ID:
        return R_RUN_ID
    if not _is(SHA, entry['signer_sha']):
        return R_SIGNER
    manifest = entry['manifest']
    if not _is(MANIFEST, manifest) or '..' in manifest.split('/'):
        return R_MANIFEST
    return None


def validate(doc):
    """The queue's entries that are entries, and the reasons for the others. A document that is
    not the queue has no entries."""
    if (not isinstance(doc, dict) or set(doc) != {'generated_at', 'entries'}
            or not _is(GENERATED, doc['generated_at']) or not isinstance(doc['entries'], list)):
        return [], [R_NOT_QUEUE]
    kept, reasons, seen = [], [], set()
    for n, entry in enumerate(doc['entries'][:MAX_ENTRIES], 1):
        why = problem(entry)
        if why is None and entry['id'] in seen:
            why = R_DUPLICATE
        if why is None:
            seen.add(entry['id'])
            kept.append(entry)
        else:
            reasons.append('entry %d: %s' % (n, why))
    if len(doc['entries']) > MAX_ENTRIES:
        reasons.append(R_OVER)
    return kept, reasons


def _unique(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError('a repeated key')
    return dict(pairs)


def _no_constant(name):
    raise ValueError('not JSON')


def load_queue(path):
    """The queue file as JSON, or None: more than MAX_BYTES, not UTF-8, not strict JSON, or with a
    key repeated in an object (which value counts would be the parser's choice)."""
    with open(path, 'rb') as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        return None
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_no_constant)
    except ValueError:
        return None


def done_ids(names):
    """The ids that have an osva-recheck-<id> among artifact names, one per line."""
    return {m.group(1) for m in map(DONE.fullmatch, names.split('\n')) if m}


def matrix(entries, done_ids):
    """The entries not done yet, in order, with every value a string: the workflow hands each to a
    string input."""
    return [{k: str(e[k]) for k in sorted(KEYS)} for e in entries if e['id'] not in done_ids]


def releases(ls_remote):
    """The commits of verificationalliance/verify's workflow-<n> tags, from `git ls-remote --tags`:
    an annotated tag's line `^{}` names its commit, a lightweight tag's own line does."""
    own, peeled = {}, {}
    for m in map(TAG.fullmatch, ls_remote.split('\n')):
        if m:
            (peeled if m.group(3) else own)[m.group(2)] = m.group(1)
    return {peeled.get(tag, sha) for tag, sha in own.items()}


def released(entries, shas):
    """The entries whose signer_sha is a release, and the reasons for the others."""
    kept = [e for e in entries if e['signer_sha'] in shas]
    dropped = len(entries) - len(kept)
    return kept, ['%d %s: %s' % (dropped, 'entry' if dropped == 1 else 'entries', R_RELEASE)] if dropped else []


def action_pin(lean_yml):
    """The commit at which lean.yml pins the check action, or None unless lean.yml names that action
    exactly once (in any case, comments included), on a line of its own."""
    if lean_yml.lower().count(PIN_MENTION) != 1:
        return None
    found = [m.group(1) for m in map(PIN.fullmatch, lean_yml.split('\n')) if m]
    return found[0] if found else None


def entry_from_env(env):
    """The entry the variables ID, REPO, COMMIT, RUN_ID, SIGNER_SHA and MANIFEST give, or None."""
    run_id = env.get('RUN_ID')
    entry = {'id': env.get('ID'), 'repo': env.get('REPO'), 'commit': env.get('COMMIT'),
             'run_id': int(run_id) if _is(RUN_ID, run_id) else None,
             'signer_sha': env.get('SIGNER_SHA'), 'manifest': env.get('MANIFEST')}
    return entry if problem(entry) is None else None


def canonical(entry):
    return json.dumps(entry, sort_keys=True, separators=(',', ':')) + '\n'


def same_entry(result, entry):
    return isinstance(result, dict) and result.get('repo') == entry['repo'] and result.get('commit') == entry['commit']


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read(MAX_BYTES + 1)


def _fail(message):
    # To stderr: stdout is $GITHUB_OUTPUT, entry.json or the pin.
    print('::error::' + message, file=sys.stderr)
    return 1


def _plan(queue_path, artifacts_path, releases_path):
    doc = load_queue(queue_path)
    if doc is None:
        return _fail(R_NOT_QUEUE)
    kept, reasons = validate(doc)
    if reasons == [R_NOT_QUEUE]:
        return _fail(R_NOT_QUEUE)
    kept, more = released(kept, releases(_read(releases_path)))
    reasons += more
    for reason in reasons:
        print('::warning::Dropped: ' + reason if reason != R_OVER else '::warning::' + reason, file=sys.stderr)
    done = done_ids(_read(artifacts_path))
    todo = matrix(kept, done)
    print('The queue lists %d entries: %d to re-check, %d of them done; %d dropped.'
          % (len(doc['entries']), len(kept), len(kept) - len(todo), len(doc['entries']) - len(kept)),
          file=sys.stderr)
    print('matrix=' + json.dumps(todo, separators=(',', ':')))
    return 0


def main(argv, env):
    if argv[1:2] == ['plan'] and len(argv) == 5:
        return _plan(*argv[2:])
    if argv[1:] == ['entry']:
        entry = entry_from_env(env)
        if entry is None:
            return _fail('The entry is not one: each field must match its pattern.')
        sys.stdout.write(canonical(entry))
        return 0
    if argv[1:2] == ['pin'] and len(argv) == 3:
        pin = action_pin(_read(argv[2]))
        if pin is None:
            return _fail('lean.yml does not pin the check action by a full commit exactly once.')
        print(pin)
        return 0
    if argv[1:2] == ['same-entry'] and len(argv) == 3:
        entry = entry_from_env(env)
        with open(argv[2], encoding='utf-8') as f:
            result = json.load(f)
        if entry is None or not same_entry(result, entry):
            return _fail("The result is not for the entry's repository and commit.")
        return 0
    print('usage: queue.py plan QUEUE ARTIFACTS RELEASES | entry | pin LEAN_YML | same-entry RESULT',
          file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv, os.environ))
