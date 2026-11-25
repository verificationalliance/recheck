"""The queue of results waiting for our re-check: reads it, checks every field, and says what to do.

Our server lists each signed result it holds pending in
https://verificationalliance.org/data/recheck-pending.json:

  {"generated_at": "<UTC time>Z",
   "entries": [{"id": "<32 hex>", "repo": "github.com/<owner>/<name>", "commit": "<40 hex>",
                "run_id": <int>, "artifact_id": <int>, "signer_sha": "<40 hex>", "manifest": "<path>"}]}

`run_id` is the developer's run, whose build job made the export, `artifact_id` that run's signed
result (an attempt of the run again uploads another), and `id` is
sha256("<repo>@<run_id>@<artifact_id>")[:32]; `signer_sha` is the commit of
verificationalliance/verify whose lean.yml signed the result; `manifest` is the path lean.yml's
`manifest` input had in that run.
Every field reaches a checkout, an artifact name or a step's environment, so each must match its
pattern exactly, or the entry is dropped. Only the first 50 entries are read, oldest first. A reason
for a drop is a fixed text with the entry's number: nothing of an entry is ever printed, since the
runner reads workflow commands in the log.

queue.yml's plan job runs, in turn:
  queue.py entries QUEUE RELEASES > DIR/entries.json
      the entries of QUEUE, the queue file, signed by a release this repository re-checks (RELEASES
      below) that is still the commit of its workflow-<n> tag in RELEASES, `git ls-remote --tags` of
      verificationalliance/verify (a commit of a fork can be fetched through the repository too).
      The reasons go to stderr; a file that is not the queue fails.
  queue.py ids DIR/entries.json
      their ids, one per line. For each, the job saves GitHub's lists of two kinds of artifact, a
      page of 100 at a time, as DIR/<kind>-<id>-<page>.json: `artifacts`, named osva-recheck-<id>,
      our re-checks; and `stops`, named osva-recheck-stopped-<id>, which recheck.yml uploads when
      our check stopped before every pair had a verdict. It asks for the next page while
  queue.py more DIR ID PAGE [KIND]
      says (exit 0) that the list holds more than its pages so far: it counts more, and PAGE is
      below MAX_PAGES. Artifacts of others' runs (a fork's pull request) can come before ours.
  queue.py runs DIR
      the runs that uploaded them, one per line, of those that could be ours. The job saves each
      as DIR/run-<run id>.json.
  queue.py plan DIR
      prints `matrix=<JSON>` for $GITHUB_OUTPUT: the entries not re-checked yet and not given up,
      every value a string. An artifact counts only when a run of queue.yml on this repository's
      main uploaded it: any workflow of a branch, a pull request from a fork, and the other
      workflows here can upload an artifact of that name too. An entry is given up once MAX_STOPS
      such runs stopped its check; our server's own time limit then ends it.
recheck.yml runs:
  queue.py entry [RELEASES]
      checks the one entry given by the variables ID, REPO, COMMIT, RUN_ID, ARTIFACT_ID, SIGNER_SHA
      and MANIFEST, and with RELEASES that its signer_sha is a release this repository re-checks,
      and prints it as entry.json.
  queue.py pin LEAN_YML
      prints the commit at which lean.yml pins the check action.
  queue.py same-entry RESULT
      checks that a validated result.json is for that entry's repository and commit.
  queue.py result RESULT
      prints `predicate-type=<its schema>` and `sanity=<its sanity>` for $GITHUB_OUTPUT, if its
      schema is SCHEMA and its sanity one of SANITY; fails otherwise.
"""
import hashlib
import json
import os
import re
import sys

MAX_BYTES = 1_000_000
MAX_ENTRIES = 50
# The check action takes a run id of at most 15 digits: download-artifact reads it as a JavaScript
# number, which is exact only up to 2**53. An artifact id is held to the same.
MAX_RUN_ID = 10 ** 15 - 1
# Pages of 100 of GitHub's list of an entry's artifacts, at most.
MAX_PAGES = 10
KEYS = frozenset({'id', 'repo', 'commit', 'run_id', 'artifact_id', 'signer_sha', 'manifest'})
# verificationalliance/recheck, and the workflow whose runs upload our re-checks.
REPO_ID = 1471096694
QUEUE_WORKFLOW = '.github/workflows/queue.yml'
# The workflow releases this repository re-checks: each one's commit, and the commit of the check
# action its lean.yml pins. recheck.yml runs that action by a step for each; tests/test_workflows.py
# checks both against verificationalliance/verify.
RELEASES = {
    10: ('6fdf9a0870d09204e776d2fc357d96acb3258eb8', 'e857d7a7e58ca573a3d233f8547c5c62b5fd82f1'),
}
# The result's schema, which names the predicate type it is signed under, and how far its sanity
# step got (vacheck 2.0.2's result.py).
SCHEMA = 'https://verificationalliance.org/attestations/proof-check/v2'
SANITY = ('complete', 'partial', 'stopped')
# Runs of queue.yml whose check of an entry stopped, at most: a stop that happens every time would
# otherwise be tried every 5 minutes until our server's limit.
MAX_STOPS = 3
KINDS = {'artifacts': 'osva-recheck-', 'stops': 'osva-recheck-stopped-'}

GENERATED = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z')
ID = re.compile(r'[0-9a-f]{32}')
SHA = re.compile(r'[0-9a-f]{40}')
# GitHub's names: an owner of 1 to 39 letters, digits and hyphens, not starting with a hyphen; a
# repository of 1 to 100 letters, digits, '.', '_' and '-', which may not be '.' or hold '..' here.
REPO = re.compile(r'github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}')
# lean.yml's manifest_path.py: a relative path, and no part of it '..'.
MANIFEST = re.compile(r'[A-Za-z0-9_.][A-Za-z0-9_./-]{0,254}')
RUN_ID = re.compile(r'[1-9][0-9]{0,14}')
TAG = re.compile(r'([0-9a-f]{40})\trefs/tags/(workflow-[1-9][0-9]*)(\^\{\})?')
PIN_MENTION = 'verificationalliance/verify/.github/actions/check@'
PIN = re.compile(r' *(?:- )?uses: verificationalliance/verify/\.github/actions/check@([0-9a-f]{40})(?: +#.*)?')

R_NOT_QUEUE = 'The queue is not a JSON object of at most 1,000,000 bytes with generated_at and entries only.'
R_NOT_OBJECT = 'not a JSON object'
R_KEYS = 'keys other than id, repo, commit, run_id, artifact_id, signer_sha and manifest'
R_ID = 'id is not 32 lowercase hex digits'
R_REPO = 'repo is not github.com/<owner>/<name>'
R_COMMIT = 'commit is not 40 lowercase hex digits'
R_RUN_ID = 'run_id is not a whole number from 1 to 999,999,999,999,999'
R_ARTIFACT_ID = 'artifact_id is not a whole number from 1 to 999,999,999,999,999'
R_SIGNER = 'signer_sha is not 40 lowercase hex digits'
R_MANIFEST = 'manifest is not a relative path without ..'
R_BINDING = 'id is not sha256("<repo>@<run_id>@<artifact_id>")[:32]'
R_DUPLICATE = 'its id is listed before'
R_OVER = 'Entries after the 50th dropped.'
R_RELEASE = 'signer_sha is not the commit of a workflow release this repository re-checks'


def _is(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _plural(n, one, many):
    return '%d %s' % (n, one if n == 1 else many)


def entry_id(repo, run_id, artifact_id):
    return hashlib.sha256(('%s@%d@%d' % (repo, run_id, artifact_id)).encode('utf-8')).hexdigest()[:32]


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
    artifact_id = entry['artifact_id']
    if type(artifact_id) is not int or not 1 <= artifact_id <= MAX_RUN_ID:
        return R_ARTIFACT_ID
    if not _is(SHA, entry['signer_sha']):
        return R_SIGNER
    manifest = entry['manifest']
    if not _is(MANIFEST, manifest) or '..' in manifest.split('/'):
        return R_MANIFEST
    if entry['id'] != entry_id(repo, run_id, artifact_id):
        return R_BINDING
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


def load_json(path, max_bytes=MAX_BYTES):
    """A file as JSON, or None: more than max_bytes, not UTF-8, not strict JSON, nested deeper than
    the parser goes, or with a key repeated in an object (which value counts would be the parser's
    choice)."""
    try:
        with open(path, 'rb') as f:
            data = f.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes:
        return None
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        return None


def load_queue(path):
    return load_json(path, MAX_BYTES)


def _int(value):
    return type(value) is int and value > 0


def _page(folder, entry_id, page, kind):
    """(artifacts, total_count) of a saved page of an entry's artifacts, or None for one that is not."""
    doc = load_json(os.path.join(folder, '%s-%s-%d.json' % (kind, entry_id, page)), 10 * MAX_BYTES)
    if not (isinstance(doc, dict) and isinstance(doc.get('artifacts'), list) and type(doc.get('total_count')) is int):
        return None
    return doc['artifacts'], doc['total_count']


def artifacts_of(folder, entry_id, kind='artifacts'):
    """An entry's artifacts of a kind as its saved pages list them, in order, up to the first that is
    not a page, as one list in the form recheck_runs and stopped_runs read."""
    found = []
    for page in range(1, MAX_PAGES + 1):
        read = _page(folder, entry_id, page, kind)
        if read is None:
            break
        found += read[0]
    return {'artifacts': found}


def more_pages(folder, entry_id, page, kind='artifacts'):
    """Whether to ask GitHub for page + 1 of an entry's artifacts of a kind: pages 1 to `page` are
    saved, the last of them lists some, all of them fewer than its total_count, and `page` is below
    MAX_PAGES."""
    if not 1 <= page < MAX_PAGES:
        return False
    read = [_page(folder, entry_id, p, kind) for p in range(1, page + 1)]
    if any(r is None for r in read):
        return False
    return bool(read[-1][0]) and sum(len(r[0]) for r in read) < read[-1][1]


def _uploads(name, doc):
    """The runs that uploaded an unexpired artifact `name` in this repository, from its main and not
    from a fork's, as GitHub's list of artifacts by that name gives them."""
    found = []
    artifacts = doc.get('artifacts') if isinstance(doc, dict) else None
    for a in artifacts if isinstance(artifacts, list) else []:
        run = a.get('workflow_run') if isinstance(a, dict) else None
        if (isinstance(run, dict) and a.get('name') == name and a.get('expired') is False
                and _int(run.get('id')) and run.get('repository_id') == REPO_ID
                and run.get('head_repository_id') == REPO_ID and run.get('head_branch') == 'main'
                and run['id'] not in found):
            found.append(run['id'])
    return found


def recheck_runs(entry_id, doc):
    """The runs that could have uploaded our re-check of an entry, osva-recheck-<entry_id>."""
    return _uploads(KINDS['artifacts'] + entry_id, doc)


def stopped_runs(entry_id, doc):
    """The runs that could have stopped checking an entry, by their osva-recheck-stopped-<entry_id>."""
    return _uploads(KINDS['stops'] + entry_id, doc)


def queue_run(doc):
    """Whether GitHub's record of a run is one of queue.yml's, on this repository's main."""
    return (isinstance(doc, dict) and doc.get('path') == QUEUE_WORKFLOW
            and doc.get('event') in ('schedule', 'workflow_dispatch') and doc.get('head_branch') == 'main'
            and isinstance(doc.get('repository'), dict) and doc['repository'].get('id') == REPO_ID
            and isinstance(doc.get('head_repository'), dict) and doc['head_repository'].get('id') == REPO_ID)


def done_ids(entries, artifacts, runs):
    """The ids of the entries re-checked already: artifacts maps an id to its list of artifacts,
    runs a run id to its record, each as GitHub gave it."""
    return {e['id'] for e in entries
            if any(queue_run(runs.get(r)) for r in recheck_runs(e['id'], artifacts.get(e['id'])))}


def given_up_ids(entries, stops, runs):
    """The ids of the entries whose check MAX_STOPS runs of queue.yml stopped: stops maps an id to
    its list of osva-recheck-stopped-<id> artifacts, runs a run id to its record."""
    return {e['id'] for e in entries
            if sum(queue_run(runs.get(r)) for r in stopped_runs(e['id'], stops.get(e['id']))) >= MAX_STOPS}


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


def rechecked(ls_remote):
    """The releases this repository re-checks that are still the commits of their tags."""
    return releases(ls_remote) & {signer for signer, _ in RELEASES.values()}


def released(entries, shas):
    """The entries whose signer_sha is a release, and the reasons for the others."""
    kept = [e for e in entries if e['signer_sha'] in shas]
    dropped = len(entries) - len(kept)
    return kept, ['%s: %s' % (_plural(dropped, 'entry', 'entries'), R_RELEASE)] if dropped else []


def action_pin(lean_yml):
    """The commit at which lean.yml pins the check action, or None unless lean.yml names that action
    exactly once (in any case, comments included), on a line of its own."""
    if lean_yml.lower().count(PIN_MENTION) != 1:
        return None
    found = [m.group(1) for m in map(PIN.fullmatch, lean_yml.split('\n')) if m]
    return found[0] if found else None


def entry_from_env(env, release_shas=None):
    """The entry the variables ID, REPO, COMMIT, RUN_ID, ARTIFACT_ID, SIGNER_SHA and MANIFEST give, or None; with
    release_shas, also None unless its signer_sha is one of them."""
    run_id, artifact_id = env.get('RUN_ID'), env.get('ARTIFACT_ID')
    entry = {'id': env.get('ID'), 'repo': env.get('REPO'), 'commit': env.get('COMMIT'),
             'run_id': int(run_id) if _is(RUN_ID, run_id) else None,
             'artifact_id': int(artifact_id) if _is(RUN_ID, artifact_id) else None,
             'signer_sha': env.get('SIGNER_SHA'), 'manifest': env.get('MANIFEST')}
    if problem(entry) is not None or (release_shas is not None and entry['signer_sha'] not in release_shas):
        return None
    return entry


def canonical(entry):
    return json.dumps(entry, sort_keys=True, separators=(',', ':')) + '\n'


def same_entry(result, entry):
    return isinstance(result, dict) and result.get('repo') == entry['repo'] and result.get('commit') == entry['commit']


def result_facts(result):
    """(schema, sanity) of a result whose schema is SCHEMA and whose sanity is one of SANITY, or None."""
    if not isinstance(result, dict) or result.get('schema') != SCHEMA:
        return None
    sanity = result.get('sanity')
    return (SCHEMA, sanity) if isinstance(sanity, str) and sanity in SANITY else None


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read(MAX_BYTES + 1)


def _fail(message):
    # To stderr: stdout is $GITHUB_OUTPUT, a file the job keeps, or the pin.
    print('::error::' + message, file=sys.stderr)
    return 1


def _our_entries(path):
    """entries.json, as `entries` wrote it, or None."""
    entries = load_json(path)
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES or any(problem(e) for e in entries):
        return None
    return entries


def _entries(queue_path, releases_path):
    doc = load_queue(queue_path)
    kept, reasons = validate(doc) if doc is not None else ([], [R_NOT_QUEUE])
    if reasons == [R_NOT_QUEUE]:
        return _fail(R_NOT_QUEUE)
    kept, more = released(kept, rechecked(_read(releases_path)))
    for reason in reasons + more:
        print('::warning::' + (reason if reason == R_OVER else 'Dropped: ' + reason), file=sys.stderr)
    listed = len(doc['entries'])
    print('The queue lists %s: %d kept, %d dropped.' % (_plural(listed, 'entry', 'entries'), len(kept), listed - len(kept)),
          file=sys.stderr)
    print(json.dumps(kept, separators=(',', ':')))
    return 0


def _evidence(folder, entries):
    artifacts = {e['id']: artifacts_of(folder, e['id']) for e in entries}
    stops = {e['id']: artifacts_of(folder, e['id'], 'stops') for e in entries}
    run_ids = {r for e in entries for r in recheck_runs(e['id'], artifacts[e['id']]) + stopped_runs(e['id'], stops[e['id']])}
    return artifacts, stops, sorted(run_ids)


def _plan(folder):
    entries = _our_entries(os.path.join(folder, 'entries.json'))
    if entries is None:
        return _fail('entries.json is not the entries queue.py wrote.')
    artifacts, stops, run_ids = _evidence(folder, entries)
    runs = {r: load_json(os.path.join(folder, 'run-%d.json' % r), 10 * MAX_BYTES) for r in run_ids}
    done = done_ids(entries, artifacts, runs)
    given_up = given_up_ids(entries, stops, runs) - done
    todo = matrix(entries, done | given_up)
    print('Of %s, %d %s re-checked already and %d stopped %d times; %d to re-check.'
          % (_plural(len(entries), 'entry', 'entries'), len(done), 'is' if len(done) == 1 else 'are',
             len(given_up), MAX_STOPS, len(todo)),
          file=sys.stderr)
    print('matrix=' + json.dumps(todo, separators=(',', ':')))
    return 0


def main(argv, env):
    args = argv[1:]
    if args[:1] == ['entries'] and len(args) == 3:
        return _entries(args[1], args[2])
    if args[:1] == ['ids'] and len(args) == 2:
        entries = _our_entries(args[1])
        if entries is None:
            return _fail('entries.json is not the entries queue.py wrote.')
        sys.stdout.write(''.join(e['id'] + '\n' for e in entries))
        return 0
    if args[:1] == ['more'] and len(args) in (4, 5):
        kind = args[4] if len(args) == 5 else 'artifacts'
        if not (_is(ID, args[2]) and _is(RUN_ID, args[3]) and kind in KINDS):
            return _fail('more takes a folder, an id, a page number and artifacts or stops.')
        return 0 if more_pages(args[1], args[2], int(args[3]), kind) else 1
    if args[:1] == ['runs'] and len(args) == 2:
        entries = _our_entries(os.path.join(args[1], 'entries.json'))
        if entries is None:
            return _fail('entries.json is not the entries queue.py wrote.')
        sys.stdout.write(''.join('%d\n' % r for r in _evidence(args[1], entries)[2]))
        return 0
    if args[:1] == ['plan'] and len(args) == 2:
        return _plan(args[1])
    if args[:1] == ['entry'] and len(args) <= 2:
        shas = rechecked(_read(args[1])) if len(args) == 2 else None
        entry = entry_from_env(env, shas)
        if entry is None:
            return _fail('The entry is not one: each field must match its pattern, and the signer must be a release re-checked here.')
        sys.stdout.write(canonical(entry))
        return 0
    if args[:1] == ['pin'] and len(args) == 2:
        pin = action_pin(_read(args[1]))
        if pin is None:
            return _fail('lean.yml does not pin the check action by a full commit exactly once.')
        print(pin)
        return 0
    if args[:1] == ['same-entry'] and len(args) == 2:
        entry = entry_from_env(env)
        if entry is None or not same_entry(load_json(args[1], 10 * MAX_BYTES), entry):
            return _fail("The result is not for the entry's repository and commit.")
        return 0
    if args[:1] == ['result'] and len(args) == 2:
        facts = result_facts(load_json(args[1], 10 * MAX_BYTES))
        if facts is None:
            return _fail('The result is not of schema %s with a sanity of complete, partial or stopped.' % SCHEMA)
        print('predicate-type=%s\nsanity=%s' % facts)
        return 0
    print('usage: queue.py entries QUEUE RELEASES | ids ENTRIES | more DIR ID PAGE [KIND] | runs DIR | plan DIR'
          ' | entry [RELEASES] | pin LEAN_YML | same-entry RESULT | result RESULT', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv, os.environ))
