# recheck

Re-checks proof results for the [Verification Alliance](https://verificationalliance.org)
checkmark. When a developer's workflow signs a result, a workflow here runs the same check
again, on a GitHub-hosted runner in our own organisation. The result is published only if
both checks give exactly the same answer.

- `queue.yml` runs every 5 minutes. It reads the results waiting for a re-check from
  https://verificationalliance.org/data/recheck-pending.json, and calls `recheck.yml` for each
  one not re-checked yet.
- `recheck.yml` runs the check action of [verificationalliance/verify](https://github.com/verificationalliance/verify),
  at the commit the developer's workflow release pins, on the developer's commit and the export
  their run made. It signs our result and uploads the artifact `osva-recheck-<id>`, kept 7 days:
  `result.json`, its attestation `result.sigstore.json`, and the queue entry `entry.json`.

To check one of our results yourself:

```
gh attestation verify result.json --bundle result.sigstore.json \
  --repo verificationalliance/recheck \
  --signer-workflow verificationalliance/recheck/.github/workflows/recheck.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners
```

The tests use Python's standard library only: `python3 -I -m unittest discover -s tests`.
