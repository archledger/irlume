# Minihost LiteRT unsigned trial

This manual workflow runs one read-only job on minihost from protected
`main`. It does not sign, attest, upload build artifacts, or change the
application's default runtime. The runtime, its source capsule and
Ubuntu package inputs are staged privately on minihost before dispatch;
the workflow refuses missing or changed inputs. No public asset is
created by this workflow.

The private rootless Podman environment must match `minihost-platform.sha256`.
The build requires the pinned runtime input manifest and capsule in
`reviewed-inputs.json`. The container and scope deadlines are 60 and
65 minutes, inside a 68-minute rebuild step and a 70-minute job. The
scope uses two CPU equivalents, a 3,500 MiB memory cap and no swap or
zswap. It does not use the Docker service or another runner.

After an approved run, check the actual exit, exact runtime digest,
container and scope cleanup, and local unsigned handoff. The run's
`github-replay-<run-id>-<attempt>/` directory under the private task
prefix holds `rebuild.log` and `handoff/`; neither is uploaded, and
neither depends on GitHub's temporary workspace surviving the job.
Independently
fetch the GitHub run-attempt and job records and check them with
`routing.py`, using the expected commit, run ID and attempt. That check
confirms the reported runner registration, not a physical machine
identity or a signed build. No local synthetic handoff is admissible as
evidence of this workflow.

The hosted CI check runs the fixture suite without minihost, Podman
or the private input bundle. Run it and the workflow linters locally
with:

```sh
python3 -E -B -m unittest discover -s scripts/ci/litert-provenance -p 'test_*.py' -v
bash scripts/check-action-pins.sh
actionlint
zizmor .github/workflows
```
