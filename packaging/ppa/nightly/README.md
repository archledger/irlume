# The nightly PPA uploader

`scripts/ppa-nightly.py` uploads `main` to `ppa:archledger/irlume-nightly`
once a day ([ADR-0037](../../../docs/adr/0037-nightly-channel.md) section 3).
It runs as a user timer on minihost, which holds the key Launchpad has for
`~archledger` and already runs user timers with lingering enabled.

## Install

From a reviewed checkout, never the clone the script updates (the script
holds the key's use, so it runs only reviewed code; code from `main` runs
only inside its build container):

```sh
install -Dm0644 scripts/ppa-nightly.py ~/.local/lib/irlume-nightly/ppa-nightly.py
install -Dm0644 scripts/verify-ppa-publish.py ~/.local/lib/irlume-nightly/verify-ppa-publish.py
install -Dm0644 packaging/ppa/nightly/irlume-ppa-nightly.service ~/.config/systemd/user/irlume-ppa-nightly.service
install -Dm0644 packaging/ppa/nightly/irlume-ppa-nightly.timer ~/.config/systemd/user/irlume-ppa-nightly.timer
systemctl --user daemon-reload
systemctl --user enable --now irlume-ppa-nightly.timer
```

Reinstall the two scripts the same way after a reviewed change to them.

It needs docker (or podman), git, and gpg with the key in the user's
gpg-agent. The PPA `irlume-nightly` must exist under `~archledger` first.

## What it keeps

- `~/.local/share/irlume-nightly/irlume`: its clone of the repository.
- `~/.local/state/irlume-nightly/ppa.json`: the version last published, a
  pending upload or a failed one (the decisions are in `decide()`).
- `~/.cache/irlume-nightly`: the last build, a few GB, on disk.

## Checking on it

```sh
systemctl --user list-timers irlume-ppa-nightly.timer
journalctl --user -u irlume-ppa-nightly.service -n 50
cat ~/.local/state/irlume-nightly/ppa.json
python3 ~/.local/lib/irlume-nightly/ppa-nightly.py --no-upload   # build and sign only
```

One run at a time: a run started while another holds
`~/.local/state/irlume-nightly/lock` (the timer's, or a dry run) exits 1
without touching anything.
