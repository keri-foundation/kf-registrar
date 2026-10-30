# kf-registrar

`kf-registrar` is the KERI Foundation registrar service: a long-running node that
governs ACDC transaction event logs (TELs) and serves them in bulk to
observers only (see kf-observer).

It is the ACDC counterpart of a witness. Witnesses serve KELs; this process
serves TELs. Wallets and verifiers do not communicate directly with this service, they 
should talk to an observer.

## Dual HTTP

Modeled on [`witness-hk`](https://github.com/keri-foundation/witness-hk):

- **Internal / admin** (default `127.0.0.1:6631`): controller API for the
  registrar/issuer habitat. Create/list registries, append `bup`, read its own
  TEL data **without** running an observer. Also
  `POST /ingest` for hosting pre-built, KEL-anchored TEL events (e.g.
  presentation registries built in a wallet): JSON
  `{ "kel": "<CESR>", "tel": "<CESR rip/bup>" }` → verify (`regeventing.vet`)
  and store for observer bulk. This is controller publish, not a wallet status
  query.
- **External** (default `127.0.0.1:6632`): signed V2 `qry` POST (`r: "tels/bulk"`
  or `"regs"`) authenticated with KRAM and restricted to configured observer
  AIDs. Response is concatenated CESR of accepted `rip`/`bup` events.

There is no registrar pool, no TEL receipts, and no wallet-shaped
`GET /query?typ=tel`. Wallets and verifiers must not query this service for
TEL status; they talk to an observer.

## Introduce an observer

Before its first signed query, an observer publishes its public key history to
`POST /introductions` on the external port. Send the signed V2 KEL clone as raw
CESR with `Content-Type: application/cesr`. Native KERI validation checks
new events, signatures, delegation, and witness receipts. The response is
`{"prefixes": ["<observer AID>"]}` after all supplied events are accepted.
Malformed, unsigned, or unaccepted history returns HTTP 400.

The registrar accepts history only for AIDs configured with `--observer` and
the delegators their delegated inception events name. Supply each delegator's
history, including its delegation anchors, before the dependent observer history.
Any other event prefix in the stream returns HTTP 403 before processing.
Native validation processes events one at a time, so events accepted or
escrowed before a later failure stay in the registrar database. Resend the
complete clone to finish the introduction. Previously accepted events, including
history superseded by recovery, are skipped using the native first-seen log.

An introduction supplies verification keys. It does not grant access. Each
query must still pass KRAM. Publish updated public history after a rotation.
Do not send private keys or credential data to this endpoint.

## Requirements

- Python >= 3.14
- `libsodium` (required by the `keri` package)

### Installing libsodium

**macOS:**

```bash
brew install libsodium
```

**Ubuntu/Debian:**

```bash
sudo apt-get install libsodium-dev
```

## Installation

Published dependency is `keri` from WebOfTrust/keripy. In this umbrella
checkout, `tool.uv.sources` points at the sibling `../keripy` (editable):

```bash
cd kf-registrar
uv sync --all-extras
```

Or with pip:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e '.[dev]'
```

Standalone clones without the sibling tree will pull `keri` from git.
## Running

```bash
kf-registrar start \
  --alias registrar \
  --config-dir /path/to/scripts \
  --config-file kf-registrar \
  --host 127.0.0.1 \
  --http 6632 \
  --boothost 127.0.0.1 \
  --bootport 6631 \
  --observer <observer-aid>
```

`--config-dir` must point at the directory *above* `keri/cf/` (KERI appends
`keri/cf/` when locating the file). For this repo that is `scripts/`.

Repeat `--observer` for each allow-listed observer AID, or list them in
`scripts/keri/cf/kf-registrar.json` under `kf-registrar.observers`.

## Tests

```bash
export DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix)/lib:/usr/local/lib:/usr/lib"
export DYLD_LIBRARY_PATH="$(brew --prefix)/lib"
pytest tests/
```

On Linux, libsodium install is enough; the `DYLD_*` exports are macOS-only.
