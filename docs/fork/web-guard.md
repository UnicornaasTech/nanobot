# Web fetch content guard

Fork-only post-fetch screening for `web_fetch` tool output. Models are downloaded from Hugging Face on first use (not bundled in this repo).

## Install

From this fork’s repo root (the `web-guard` extra is not on PyPI yet):

CliGuard (default backend):

```bash
pip install -e ".[web-guard]"
```

Prompt Guard 2 (gated model; requires Hugging Face access):

```bash
pip install -e ".[web-guard-prompt]"
```

Use `pip install ".[web-guard]"` (without `-e`) in Docker or other non-editable installs.

Set `HF_TOKEN` or `HUGGINGFACE_HUB_TOKEN` for Prompt Guard.

## Config

Create `web-fetch-guard.json` next to `config.json`:

```json
{
  "patchEnabled": true,
  "contentGuard": {
    "enabled": true,
    "backend": "cliguard",
    "modelId": "",
    "device": "cpu",
    "threshold": 0.5,
    "maxInputChars": 32000,
    "failClosed": true
  }
}
```

| Field | Description |
|-------|-------------|
| `patchEnabled` | Enable monkey-patch on `WebFetchTool.execute` |
| `contentGuard.backend` | `cliguard` (default) or `prompt-guard` |
| `contentGuard.modelId` | Override HF model id (empty = backend default) |
| `contentGuard.device` | `cpu`, `cuda`, or `mps` |
| `contentGuard.threshold` | Block threshold for classifier scores |
| `contentGuard.failClosed` | Block fetch when guard dependencies or inference fail |

### Environment overrides

| Variable | Effect |
|----------|--------|
| `NANOBOT_WEB_FETCH_GUARD` | Overrides `patchEnabled` (`0`/`false`/`off` disables patch) |
| `NANOBOT_WEB_FETCH_GUARD_DEVICE` | Overrides `contentGuard.device` |
| `HF_TOKEN` / `HUGGINGFACE_HUB_TOKEN` | Hugging Face auth for gated models |

## Backends

| Backend | Default model | Block rule |
|---------|---------------|------------|
| `cliguard` | `fastino/gliguard-LLMGuardrails-300M` | `prompt_safety == unsafe` or any non-`benign` jailbreak label |
| `prompt-guard` | `meta-llama/Llama-Prompt-Guard-2-86M` | top label `malicious` with score ≥ threshold |

When guard is disabled (default until you set ``contentGuard.enabled`` in config), the patch still runs but passes fetch results through unchanged.

## Manual test

```bash
python scripts/defended_web_fetch.py https://example.com/ --pretty
```

Blocked responses use `reason: content_blocked` with no page body.

## Docker

The fork’s `Dockerfile` installs `.[matrix,web-guard]` by default (CPU-only `torch` from the PyTorch index; no NVIDIA CUDA wheels). Enable the guard via `web-fetch-guard.json` in your mounted `~/.nanobot` config.

To **skip** the ML stack when you do not use the guard:

```bash
./build-nanobot.sh no-web-guard
```

Or pass the build arg directly: `docker compose build --build-arg NANOBOT_EXTRAS=matrix`.

Without the extra, runtime still works if you do not enable `contentGuard.enabled`. Set `NANOBOT_WEB_FETCH_GUARD=0` in `.env` (see `.env.example`) to disable the fetch patch entirely. Use `NANOBOT_MEMORY_LIMIT=1G` when the 3G web-guard limit is unnecessary.

`docker-compose.override.yml` mounts your host Hugging Face cache into the container (`${HF_HOME:-~/.cache/huggingface}` → `/home/nanobot/.cache/huggingface`, with `HF_HOME` set in-container). Models downloaded on the host or in a previous container run are reused.

Set `HF_TOKEN` in the repo `.env` file (see `.env.example`); it is loaded into containers via `env_file`.

For Prompt Guard 2, build a custom image with `.[web-guard-prompt]` and set `HF_TOKEN` in `.env`.
