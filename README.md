# LW Client

Library Watcher is **self-hosted** — you run the server on your own machine over your local network.
This CLI client connects to that server via WebSocket, receives scan commands, hashes files locally,
and sends results back. The client must be able to reach the server over your network.

## Installation

### From GitHub

```bash
npm install -g git+https://github.com/mrdhnto/lw-client.git
```

### Local development

```bash
git clone <repo-url>
cd lw-client
npm install
npm link
```

### Run without installing

```bash
npx github:mrdhnto/lw-client -u <url> -t <token>
```

## Usage

### First-time setup

```bash
lw-client -u ws://your-server:8080/api/client/ws -t <token>
```

Saves the URL and token to `~/.lw-client.json` and connects immediately.

> **Note:** The server must be running and accessible from this machine over your network.

### Reconnect (after restart)

```bash
lw-client connect
```

Reads saved config from `~/.lw-client.json` and reconnects. No need to type
URL and token again.

## Options

| Flag | Alias | Description |
|------|-------|-------------|
| `--url <url>` | `-u` | WebSocket server URL |
| `--token <token>` | `-t` | Authentication token |

## Commands

| Command | Description |
|---------|-------------|
| `connect` | Reconnect using saved configuration |

## Behavior

- Connects to server and authenticates with token + machine hostname
- Token is one-time-use — first hostname to connect claims it
- Same hostname can always reconnect with same token (even after restart)
- Listens for scan commands from server
- Scans directories, computes SHA-256 hashes
  > Remote client scans are **10–30% faster** than server-side scanning.
- Sends progress updates in real-time
- Reconnects on disconnect (exponential backoff)
- Exits cleanly on Ctrl+C or kick from server
