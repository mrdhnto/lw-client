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
# Note: Use wss:// for secure connections, ws:// for local IPs
lw-client -u wss://your-server.com/api/client/ws -t <token>
```

Saves the URL configuration to `~/.lw-client.json`. The token provided is a one-time registration token that is securely exchanged for a session and stored in your OS **keychain** (using `keytar`).

> **Note:** The server must be running and accessible from this machine over your network.

### Reconnect (after restart)

```bash
lw-client connect
```

Reads the saved URL from `~/.lw-client.json` and securely retrieves your token from the OS keychain. No need to type URL and token again.

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

- **Secure Connection:** Automatically defaults to `wss://` in production or `ws://` in development (based on `NODE_ENV` in a `.env` file). You can also explicitly force it using `FORCE_WSS=true` in `.env`.
- **Hardware Binding:** Connects to server and authenticates with your token. The CLI automatically generates a secure **hardware fingerprint**.
- Token is one-time-use — the first machine to connect binds the token permanently to its hardware ID. Behind the scenes, it's exchanged for short-lived, rotating **JWT Access Tokens**.
- Same machine can always reconnect automatically (even after restart). Spoofing the hostname from another machine will be rejected due to hardware mismatch.
- **Auto-healing Sessions:** If a session expires while connected, the CLI will automatically fetch a new JWT and reconnect seamlessly.
- Listens for scan commands from server
- Scans directories, computes SHA-256 hashes
  > Remote client scans are **10–30% faster** than server-side scanning.
- Sends progress updates in real-time
- Reconnects on disconnect (exponential backoff)
- Exits cleanly on Ctrl+C or kick from server
