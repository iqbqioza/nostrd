# Deploying nostrd on any VPS (Ubuntu / Debian)

This is the generic guide for a plain Linux VPS (any provider — Hetzner, Vultr, Linode, Contabo, your own server, ...). The other platform guides (Digital Ocean, AWS, GCP, Azure) are shortcuts of this one with their provider-specific firewall steps.

## 1. Install the binary

The `install.sh` script downloads the latest release binary for your architecture (x86_64 / aarch64), verifies its sha256 checksum and installs it into a directory on `PATH` — **no sudo needed for the install itself**:

```sh
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrd/main/install.sh | sh
nostrd --version
```

## 2. Create a configuration

```sh
sudo mkdir -p /etc/nostrd
```

Copy the template from the repository and edit it:

```sh
sudo cp fly/nostrd.toml /etc/nostrd/nostrd.toml
sudo nano /etc/nostrd/nostrd.toml
```

At minimum, set:

```toml
[relay]
name = "My Relay"
public_url = "wss://relay.example.com"   # your public address
private_key = "..."                      # run `nostrd genkey` locally and paste the key

[server]
host = "0.0.0.0"                         # already set in the template
port = 8080
```

Generate the secret key with:

```sh
nostrd --config /tmp/nostrd-genkey.toml init && nostrd --config /tmp/nostrd-genkey.toml genkey
```

(Or mount your own config file instead of the template — any `nostrd.toml` works.)

## 3. Run as a systemd service

The repository ships a hardened unit at `deploy/nostrd.service`:

```sh
sudo cp deploy/nostrd.service /etc/systemd/system/nostrd.service
sudo systemctl daemon-reload
sudo systemctl enable --now nostrd
sudo systemctl status nostrd
```

Logs:

```sh
journalctl -u nostrd -f
```

## 4. Open the port and verify

Allow TCP 8080 in your firewall (ufw, cloud firewall, host firewall):

```sh
sudo ufw allow 8080/tcp
```

Verify locally and from the outside:

```sh
curl http://localhost:8080/health
curl http://<server-ip>:8080/health        # from your laptop
```

## 5. Put a TLS-terminating proxy in front (for wss://)

The relay serves plain WebSocket on 8080. To expose it as `wss://`, run a reverse proxy on port 443 that terminates TLS. The relay honors `X-Forwarded-Proto`, so no special configuration is needed.

**nginx** (`/etc/nginx/sites-available/relay`):

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Get a free certificate with [certbot](https://certbot.eff.org/) (`sudo certbot --nginx -d relay.example.com`).

**Caddy** (auto TLS, one file):

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Make sure `relay.public_url` in the config matches `wss://relay.example.com`.

## 6. Backups

Stop the relay, copy the data directory, restart:

```sh
sudo systemctl stop nostrd
sudo tar -czf nostrd-data-backup.tar.gz /var/lib/nostrd   # your database.path
sudo systemctl start nostrd
```

## Updates

```sh
# install.sh overwrites the binary in place (it asks for confirmation)
./install.sh
sudo systemctl restart nostrd
```
