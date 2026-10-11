# Security

BoxBox is built for private homelab use. It can modify real host files, so treat deployment configuration as part of the security boundary.

## Required Hardening

Before exposing BoxBox beyond your own machine:

- Set `BOXBOX_JWT_SECRET` to a long random value.
- Set `BOXBOX_USERS_admin` to a bcrypt hash or configure a bcrypt hash in `config.yaml`.
- Use a reverse proxy with HTTPS.
- Mount only the directories BoxBox needs.
- Use `read_only: true` for backups and sensitive locations.
- Do not expose `/host_root`; whole-host browsing is intentionally absent from the default deployment.
- Keep the default same-origin WebSocket policy or use a narrow `allowed_origins` list.
- Put the service behind your normal VPN, Tailscale, WireGuard, or trusted reverse proxy access controls when possible.

## Authentication Model

BoxBox uses JWT access and refresh tokens:

- Access tokens expire after 15 minutes.
- Refresh tokens expire after 7 days and are rotated in an HttpOnly, SameSite=Strict cookie.
- Access tokens stay in browser memory. Logout revokes the refresh token and, when supplied and valid for the same user, the access token.
- Refresh rotation and logout save revocations to `auth-revocations.json` under `data_dir`. The store holds refresh-token SHA-256 hashes and access-token IDs with expiry times, never raw JWTs.
- On Linux, the service restricts the store directory to `0700` and the file to `0600`. It creates a missing store at startup, but it does not reset a corrupt, unreadable, or unsupported store.
- A write failure before snapshot publication returns `500`; the server restores only entries changed by that request and keeps the refresh cookie for retry. If a later durability check fails after publication, the server returns `401 SESSION_RECOVERY_REQUIRED` and clears the cookie because it cannot confirm the installed snapshot will survive a crash. Sign in again.
- Keep `data_dir` on persistent storage and run one server process per directory. Deleting the store, restoring an older backup, or downgrading to a version that does not preserve revocations can make revoked tokens valid again. Rotate `BOXBOX_JWT_SECRET` if the store is lost or rolled back. Revocations from before this feature cannot be recovered; rotate the secret after upgrading if those sessions must be invalidated.
- Auth endpoints are rate-limited per client IP.
- Repeated failures trigger exponential per-account lockouts.

Generate bcrypt hashes with `htpasswd` (from `apache2-utils` on Debian/Ubuntu):

```bash
htpasswd -bnBC 12 admin 'your-password' | cut -d: -f2
```

Store only the resulting hash:

```yaml
users:
  admin: "$2b$12$..."
```

```bash
BOXBOX_USERS_admin='$2b$12$...'
```

Plaintext configured passwords and JWT secrets shorter than 32 bytes are rejected at startup. If no users are configured, the server also refuses to start.

## Mount Point Safety

Mount points define what the authenticated UI and API can access.

Prefer narrow paths:

```yaml
mount_points:
  - name: "media"
    path: "/srv/media"
    read_only: false
  - name: "backups"
    path: "/srv/backups"
    read_only: true
```

The default compose file does not mount `/`. A mount that resolves to `/` is rejected unless `allow_root_mount: true` is explicitly configured after reviewing the risk.

## Path Validation

The backend validates requested paths against configured mount points and blocks traversal outside those roots. Examples of blocked paths include:

```text
../secret
..%2Fsecret
media/../../etc/passwd
```

Read-only mount points also block write operations after path resolution.

## WebSocket Origins

With no `allowed_origins`, BoxBox accepts browser WebSocket upgrades only when `Origin` matches the request host. A literal `*` is supported as an explicit, risky opt-out.

Restrict origins for browser-exposed deployments:

```yaml
allowed_origins:
  - "https://boxbox.example.com"
  - "*.internal.example.com"
```

Or through env:

```bash
BOXBOX_ALLOWED_ORIGINS="https://boxbox.example.com,*.internal.example.com"
```

## Reverse Proxy Checklist

Use your proxy to provide:

- HTTPS certificates.
- HTTP to HTTPS redirect.
- WebSocket forwarding for `/api/v1/ws`.
- Request size limits compatible with your upload size.
- Optional extra auth, IP allow-listing, or VPN-only access.

If you use Traefik or another reverse proxy, add routing and TLS configuration according to that proxy's setup. The default compose file uses normal host port binding.

Forwarded client-IP headers are ignored unless the direct proxy IP/CIDR is configured in `trusted_proxies` or `BOXBOX_TRUSTED_PROXIES`.

## Upload Safety

Chunked uploads are assembled in `/tmp/boxbox` by default and moved into the final destination when complete. Configure enough disk space for temporary chunks:

```yaml
volumes:
  - boxbox-temp:/tmp/boxbox
```

Use `max_upload_mb` to cap accepted upload sizes.

## Share Links

Share links expose one file or a folder tree to anyone holding the token URL:

- Tokens are 256-bit random values (43 URL-safe characters); possession of the token is the only credential for recipient endpoints.
- Recipient endpoints are public and rate-limited per client IP, separately from the stricter auth budget.
- Unknown, expired, and revoked tokens all return the same `404`, so recipients cannot probe why a link stopped working.
- Share management is scoped to the creating account: users can list, update, and revoke only their own links.
- Owners can revoke a link at any time; expiry is optional (`expiresInSeconds` at creation). A revocation that completes during an upload prevents that upload from being published.
- Shared targets are re-resolved against the current mount configuration on every recipient access. Removed or renamed mounts invalidate the link, and a mount that became read-only still serves reads while denying uploads or deletes.
- Recipient downloads and previews carry the same sandboxed `Content-Security-Policy` as the app's streaming endpoints, and active document formats (HTML, SVG, XML) are forced to download instead of rendering inline.
- Folder uploads are capped by both the per-link `maxUploadBytes` and server `max_upload_mb` limits. Upload-only links cannot replace existing items; delete permission also permits replacement and deletion below (never at) the shared root.
- Folder ZIP archives validate traversal and resolved paths against the share root before streaming.
- Full-access links also allow folder creation and empty file edits. Folder creation uses an opened filesystem root to confine mutations if another writer swaps a parent directory for a symlink.
- Anyone holding an active share link can view the owner's stored wallpaper. The browser keeps the wallpaper owner marker and cancels pending synchronization when the authenticated session ends.
- Recipient metadata responses never include mount names or internal paths.
- The share store directory is restricted to owner access (`0700`) and its token-bearing `shares.json` file to `0600`, including existing stores when the service initializes.
- Before downgrading to a version predating split upload/delete permissions, back up `shares.json`; older versions cannot preserve the new per-link permissions and upload caps if they rewrite the store.

## Operational Checklist

- Rotate `BOXBOX_JWT_SECRET` if it was ever committed or shared.
- After upgrading from a version that kept revocations only in memory, rotate `BOXBOX_JWT_SECRET` once if you need to invalidate every token that may have been revoked before a restart. Those old revocations cannot be recovered.
- Rotate admin passwords after test deployments.
- Review mounted paths after adding new host disks.
- Check logs for repeated failed logins or path validation errors.
- Keep the image rebuilt from current dependencies.
- Back up `/data` if custom drive names matter to you.
