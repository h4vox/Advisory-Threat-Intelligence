# Antigravity agent (AGY) sandbox

AIE runs the Antigravity CLI (`agy`) only inside a Docker container, `aie-agent-sandbox`. The host
needs Docker; nothing about the agent is installed on the host.

## Install and sign in

Marketplace → Manage AI integrations → **Antigravity Agent (AGY)** → **Install** → **Install and sign in**
(administrators only). The steps run on the server and the page shows each one as it happens:

1. **Environment.** Docker answers, and the sandbox image exists. The first install builds it
   (`docker compose -f docker-compose.agent-sandbox.yml build`), which runs Google's official installer
   (`https://antigravity.google/cli/install.sh`) and takes a few minutes.
2. **Install.** The real CLI is in the image. If the image holds only the fallback shim (built while
   the installer could not be reached), AIE rebuilds it once and reports the build's warning if the
   CLI is still missing.
3. **Start.** The container runs with the agent's home on the `aie-agent-home` volume.
4. **Sign in.** If the CLI already answers a prompt, it is signed in and setup finishes. Otherwise
   AIE starts `agy` in a pseudo-terminal inside the container, picks **Google OAuth** in the CLI's
   menu, and shows the sign-in link the CLI printed. Open it, approve access, and paste the
   authorization code Google shows (or the address of the page it sent you to). AIE types it into the
   CLI, waits for "Signing in…" to finish, then sends a real prompt to confirm the agent answers.

The CLI owns the sign-in: the link uses the CLI's own OAuth client, and the CLI exchanges the code
and stores the result in its home. AIE never builds OAuth links, never sees Google tokens, and never
stores or logs the authorization code (it is redacted from the CLI output shown to administrators).

## Where the sign-in lives

In the `aie-agent-home` volume (the container's `/home/agent`), so it survives container restarts and
re-creation. **Reset** in the install view signs out completely: it removes the container and the
volume. Older versions used a volume named `aie-agent-vault`; it is no longer used and Reset removes it.

## Container hardening

User 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`, memory, CPU and
process limits, tmpfs `/tmp` and `/workspace`, no host directories mounted. Network access stays on
because the agent must reach its model API. Prompts run in print mode with tools disabled.

## Troubleshooting

| What the install view says | What to do |
|---|---|
| Docker is not installed / not reachable | Install or start Docker, then **Try again**. |
| The Antigravity CLI could not be installed … `antigravity.google` | The image build could not download the installer. Check this machine's network access to `antigravity.google`, then **Try again** (it rebuilds). |
| The CLI rejected the code | The code was wrong or expired. **Try again** gets a new link. |
| The sign-in was interrupted | The server restarted while the link was open. **Try again**. |

Build the image by hand: `docker compose -f docker-compose.agent-sandbox.yml build`. Skip the CLI
download (shim only): add `--build-arg AGY_INSTALL=0`.
