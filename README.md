This code was written with the help of generative AI tools and reviewed by ETLYON. It is intended for professional use; test it in your environment before production. Provided as is, without warranty.

# open-mcp-nextcloud

Connect any assistant to **your own Nextcloud (Hub)**. You bring your server or account and your own key; nothing is set up in advance.

Works with Claude, ChatGPT, Le Chat, eBot and any assistant that can add a connector by address. Your assistant acts as you, with exactly the rights you have.

> "mcp" appears only in this repository's name. People and product screens say **Apps** / **Connector** (D386).

## Install in 5 minutes

**1. Run one Docker container** (TLS in front of it; set the three names below — never put secrets in the image):

```sh
mkdir -p /etc/open-mcp-nextcloud /var/lib/open-mcp-nextcloud
cat >/etc/open-mcp-nextcloud/connector.toml <<'EOF'
public_url = "https://hub.example.org"
app = "nextcloud"
state_dir = "/var/lib/open-mcp-nextcloud"
source_url = "https://github.com/etlyon/open-mcp-nextcloud"
maker_label = "open source"
EOF
docker build -t open-mcp-nextcloud:0.1.0 .
docker run --name open-mcp-nextcloud --restart=unless-stopped \
  -p 127.0.0.1:8120:8000 \
  -v /etc/open-mcp-nextcloud/connector.toml:/config/connector.toml:ro \
  -v /var/lib/open-mcp-nextcloud:/var/lib/open-mcp-nextcloud \
  open-mcp-nextcloud:0.1.0
```

Settings (names only — put your own values):
| Setting | Meaning |
|---|---|
| `public_url` | Public https host of **this** connector (no path) |
| `source_url` | Public source of the code you run (AGPL §13) |
| `state_dir` | Where the SQLite file lives (0700) |
| `allowed_servers` | Optional exact hosts people may connect (Hub server apps) |
| `allowed_mail_domains` / `send_recipient_domains` | kSuite only — see `config.example.toml` |

Put a reverse proxy with TLS in front (`X-Forwarded-For` / `X-Forwarded-Proto`) and pass `--forwarded-allow-ips` if you change the entrypoint.

**2. Connect it in eBot (or any AI app)**

1. In the assistant, add a custom connector / MCP server and paste `https://<your-connector-host>/mcp`.
2. Complete the on-screen window (address + key, or Grant access, or Infomaniak token — this app's steps are below).
3. Allow the assistant when asked. Done.

Same paste works in Claude, ChatGPT, Le Chat and eBot. Menu names per assistant: [docs/assistants.md](docs/assistants.md).

## Hub (Nextcloud)

Same window, same four steps; one process with `app = "nextcloud"` (see `config.example.toml`).

**B. Which server?** Type the address you open Nextcloud with, e.g. `cloud.example.com` (a pasted page address such as `https://cloud.example.com/apps/files/files?dir=/` is fine: only the host is kept). The page checks `status.php`: installed, not in maintenance, version 28 or newer. Version 1 supports Nextcloud installed at the root of its host only (not under a sub-path such as `/nextcloud`).

**C. Grant access.** The page shows *1. Open Hub ↗ 2. Click Log in, then Grant access 3. Come back here*. "Open Hub" is Nextcloud's own Login Flow v2 page on your server (it shows **Log in** first, then **Grant access**); after you click **Grant access** there, this page notices by itself (it reloads every few seconds) and connects. Nextcloud then lists a new app password named "Assistant connector" under *Settings › Security*. Not possible? **Paste an app password instead**: in Nextcloud, *Your picture › Settings › Security › Create new app password* (an administrator's menu says *Personal settings*), then paste the user name and the app password it shows.

**D. Done.** Your assistant can list, search and read your files (PDF, Word, Excel, PowerPoint and OpenDocument are read in memory), write files and folders, move and delete (to the trash). Overwriting, moving and deleting ask you first.

To stop: remove the connector in your assistant. Its app password is then deleted in Nextcloud too. App passwords do not expire, so there is no reminder.

People see **Hub**; this repository is named for Nextcloud.

## What it keeps

- Your key (Odoo), app password (Hub) or API token (kSuite, with the id and address of your own mailbox), encrypted with a key that only your assistant's live sign-in can unlock. A copy of the connector's disk or backups opens nothing.
- Your name and email as Odoo, Nextcloud or Infomaniak gives them, to show on the "Allow?" and "connected" pages.
- For a change made with an idempotency key (so a repeat does not write twice): the key, a hash of the arguments and the answer. For kSuite only the ids, yes/no answers and counts of that answer are kept: no address, subject, title or text.
- Nothing else: no chat content.

## Licence

AGPL-3.0-or-later ([LICENSE](LICENSE)). If you run a modified copy for others, offer them its source: set `source_url`; every page links to it. Third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Not affiliated with Odoo S.A., Nextcloud GmbH or Infomaniak.
