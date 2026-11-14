# Crosspost guard

A small Discord bot that catches one account posting attachments or links in
several channels within a few seconds, which is how hijacked accounts spread
scam screenshots. When that happens it:

1. softbans the account: bans and immediately unbans it, which removes it from the
   server and makes Discord purge its last 10 minutes of messages,
2. deletes the posts that triggered it, and any more that arrive in the next 5 minutes,
3. posts a report in your moderator channel.

The account's owner can rejoin with an invite once they have it back, but their roles
are gone. Set `ACTION=timeout` to mute the account for 24 hours instead and leave it
in the server.

Members with the Manage Messages permission, bots and webhooks are never checked.

## 1. Create the bot account

1. Open <https://discord.com/developers/applications> and choose **New Application**.
2. On the **Bot** page, choose **Reset Token** and copy the token. Treat it like a password.
3. On the same page, turn on **Message Content Intent**. Without it the bot cannot see attachments or links.
4. Copy the **Application ID** from the **General Information** page and open this link with it filled in:

   ```
   https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot&permissions=1374389627908
   ```

   That grants View Channels, Send Messages, Send Messages in Threads, Embed Links,
   Read Message History, Manage Messages, Ban Members (for softbans) and Moderate
   Members (for timeouts).
5. In **Server Settings > Roles**, drag the bot's role above the roles of the members it
   should be able to act on. It can never softban the server owner, and it can never
   time out the owner or administrators.

## 2. Run it

Needs Python 3.10 or newer on a machine that stays on.

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements.txt
```

```bash
DISCORD_TOKEN=your-token .venv/bin/python bot.py
```

Start with `DRY_RUN=1` for a few days if you want to see what it would catch before
it acts on anyone.

## 3. Choose the report channel

In your server, run `/modlog` and pick a channel:

```
/modlog channel:#mod-log
```

The bot posts a test message there and, if that works, sends its reports there from
then on. `/modlog` on its own shows the current channel. The choice is saved in
`settings.json` next to `bot.py`, so it survives restarts.

Only members with Manage Server can use the command. You can change that under
**Server Settings > Integrations**. If the command doesn't show up, restart Discord;
new commands can take a few minutes to appear.

You can also set `LOG_CHANNEL_ID` instead. It is used for any server where nobody has
run `/modlog`. To get a channel ID, turn on **Developer Mode** in Discord's Advanced
settings, then right-click the channel and choose **Copy Channel ID**.

## Optional: keep the token behind a passphrase

Instead of leaving the token readable in a file, you can store it encrypted and type a
passphrase each time the bot starts.

```bash
.venv/bin/python bot.py --encrypt-token
```

It asks for the token and a passphrase, then writes `token.enc`. After that, remove
`DISCORD_TOKEN` from wherever you had it and start the bot as usual; it will ask for
the passphrase. On Windows, use `.venv\Scripts\python` instead.

- The bot cannot start without someone typing the passphrase, so this does not suit a
  service that restarts on its own.
- It protects the token on disk: a stolen laptop, a backup, a synced copy. It does not
  protect against malware running on the machine while the bot is running.
- Some terminals, Git Bash on Windows among them, cannot hide what you type. The bot
  says so when that is the case.
- If `DISCORD_TOKEN` is set, it wins and `token.enc` is ignored.
- If you forget the passphrase, reset the token in the Developer Portal and run
  `--encrypt-token` again.

## Optional: start automatically on Windows

`start-bot.bat` loads `.env` (if there is one) and runs the bot in its own window. To
have it start every time you log in to Windows:

1. Open the `crosspost-guard` folder in File Explorer, right-click `start-bot.bat` and
   choose **Create shortcut** (under **Show more options** on Windows 11).
2. Press Win+R, type `shell:startup` and press Enter. This opens your Startup folder.
3. Move the shortcut into that folder.

To check it, double-click the shortcut: a window titled "Crosspost guard" should open
and log in. To stop starting automatically, delete the shortcut from the Startup folder.

- It starts when you log in, not when the PC switches on, and stops when you log out,
  shut down or the PC sleeps.
- With the passphrase option, the window waits for you to type the passphrase.
- Closing the window stops the bot. To keep it out of the way, right-click the shortcut,
  choose **Properties** and set **Run** to **Minimized**.

## Settings

All are environment variables. Only the token is required: either `DISCORD_TOKEN` or the
passphrase option above.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DISCORD_TOKEN` | none | The bot token. Leave it unset if you use the passphrase option. |
| `LOG_CHANNEL_ID` | none | Report channel for servers where `/modlog` hasn't been run. With neither, catches only appear in the console. |
| `STATE_FILE` | `settings.json` | Where the `/modlog` choices and the `DAILY_LIMIT` count are saved. |
| `TOKEN_FILE` | `token.enc` | Where the passphrase-protected token is kept, if you use that option. |
| `CHANNEL_THRESHOLD` | `3` | How many different channels count as spam. |
| `WINDOW_SECONDS` | `30` | How quickly those posts have to happen. |
| `ACTION` | `softban` | `softban` or `timeout`. |
| `DAILY_LIMIT` | `3` | Most accounts it will softban or time out per server in any 24 hours. `0` removes the limit. |
| `FLAVOR` | `Mr. Beast-ing` | What the report says they were doing, as in "was softbanned for Mr. Beast-ing". |
| `PURGE_MINUTES` | `10` | Softban only: how far back Discord purges the account's messages. |
| `TIMEOUT_HOURS` | `24` | Timeout only: how long. Discord's limit is 28 days (672). |
| `COUNT_LINKS` | `1` | Also count messages that contain a link. Set `0` for attachments only. |
| `EXEMPT_ROLE_IDS` | none | Comma-separated role IDs to skip. |
| `DRY_RUN` | `0` | Set `1` to report without softbanning, timing out or deleting. |

## Things to know

- Threads and forum posts each count as their own channel.
- Forwarded messages are checked as well as normal ones.
- With `COUNT_LINKS=1`, a member who pastes the same link or GIF into three channels
  within 30 seconds will be caught too.
- A softban purges everything the account posted in the last `PURGE_MINUTES`, not
  only the posts that triggered it.
- A report is one line saying what happened, the account's name and ID, and a footer.
  A "Needs attention" section is added only when something went wrong, such as a
  softban that failed or a message that could not be deleted. The console log has the
  full detail for every catch.
- As a safety rail, the bot softbans or times out at most `DAILY_LIMIT` accounts per
  server in any 24 hours (3 by default). Past that it still deletes the posts and
  reports the catch, but leaves the account alone and says so in the report, so a
  moderator has to deal with it. The count is saved in `settings.json`, so restarting
  the bot does not reset it.
- Apart from the `/modlog` choice and that count, the bot keeps its state in memory,
  so a restart forgets the last 30 seconds of posts.

## Tests

```bash
.venv/bin/python -m unittest -v
```
