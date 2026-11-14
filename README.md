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

## Settings

All are environment variables. Only `DISCORD_TOKEN` is required.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DISCORD_TOKEN` | none | The bot token. |
| `LOG_CHANNEL_ID` | none | Report channel for servers where `/modlog` hasn't been run. With neither, catches only appear in the console. |
| `STATE_FILE` | `settings.json` | Where the `/modlog` choices and the `DAILY_LIMIT` count are saved. |
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
