"""Crosspost guard: catches one account posting attachments or links in several
channels within a short window (the usual pattern of a hijacked account posting
scam screenshots), softbans the account, deletes the posts and tells the mods.

Configuration is by environment variable; see README.md.
"""

from __future__ import annotations

import base64
import getpass
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import discord
from discord import app_commands

log = logging.getLogger("crosspost-guard")


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _ids(name: str) -> set[int]:
    return {int(part) for part in os.environ.get(name, "").split(",") if part.strip()}


# How many different channels, within how many seconds, counts as spam.
CHANNEL_THRESHOLD = int(os.environ.get("CHANNEL_THRESHOLD", "3"))
WINDOW_SECONDS = float(os.environ.get("WINDOW_SECONDS", "30"))
# What to do to the account. "softban" bans and immediately unbans, which removes
# it from the server and has Discord purge its recent messages. "timeout" keeps
# it in the server but muted.
ACTION = os.environ.get("ACTION", "softban").strip().lower()
if ACTION not in {"softban", "timeout"}:
    raise SystemExit(f"ACTION must be 'softban' or 'timeout', not {ACTION!r}.")
ACTION_VERB = {"softban": "softbanned", "timeout": "timed out"}
# What the report says the account was doing, as in "was softbanned for ...".
FLAVOR = os.environ.get("FLAVOR", "Mr. Beast-ing")
# Softban only: how far back Discord purges the account's messages.
PURGE_MINUTES = float(os.environ.get("PURGE_MINUTES", "10"))
# Timeout only: how long. Discord's maximum is 28 days.
TIMEOUT_HOURS = float(os.environ.get("TIMEOUT_HOURS", "24"))
# Count messages that contain a link as well as ones with attachments.
COUNT_LINKS = _flag("COUNT_LINKS", True)
# Report only: no timeout, no deletions.
DRY_RUN = _flag("DRY_RUN", False)
# Channel that receives a report for each catch, for servers where nobody has
# chosen one with /modlog (optional).
LOG_CHANNEL_ID = int(os.environ.get("LOG_CHANNEL_ID", "0")) or None
# Where the channels chosen with /modlog are remembered.
STATE_FILE = Path(os.environ.get("STATE_FILE", "settings.json"))
# Where the token is kept when it is stored behind a passphrase (optional).
TOKEN_FILE = Path(os.environ.get("TOKEN_FILE", "token.enc"))
# Work factor for turning the passphrase into a key. Higher is slower to guess.
SCRYPT_N = 2**17
MIN_PASSPHRASE = 8
# Roles that are never checked. Members with Manage Messages are always skipped.
EXEMPT_ROLE_IDS = _ids("EXEMPT_ROLE_IDS")
# Safety rail: the most accounts the bot will softban or time out in one server
# in any 24 hours. Past that it still deletes and reports, but leaves the
# account to the moderators. 0 means no limit.
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "3"))
if DAILY_LIMIT < 0:
    raise SystemExit("DAILY_LIMIT must be 0 or more.")
DAY_SECONDS = 24 * 60 * 60
# After a catch, keep deleting that account's matching posts for this long, in
# case the softban or timeout failed or messages were already in flight.
FLAG_SECONDS = 300.0

URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


@dataclass(frozen=True)
class Hit:
    channel_id: int
    message_id: int
    at: float


@dataclass(frozen=True)
class Verdict:
    hits: list[Hit]  # messages to remove
    newly_flagged: bool  # True on the message that crossed the threshold


class SpamTracker:
    """Remembers each member's recent matching posts and says when to act."""

    def __init__(self, threshold: int, window: float, flag_seconds: float = FLAG_SECONDS):
        self.threshold = threshold
        self.window = window
        self.flag_seconds = flag_seconds
        self._hits: dict[tuple[int, int], list[Hit]] = {}
        self._flagged: dict[tuple[int, int], float] = {}
        self._records = 0

    def record(
        self, guild_id: int, user_id: int, channel_id: int, message_id: int, now: float
    ) -> Verdict | None:
        self._records += 1
        if self._records % 500 == 0:
            self._sweep(now)

        key = (guild_id, user_id)
        hit = Hit(channel_id, message_id, now)

        flagged_until = self._flagged.get(key)
        if flagged_until is not None:
            if now < flagged_until:
                return Verdict([hit], newly_flagged=False)
            del self._flagged[key]

        # Keep only posts within one window of the newest. Messages can arrive
        # late or out of order (Discord replays missed ones after a reconnect),
        # so this goes by when they were posted, not by arrival order.
        hits = [*self._hits.get(key, ()), hit]
        newest = max(h.at for h in hits)
        hits = [h for h in hits if newest - h.at <= self.window]
        self._hits[key] = hits

        if len({h.channel_id for h in hits}) < self.threshold:
            return None

        del self._hits[key]
        self._flagged[key] = newest + self.flag_seconds
        return Verdict(hits, newly_flagged=True)

    def _sweep(self, now: float) -> None:
        stale = [
            k for k, v in self._hits.items() if now - max(h.at for h in v) > self.window
        ]
        for key in stale:
            del self._hits[key]
        for key in [k for k, until in self._flagged.items() if now >= until]:
            del self._flagged[key]


class Settings:
    """What the bot has to remember across restarts, kept in a JSON file: each
    server's report channel from /modlog, and when it last softbanned or timed
    someone out there (for DAILY_LIMIT).
    """

    def __init__(self, path: Path):
        self.path = path
        self._log_channels: dict[int, int] = {}
        self._actions: dict[int, list[float]] = {}
        try:
            saved = json.loads(path.read_text())
            self._log_channels = {
                int(g): int(c) for g, c in saved.get("log_channels", {}).items()
            }
            self._actions = {
                int(g): [float(t) for t in times] for g, times in saved.get("actions", {}).items()
            }
        except FileNotFoundError:
            pass
        except (ValueError, TypeError, AttributeError) as exc:
            raise SystemExit(f"{path} is damaged ({exc!r}). Fix it or delete it.") from exc

    def _save(self) -> None:
        saved = {
            "log_channels": {str(g): c for g, c in self._log_channels.items()},
            "actions": {str(g): times for g, times in self._actions.items() if times},
        }
        # Write beside the file and swap it in, so a crash can't leave it half-written.
        scratch = self.path.with_name(self.path.name + ".tmp")
        scratch.write_text(json.dumps(saved, indent=2) + "\n")
        scratch.replace(self.path)

    def log_channel_id(self, guild_id: int) -> int | None:
        return self._log_channels.get(guild_id, LOG_CHANNEL_ID)

    def set_log_channel(self, guild_id: int, channel_id: int) -> None:
        self._log_channels[guild_id] = channel_id
        self._save()

    def claim_action(self, guild_id: int, now: float) -> float | None:
        """Take one of this server's action slots for the last 24 hours.

        Returns a receipt to hand to release_action if the action then fails,
        or None if DAILY_LIMIT is already used up. The slot is taken before
        the action is attempted so that simultaneous catches can't both
        squeeze under the limit.
        """
        recent = [t for t in self._actions.get(guild_id, []) if now - t < DAY_SECONDS]
        self._actions[guild_id] = recent
        if DAILY_LIMIT and len(recent) >= DAILY_LIMIT:
            return None
        recent.append(now)
        self._save()
        return now

    def release_action(self, guild_id: int, receipt: float) -> None:
        times = self._actions.get(guild_id, [])
        if receipt in times:
            times.remove(receipt)
            self._save()


def is_suspicious(message: discord.Message) -> bool:
    """True for messages that carry an attachment or (optionally) a link.

    Forwarded messages are checked too, since their content lives in a snapshot
    rather than on the message itself.
    """
    parts = [message, *getattr(message, "message_snapshots", [])]
    for part in parts:
        if part.attachments:
            return True
        if COUNT_LINKS and URL_RE.search(part.content or ""):
            return True
    return False


def is_exempt(member: discord.Member) -> bool:
    if member.guild_permissions.manage_messages:
        return True
    return any(role.id in EXEMPT_ROLE_IDS for role in member.roles)


intents = discord.Intents.none()
intents.guilds = True
intents.guild_messages = True
intents.message_content = True  # privileged: enable it in the Developer Portal

client = discord.Client(intents=intents, allowed_mentions=discord.AllowedMentions.none())
tree = app_commands.CommandTree(client)
tracker = SpamTracker(CHANNEL_THRESHOLD, WINDOW_SECONDS)
settings = Settings(STATE_FILE)


@client.event
async def setup_hook() -> None:
    # Register /modlog with Discord. The guard still works if this fails.
    try:
        synced = await tree.sync()
        log.info("Registered with Discord: %s", ", ".join(f"/{c.name}" for c in synced) or "none")
    except discord.HTTPException as exc:
        log.warning("Could not register the /modlog command: %s", exc)


@tree.command(name="modlog", description="Choose where crosspost guard posts its reports.")
@app_commands.describe(channel="Channel for reports. Leave empty to see the current one.")
@app_commands.default_permissions(manage_guild=True)
@app_commands.guild_only()
async def modlog(
    interaction: discord.Interaction, channel: discord.TextChannel | None = None
) -> None:
    guild = interaction.guild

    if channel is None:
        current = settings.log_channel_id(guild.id)
        if current is None:
            text = "No report channel is set. Run `/modlog` with a channel to choose one."
        else:
            text = f"Reports go to <#{current}>."
        await interaction.response.send_message(text, ephemeral=True)
        return

    # Prove the bot can post reports there before switching to it.
    mine = channel.permissions_for(guild.me)
    needed = {
        "View Channel": mine.view_channel,
        "Send Messages": mine.send_messages,
        "Embed Links": mine.embed_links,
    }
    missing = [name for name, has in needed.items() if not has]
    problem = f"I'm missing {', '.join(missing)} there" if missing else None
    if problem is None:
        try:
            await channel.send(
                f"Crosspost guard reports will be posted here (set by {interaction.user.mention})."
            )
        except discord.HTTPException as exc:
            problem = f"Discord refused my test message ({exc.text or exc})"
    if problem:
        await interaction.response.send_message(
            f"Nothing was changed: {problem}, so I can't report in {channel.mention}.",
            ephemeral=True,
        )
        return

    settings.set_log_channel(guild.id, channel.id)
    log.info("%s set the report channel in %s to #%s", interaction.user, guild.name, channel.name)
    await interaction.response.send_message(
        f"Reports will now go to {channel.mention}.", ephemeral=True
    )


@client.event
async def on_ready() -> None:
    log.info(
        "Logged in as %s. Watching %d server(s): %d channels in %gs gets a %s%s",
        client.user,
        len(client.guilds),
        CHANNEL_THRESHOLD,
        WINDOW_SECONDS,
        ACTION,
        " (dry run)" if DRY_RUN else "",
    )


@client.event
async def on_message(message: discord.Message) -> None:
    member = message.author
    if message.guild is None or member.bot or message.webhook_id:
        return
    if not isinstance(member, discord.Member) or is_exempt(member):
        return
    if not is_suspicious(message):
        return

    # Use the time Discord says the message was posted, not the time it reached
    # us: after a reconnect, minutes of missed messages arrive within a second.
    posted_at = message.created_at.timestamp()
    verdict = tracker.record(
        message.guild.id, member.id, message.channel.id, message.id, posted_at
    )
    if verdict is not None:
        await act(message, member, verdict)


async def punish(member: discord.Member) -> tuple[str | None, str]:
    """Softban or time out the member.

    Returns what ended up happening to them ("softbanned", "timed out", "banned",
    or None if nothing did) and a note for the report.
    """
    reason = f"Posted in {CHANNEL_THRESHOLD}+ channels within {WINDOW_SECONDS:g}s"

    if ACTION == "timeout":
        try:
            await member.timeout(timedelta(hours=TIMEOUT_HOURS), reason=reason)
        except discord.HTTPException as exc:
            return None, f"Could not time out: {exc.text or exc}"
        return "timed out", f"Timed out for {TIMEOUT_HOURS:g}h."

    try:
        await member.ban(delete_message_seconds=int(PURGE_MINUTES * 60), reason=reason)
    except discord.HTTPException as exc:
        return None, f"Could not softban: {exc.text or exc}"
    try:
        await member.unban(reason="Softban: lifting the ban straight away")
    except discord.HTTPException as exc:
        return "banned", (
            f"Banned, but the ban could NOT be lifted, so unban them by hand: {exc.text or exc}"
        )
    return "softbanned", "Softbanned: removed from the server and free to rejoin with an invite."


async def act(message: discord.Message, member: discord.Member, verdict: Verdict) -> None:
    guild = message.guild
    notes: list[str] = []  # what happened, for the console
    problems: list[str] = []  # what a moderator has to deal with, for the report too
    headline = ""

    if DRY_RUN:
        headline = f"{member.mention} would have been {ACTION_VERB[ACTION]} for {FLAVOR}"
        notes.append(f"Dry run: nothing was removed and no {ACTION} was applied.")
    else:
        # Deal with the account first so it stops posting while we clean up.
        if verdict.newly_flagged:
            receipt = settings.claim_action(guild.id, time.time())
            if receipt is None:
                headline = (
                    f"{member.mention} was caught {FLAVOR}, but NOT {ACTION_VERB[ACTION]}: "
                    "the daily limit is used up"
                )
                problems.append(
                    f"Already acted on {DAILY_LIMIT} account(s) in the last 24 hours, so no "
                    f"{ACTION} this time. Deal with this account by hand."
                )
                log.warning("Daily limit of %d reached in %s", DAILY_LIMIT, guild.name)
            else:
                done, note = await punish(member)
                (notes if done == ACTION_VERB[ACTION] else problems).append(note)
                if done:
                    headline = f"{member.mention} was {done} for {FLAVOR}"
                else:
                    settings.release_action(guild.id, receipt)
                    headline = f"{member.mention} was caught {FLAVOR}, but the {ACTION} failed"

        # A softban has Discord purge these too, so "already gone" counts as removed.
        removed = 0
        for hit in verdict.hits:
            channel = guild.get_channel_or_thread(hit.channel_id)
            if channel is None:
                continue
            try:
                await channel.get_partial_message(hit.message_id).delete()
                removed += 1
            except discord.NotFound:
                removed += 1
            except discord.HTTPException as exc:
                problems.append(f"Could not delete in <#{hit.channel_id}>: {exc.text or exc}")
        notes.append(f"Removed {removed} of {len(verdict.hits)} message(s).")

    log.info(
        "Caught %s (%d) in %s: %s", member, member.id, guild.name, " ".join(problems + notes)
    )
    if verdict.newly_flagged:
        await report(guild, member, headline, problems)


async def report(
    guild: discord.Guild, member: discord.Member, headline: str, problems: list[str]
) -> None:
    """Post the catch in the server's report channel.

    The report is just the headline, who it was, and the footer. A "Needs
    attention" section is added only when something went wrong.
    """
    channel_id = settings.log_channel_id(guild.id)
    if channel_id is None:
        return
    channel = guild.get_channel_or_thread(channel_id)
    if channel is None:
        log.warning("Report channel %d is not a channel in %s", channel_id, guild.name)
        return

    embed = discord.Embed(
        description=f"**{headline}**\n`{member}`, ID `{member.id}`",
        colour=discord.Colour.red(),
    )
    if problems:
        embed.add_field(name="Needs attention", value="\n".join(problems)[:1000], inline=False)
    if ACTION == "timeout":
        footer = "The account is probably hijacked. Lift the timeout once its owner has it back."
    else:
        footer = "The account is probably hijacked. Its owner can rejoin with an invite once they have it back."
    embed.set_footer(text=footer)
    try:
        await channel.send(embed=embed)
    except discord.HTTPException as exc:
        log.warning("Could not post the report: %s", exc)


def _cipher(passphrase: str, salt: bytes, n: int):
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise SystemExit(
            "The passphrase option needs the 'cryptography' package. "
            "Run the pip install -r requirements.txt step again."
        ) from None
    key = Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_token(token: str, passphrase: str, n: int = SCRYPT_N) -> dict:
    """Lock the token with a key derived from the passphrase."""
    salt = os.urandom(16)
    return {
        "kdf": "scrypt",
        "n": n,
        "salt": base64.b64encode(salt).decode(),
        "token": _cipher(passphrase, salt, n).encrypt(token.encode()).decode(),
    }


def decrypt_token(saved: dict, passphrase: str) -> str:
    """Return the token, or raise ValueError if the passphrase is wrong."""
    from cryptography.fernet import InvalidToken

    n = int(saved["n"])
    if saved.get("kdf") != "scrypt" or not 2**14 <= n <= 2**20:
        raise SystemExit(f"{TOKEN_FILE} is not in a format this version understands.")
    try:
        cipher = _cipher(passphrase, base64.b64decode(saved["salt"]), n)
        return cipher.decrypt(saved["token"].encode()).decode()
    except InvalidToken:
        raise ValueError("wrong passphrase") from None


def ask_secret(prompt: str) -> str:
    """Read a secret from the keyboard, hidden where the terminal allows it."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    # Some terminals (Git Bash on Windows, for one) can't hide typing.
    print(f"{prompt}[this terminal can't hide typing, so it will be visible] ", end="", flush=True)
    return sys.stdin.readline().rstrip("\r\n")


def save_encrypted_token() -> None:
    token = ask_secret("Bot token: ").strip()
    if not token:
        raise SystemExit("No token entered; nothing was saved.")
    passphrase = ask_secret(f"Choose a passphrase ({MIN_PASSPHRASE}+ characters): ")
    if len(passphrase) < MIN_PASSPHRASE:
        raise SystemExit("That passphrase is too short; nothing was saved.")
    if ask_secret("Type it again: ") != passphrase:
        raise SystemExit("The passphrases did not match; nothing was saved.")
    TOKEN_FILE.write_text(json.dumps(encrypt_token(token, passphrase), indent=2) + "\n")
    print(
        f"Saved to {TOKEN_FILE}. Now remove DISCORD_TOKEN from your .env file and anywhere "
        "else it is written down. The bot will ask for the passphrase each time it starts."
    )


def load_token() -> str:
    """The token from DISCORD_TOKEN, or from TOKEN_FILE after asking for the passphrase."""
    token = os.environ.get("DISCORD_TOKEN")
    if token:
        if TOKEN_FILE.exists():
            print(
                f"Note: DISCORD_TOKEN is set, so {TOKEN_FILE} and its passphrase are not being "
                "used. Remove DISCORD_TOKEN to rely on the passphrase.",
                file=sys.stderr,
            )
        return token
    if not TOKEN_FILE.exists():
        raise SystemExit(
            "No token found. Set DISCORD_TOKEN, or run this with --encrypt-token to store "
            "the token behind a passphrase."
        )
    try:
        saved = json.loads(TOKEN_FILE.read_text())
        for attempt in range(3):
            try:
                return decrypt_token(saved, ask_secret("Passphrase: "))
            except ValueError:
                print("Wrong passphrase.", file=sys.stderr)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{TOKEN_FILE} is damaged ({exc!r}). Run --encrypt-token again.") from exc
    raise SystemExit("Too many wrong passphrases.")


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--encrypt-token"]:
        save_encrypted_token()
        return
    if args:
        raise SystemExit("Usage: python bot.py [--encrypt-token]")
    client.run(load_token(), log_level=logging.INFO, root_logger=True)


if __name__ == "__main__":
    main()
