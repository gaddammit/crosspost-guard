"""Crosspost guard: catches one account posting attachments or links in several
channels within a short window (the usual pattern of a hijacked account posting
scam screenshots), softbans the account, deletes the posts and tells the mods.

Configuration is by environment variable; see README.md.
"""

from __future__ import annotations

import json
import logging
import os
import re
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
        await tree.sync()
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
    notes: list[str] = []
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
                notes.append(
                    f"Already acted on {DAILY_LIMIT} account(s) in the last 24 hours, so no "
                    f"{ACTION} this time. Deal with this account by hand."
                )
                log.warning("Daily limit of %d reached in %s", DAILY_LIMIT, guild.name)
            else:
                done, note = await punish(member)
                notes.append(note)
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
                notes.append(f"Could not delete in <#{hit.channel_id}>: {exc.text or exc}")
        notes.append(f"Removed {removed} of {len(verdict.hits)} message(s).")

    log.info("Caught %s (%d) in %s: %s", member, member.id, guild.name, " ".join(notes))
    if verdict.newly_flagged:
        await report(message, member, verdict, notes, headline)


async def report(
    message: discord.Message,
    member: discord.Member,
    verdict: Verdict,
    notes: list[str],
    headline: str,
) -> None:
    channel_id = settings.log_channel_id(message.guild.id)
    if channel_id is None:
        return
    channel = message.guild.get_channel_or_thread(channel_id)
    if channel is None:
        log.warning("Report channel %d is not a channel in %s", channel_id, message.guild.name)
        return

    channels = sorted({h.channel_id for h in verdict.hits})
    names = [a.filename for a in message.attachments]
    embed = discord.Embed(
        title="Cross-channel spam caught",
        description=f"**{headline}**\n`{member}`, ID `{member.id}`",
        colour=discord.Colour.red(),
    )
    embed.add_field(name="Channels", value=" ".join(f"<#{c}>" for c in channels), inline=False)
    if message.content:
        embed.add_field(name="Text", value=message.content[:500], inline=False)
    if names:
        embed.add_field(name="Attachments", value=", ".join(names)[:500], inline=False)
    embed.add_field(name="Result", value="\n".join(notes)[:1000], inline=False)
    if ACTION == "timeout":
        footer = "The account is probably hijacked. Lift the timeout once its owner has it back."
    else:
        footer = "The account is probably hijacked. Its owner can rejoin with an invite once they have it back."
    embed.set_footer(text=footer)
    try:
        await channel.send(embed=embed)
    except discord.HTTPException as exc:
        log.warning("Could not post the report: %s", exc)


def main() -> None:
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise SystemExit("Set DISCORD_TOKEN to your bot token first.")
    client.run(token, log_level=logging.INFO, root_logger=True)


if __name__ == "__main__":
    main()
