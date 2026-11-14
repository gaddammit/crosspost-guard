"""Crosspost guard: catches one account posting attachments or links in several
channels within a short window (the usual pattern of a hijacked account posting
scam screenshots), times the account out, deletes the posts and tells the mods.

Configuration is by environment variable; see README.md.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta

import discord

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
# Timeout length. Discord's maximum is 28 days.
TIMEOUT_HOURS = float(os.environ.get("TIMEOUT_HOURS", "24"))
# Count messages that contain a link as well as ones with attachments.
COUNT_LINKS = _flag("COUNT_LINKS", True)
# Report only: no timeout, no deletions.
DRY_RUN = _flag("DRY_RUN", False)
# Channel that receives a report for each catch (optional).
LOG_CHANNEL_ID = int(os.environ.get("LOG_CHANNEL_ID", "0")) or None
# Roles that are never checked. Members with Manage Messages are always skipped.
EXEMPT_ROLE_IDS = _ids("EXEMPT_ROLE_IDS")
# After a catch, keep deleting that account's matching posts for this long, in
# case the timeout failed or messages were already in flight.
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
        self._hits: dict[tuple[int, int], deque[Hit]] = {}
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

        hits = self._hits.setdefault(key, deque())
        hits.append(hit)
        while hits and now - hits[0].at > self.window:
            hits.popleft()

        if len({h.channel_id for h in hits}) < self.threshold:
            return None

        del self._hits[key]
        self._flagged[key] = now + self.flag_seconds
        return Verdict(list(hits), newly_flagged=True)

    def _sweep(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or now - v[-1].at > self.window]:
            del self._hits[key]
        for key in [k for k, until in self._flagged.items() if now >= until]:
            del self._flagged[key]


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
tracker = SpamTracker(CHANNEL_THRESHOLD, WINDOW_SECONDS)


@client.event
async def on_ready() -> None:
    log.info(
        "Logged in as %s. Watching %d server(s): %d channels in %gs%s",
        client.user,
        len(client.guilds),
        CHANNEL_THRESHOLD,
        WINDOW_SECONDS,
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

    verdict = tracker.record(
        message.guild.id, member.id, message.channel.id, message.id, time.monotonic()
    )
    if verdict is not None:
        await act(message, member, verdict)


async def act(message: discord.Message, member: discord.Member, verdict: Verdict) -> None:
    guild = message.guild
    notes: list[str] = []

    if DRY_RUN:
        notes.append("Dry run: nothing was removed and nobody was timed out.")
    else:
        # Time out first so the account stops posting while we clean up.
        if verdict.newly_flagged:
            try:
                await member.timeout(
                    timedelta(hours=TIMEOUT_HOURS),
                    reason=f"Posted in {CHANNEL_THRESHOLD}+ channels within {WINDOW_SECONDS:g}s",
                )
                notes.append(f"Timed out for {TIMEOUT_HOURS:g}h.")
            except discord.HTTPException as exc:
                notes.append(f"Could not time out: {exc.text or exc}")

        deleted = 0
        for hit in verdict.hits:
            channel = guild.get_channel_or_thread(hit.channel_id)
            if channel is None:
                continue
            try:
                await channel.get_partial_message(hit.message_id).delete()
                deleted += 1
            except discord.NotFound:
                pass  # already gone
            except discord.HTTPException as exc:
                notes.append(f"Could not delete in <#{hit.channel_id}>: {exc.text or exc}")
        notes.append(f"Deleted {deleted} of {len(verdict.hits)} message(s).")

    log.info("Caught %s (%d) in %s: %s", member, member.id, guild.name, " ".join(notes))
    if verdict.newly_flagged:
        await report(message, member, verdict, notes)


async def report(
    message: discord.Message, member: discord.Member, verdict: Verdict, notes: list[str]
) -> None:
    if LOG_CHANNEL_ID is None:
        return
    channel = message.guild.get_channel_or_thread(LOG_CHANNEL_ID)
    if channel is None:
        log.warning("LOG_CHANNEL_ID %d is not a channel in %s", LOG_CHANNEL_ID, message.guild.name)
        return

    channels = sorted({h.channel_id for h in verdict.hits})
    names = [a.filename for a in message.attachments]
    embed = discord.Embed(
        title="Cross-channel spam caught",
        description=f"{member.mention} (`{member}`, ID `{member.id}`)",
        colour=discord.Colour.red(),
    )
    embed.add_field(name="Channels", value=" ".join(f"<#{c}>" for c in channels), inline=False)
    if message.content:
        embed.add_field(name="Text", value=message.content[:500], inline=False)
    if names:
        embed.add_field(name="Attachments", value=", ".join(names)[:500], inline=False)
    embed.add_field(name="Result", value="\n".join(notes)[:1000], inline=False)
    embed.set_footer(text="The account is probably hijacked. Lift the timeout once its owner has it back.")
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
