import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import discord

import bot
from bot import SpamTracker


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.t = SpamTracker(threshold=3, window=30, flag_seconds=300)

    def test_three_channels_in_window_triggers(self):
        self.assertIsNone(self.t.record(1, 7, 100, 1, now=0))
        self.assertIsNone(self.t.record(1, 7, 101, 2, now=2))
        verdict = self.t.record(1, 7, 102, 3, now=4)
        self.assertTrue(verdict.newly_flagged)
        self.assertEqual([h.message_id for h in verdict.hits], [1, 2, 3])

    def test_many_posts_in_one_channel_do_not_trigger(self):
        for i in range(10):
            self.assertIsNone(self.t.record(1, 7, 100, i, now=i))

    def test_slow_posting_does_not_trigger(self):
        self.assertIsNone(self.t.record(1, 7, 100, 1, now=0))
        self.assertIsNone(self.t.record(1, 7, 101, 2, now=20))
        self.assertIsNone(self.t.record(1, 7, 102, 3, now=40))

    def test_users_and_servers_are_separate(self):
        self.assertIsNone(self.t.record(1, 7, 100, 1, now=0))
        self.assertIsNone(self.t.record(1, 8, 101, 2, now=1))
        self.assertIsNone(self.t.record(2, 7, 102, 3, now=2))
        self.assertIsNone(self.t.record(1, 7, 101, 4, now=3))

    def test_later_posts_are_removed_while_flagged_then_reset(self):
        for i, ch in enumerate((100, 101, 102)):
            self.t.record(1, 7, ch, i, now=i)
        follow_up = self.t.record(1, 7, 103, 9, now=10)
        self.assertFalse(follow_up.newly_flagged)
        self.assertEqual([h.message_id for h in follow_up.hits], [9])
        self.assertIsNone(self.t.record(1, 7, 100, 10, now=400))

    def test_sweep_drops_stale_entries(self):
        self.t.record(1, 7, 100, 1, now=0)
        self.t._sweep(now=1000)
        self.assertEqual(self.t._hits, {})


def fake_message(member, guild, channel_id, message_id, attachments=1, content=""):
    return SimpleNamespace(
        id=message_id,
        guild=guild,
        author=member,
        webhook_id=None,
        channel=SimpleNamespace(id=channel_id),
        attachments=[SimpleNamespace(filename="win.png")] * attachments,
        content=content,
        message_snapshots=[],
    )


class HandlerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.channels = {}

        def get_channel(cid):
            if cid not in self.channels:
                ch = MagicMock()
                ch.get_partial_message.return_value.delete = AsyncMock()
                ch.send = AsyncMock()
                self.channels[cid] = ch
            return self.channels[cid]

        self.guild = MagicMock()
        self.guild.id = 1
        self.guild.name = "Test"
        self.guild.get_channel_or_thread.side_effect = get_channel

        self.member = MagicMock(spec=discord.Member)
        self.member.id = 7
        self.member.bot = False
        self.member.roles = []
        self.member.guild_permissions = discord.Permissions.none()
        self.member.timeout = AsyncMock()
        self.member.ban = AsyncMock()
        self.member.unban = AsyncMock()

        patcher = patch.multiple(
            bot, tracker=SpamTracker(3, 30), LOG_CHANNEL_ID=999, DRY_RUN=False, ACTION="timeout"
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    async def post(self, channel_id, message_id, **kw):
        await bot.on_message(fake_message(self.member, self.guild, channel_id, message_id, **kw))

    async def test_spam_is_timed_out_deleted_and_reported(self):
        await self.post(100, 1)
        await self.post(101, 2)
        self.member.timeout.assert_not_awaited()
        await self.post(102, 3)

        self.member.timeout.assert_awaited_once()
        for cid, mid in ((100, 1), (101, 2), (102, 3)):
            self.channels[cid].get_partial_message.assert_called_with(mid)
            self.channels[cid].get_partial_message.return_value.delete.assert_awaited_once()
        self.channels[999].send.assert_awaited_once()

        # A straggler is deleted without a second timeout or report.
        await self.post(103, 4)
        self.member.timeout.assert_awaited_once()
        self.channels[103].get_partial_message.return_value.delete.assert_awaited_once()
        self.channels[999].send.assert_awaited_once()

    async def spam(self):
        for i, cid in enumerate((100, 101, 102)):
            await self.post(cid, i)

    def report_result(self):
        return self.channels[999].send.await_args.kwargs["embed"].fields[-1].value

    async def test_softban_bans_purges_and_unbans(self):
        with patch.multiple(bot, ACTION="softban", PURGE_MINUTES=10):
            await self.spam()
        self.member.ban.assert_awaited_once()
        self.assertEqual(self.member.ban.await_args.kwargs["delete_message_seconds"], 600)
        self.member.unban.assert_awaited_once()
        self.member.timeout.assert_not_awaited()
        self.assertIn("Softbanned", self.report_result())

    async def test_softban_counts_purged_messages_as_removed(self):
        gone = discord.NotFound(MagicMock(status=404, reason="Not Found"), "Unknown Message")
        for cid in (100, 101, 102):
            self.guild.get_channel_or_thread(cid).get_partial_message.return_value.delete.side_effect = gone
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        self.assertIn("Removed 3 of 3", self.report_result())

    async def test_softban_reports_a_ban_it_could_not_lift(self):
        response = MagicMock(status=500, reason="Server Error")
        self.member.unban.side_effect = discord.HTTPException(response, "boom")
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        self.assertIn("unban them by hand", self.report_result())

    async def test_failed_softban_still_deletes(self):
        response = MagicMock(status=403, reason="Forbidden")
        self.member.ban.side_effect = discord.Forbidden(response, "Missing Permissions")
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        self.member.unban.assert_not_awaited()
        self.channels[100].get_partial_message.return_value.delete.assert_awaited_once()
        self.assertIn("Could not softban", self.report_result())

    async def test_dry_run_does_not_softban(self):
        with patch.multiple(bot, ACTION="softban", DRY_RUN=True):
            await self.spam()
        self.member.ban.assert_not_awaited()

    async def test_plain_text_is_ignored(self):
        for i, cid in enumerate((100, 101, 102, 103)):
            await self.post(cid, i, attachments=0, content="hello")
        self.member.timeout.assert_not_awaited()

    async def test_links_count(self):
        for i, cid in enumerate((100, 101, 102)):
            await self.post(cid, i, attachments=0, content="free money https://example.com/x")
        self.member.timeout.assert_awaited_once()

    async def test_moderators_are_exempt(self):
        self.member.guild_permissions = discord.Permissions(manage_messages=True)
        for i, cid in enumerate((100, 101, 102)):
            await self.post(cid, i)
        self.member.timeout.assert_not_awaited()

    async def test_dry_run_only_reports(self):
        with patch.object(bot, "DRY_RUN", True):
            for i, cid in enumerate((100, 101, 102)):
                await self.post(cid, i)
        self.member.timeout.assert_not_awaited()
        self.assertNotIn(100, self.channels)
        self.channels[999].send.assert_awaited_once()

    async def test_failed_timeout_still_deletes(self):
        response = MagicMock(status=403, reason="Forbidden")
        self.member.timeout.side_effect = discord.Forbidden(response, "Missing Permissions")
        for i, cid in enumerate((100, 101, 102)):
            await self.post(cid, i)
        self.channels[100].get_partial_message.return_value.delete.assert_awaited_once()
        report = self.channels[999].send.await_args.kwargs["embed"]
        self.assertIn("Could not time out", report.fields[-1].value)


if __name__ == "__main__":
    unittest.main()
