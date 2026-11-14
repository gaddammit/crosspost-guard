import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import discord

import bot
from bot import Settings, SpamTracker


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

    def test_out_of_order_arrival_goes_by_post_time(self):
        self.assertIsNone(self.t.record(1, 7, 100, 1, now=100))
        self.assertIsNone(self.t.record(1, 7, 101, 2, now=10))  # old message arriving late
        self.assertIsNone(self.t.record(1, 7, 102, 3, now=105))
        verdict = self.t.record(1, 7, 103, 4, now=110)
        self.assertEqual([h.message_id for h in verdict.hits], [1, 3, 4])

    def test_sweep_drops_stale_entries(self):
        self.t.record(1, 7, 100, 1, now=0)
        self.t._sweep(now=1000)
        self.assertEqual(self.t._hits, {})


START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def fake_message(member, guild, channel_id, message_id, attachments=1, content="", age=0):
    return SimpleNamespace(
        id=message_id,
        created_at=START + timedelta(seconds=age),
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

        self.member = self.make_member(7)

        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.settings = Settings(Path(folder.name) / "settings.json")

        patcher = patch.multiple(
            bot,
            tracker=SpamTracker(3, 30),
            settings=self.settings,
            LOG_CHANNEL_ID=999,
            DRY_RUN=False,
            ACTION="timeout",
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_member(self, user_id):
        member = MagicMock(spec=discord.Member)
        member.id = user_id
        member.mention = f"<@{user_id}>"
        member.bot = False
        member.roles = []
        member.guild_permissions = discord.Permissions.none()
        member.timeout = AsyncMock()
        member.ban = AsyncMock()
        member.unban = AsyncMock()
        return member

    async def post(self, channel_id, message_id, member=None, **kw):
        member = member or self.member
        await bot.on_message(fake_message(member, self.guild, channel_id, message_id, **kw))

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

    async def spam(self, member=None):
        for i, cid in enumerate((100, 101, 102)):
            await self.post(cid, i, member=member)

    async def test_fourth_account_in_a_day_is_not_softbanned(self):
        members = [self.make_member(n) for n in (11, 12, 13, 14)]
        with patch.multiple(bot, ACTION="softban", DAILY_LIMIT=3):
            for member in members:
                await self.spam(member)
        for member in members[:3]:
            member.ban.assert_awaited_once()
        members[3].ban.assert_not_awaited()
        members[3].timeout.assert_not_awaited()

        embed = self.channels[999].send.await_args.kwargs["embed"]
        self.assertEqual(
            embed.description.splitlines()[0],
            "**<@14> was caught Mr. Beast-ing, but NOT softbanned: the daily limit is used up**",
        )
        self.assertIn("Deal with this account by hand", embed.fields[-1].value)
        # Its posts are still removed: 4 accounts, one delete each in this channel.
        self.assertEqual(self.channels[100].get_partial_message.return_value.delete.await_count, 4)

    async def test_limit_applies_to_timeouts_too(self):
        first, second = self.make_member(11), self.make_member(12)
        with patch.object(bot, "DAILY_LIMIT", 1):
            await self.spam(first)
            await self.spam(second)
        first.timeout.assert_awaited_once()
        second.timeout.assert_not_awaited()

    async def test_failed_softban_does_not_use_up_the_limit(self):
        failing, second = self.make_member(11), self.make_member(12)
        response = MagicMock(status=403, reason="Forbidden")
        failing.ban.side_effect = discord.Forbidden(response, "Missing Permissions")
        with patch.multiple(bot, ACTION="softban", DAILY_LIMIT=1):
            await self.spam(failing)
            await self.spam(second)
        second.ban.assert_awaited_once()

    async def test_dry_run_does_not_use_up_the_limit(self):
        first, second = self.make_member(11), self.make_member(12)
        with patch.multiple(bot, ACTION="softban", DAILY_LIMIT=1, DRY_RUN=True):
            await self.spam(first)
        with patch.multiple(bot, ACTION="softban", DAILY_LIMIT=1):
            await self.spam(second)
        second.ban.assert_awaited_once()

    async def test_zero_means_no_limit(self):
        members = [self.make_member(n) for n in range(11, 17)]
        with patch.multiple(bot, ACTION="softban", DAILY_LIMIT=0):
            for member in members:
                await self.spam(member)
        for member in members:
            member.ban.assert_awaited_once()

    def report_result(self):
        return self.channels[999].send.await_args.kwargs["embed"].fields[-1].value

    async def test_report_goes_to_the_channel_chosen_with_modlog(self):
        self.settings.set_log_channel(self.guild.id, 555)
        await self.spam()
        self.channels[555].send.assert_awaited_once()
        self.assertNotIn(999, self.channels)

    async def test_replayed_backlog_is_judged_by_post_time(self):
        # Three posts a minute apart, delivered back to back after a reconnect.
        for i, cid in enumerate((100, 101, 102)):
            await self.post(cid, i, age=60 * i)
        self.member.ban.assert_not_awaited()
        self.member.timeout.assert_not_awaited()

    def headline(self):
        return self.channels[999].send.await_args.kwargs["embed"].description.splitlines()[0]

    async def test_headline_says_what_happened(self):
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        self.assertEqual(self.headline(), "**<@7> was softbanned for Mr. Beast-ing**")

    async def test_headline_for_timeout_and_custom_flavor(self):
        with patch.object(bot, "FLAVOR", "spamming"):
            await self.spam()
        self.assertEqual(self.headline(), "**<@7> was timed out for spamming**")

    async def test_headline_for_dry_run(self):
        with patch.multiple(bot, ACTION="softban", DRY_RUN=True):
            await self.spam()
        self.assertEqual(self.headline(), "**<@7> would have been softbanned for Mr. Beast-ing**")

    async def test_headline_when_the_softban_fails(self):
        response = MagicMock(status=403, reason="Forbidden")
        self.member.ban.side_effect = discord.Forbidden(response, "Missing Permissions")
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        self.assertEqual(
            self.headline(), "**<@7> was caught Mr. Beast-ing, but the softban failed**"
        )

    async def test_headline_when_the_ban_could_not_be_lifted(self):
        response = MagicMock(status=500, reason="Server Error")
        self.member.unban.side_effect = discord.HTTPException(response, "boom")
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        self.assertEqual(self.headline(), "**<@7> was banned for Mr. Beast-ing**")

    async def test_softban_bans_purges_and_unbans(self):
        with patch.multiple(bot, ACTION="softban", PURGE_MINUTES=10):
            await self.spam()
        self.member.ban.assert_awaited_once()
        self.assertEqual(self.member.ban.await_args.kwargs["delete_message_seconds"], 600)
        self.member.unban.assert_awaited_once()
        self.member.timeout.assert_not_awaited()
        # A clean catch reports only the headline, the account and the footer.
        embed = self.channels[999].send.await_args.kwargs["embed"]
        self.assertIsNone(embed.title)
        self.assertEqual(embed.fields, [])
        self.assertEqual(
            embed.description, "**<@7> was softbanned for Mr. Beast-ing**\n`" + str(self.member) + "`, ID `7`"
        )
        self.assertIn("probably hijacked", embed.footer.text)

    async def test_softban_counts_purged_messages_as_removed(self):
        gone = discord.NotFound(MagicMock(status=404, reason="Not Found"), "Unknown Message")
        for cid in (100, 101, 102):
            self.guild.get_channel_or_thread(cid).get_partial_message.return_value.delete.side_effect = gone
        with patch.object(bot, "ACTION", "softban"), self.assertLogs("crosspost-guard") as logs:
            await self.spam()
        self.assertIn("Removed 3 of 3", logs.output[-1])

    async def test_failed_delete_is_reported(self):
        response = MagicMock(status=403, reason="Forbidden")
        self.guild.get_channel_or_thread(101).get_partial_message.return_value.delete.side_effect = (
            discord.Forbidden(response, "Missing Permissions")
        )
        with patch.object(bot, "ACTION", "softban"):
            await self.spam()
        embed = self.channels[999].send.await_args.kwargs["embed"]
        self.assertEqual(embed.fields[-1].name, "Needs attention")
        self.assertIn("Could not delete in <#101>", embed.fields[-1].value)

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


class SettingsTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "settings.json"

    def test_choice_survives_a_restart(self):
        Settings(self.path).set_log_channel(1, 555)
        self.assertEqual(Settings(self.path).log_channel_id(1), 555)

    def test_other_servers_fall_back_to_the_environment_setting(self):
        settings = Settings(self.path)
        settings.set_log_channel(1, 555)
        with patch.object(bot, "LOG_CHANNEL_ID", 999):
            self.assertEqual(settings.log_channel_id(2), 999)
        with patch.object(bot, "LOG_CHANNEL_ID", None):
            self.assertIsNone(settings.log_channel_id(2))

    def test_limit_is_per_server_and_rolls_over_after_24_hours(self):
        settings = Settings(self.path)
        with patch.object(bot, "DAILY_LIMIT", 2):
            self.assertIsNotNone(settings.claim_action(1, now=0))
            self.assertIsNotNone(settings.claim_action(1, now=3600))
            self.assertIsNone(settings.claim_action(1, now=7200))
            self.assertIsNotNone(settings.claim_action(2, now=7200))  # another server
            self.assertIsNone(settings.claim_action(1, now=86399))
            self.assertIsNotNone(settings.claim_action(1, now=86401))  # first one aged out

    def test_limit_survives_a_restart(self):
        with patch.object(bot, "DAILY_LIMIT", 1):
            self.assertIsNotNone(Settings(self.path).claim_action(1, now=0))
            self.assertIsNone(Settings(self.path).claim_action(1, now=60))

    def test_released_slot_can_be_claimed_again(self):
        settings = Settings(self.path)
        with patch.object(bot, "DAILY_LIMIT", 1):
            receipt = settings.claim_action(1, now=0)
            settings.release_action(1, receipt)
            self.assertIsNotNone(settings.claim_action(1, now=60))

    def test_file_from_before_the_limit_existed_still_loads(self):
        self.path.write_text('{"log_channels": {"1": 555}}')
        settings = Settings(self.path)
        self.assertEqual(settings.log_channel_id(1), 555)
        self.assertIsNotNone(settings.claim_action(1, now=0))

    def test_damaged_file_stops_startup(self):
        self.path.write_text("{not json")
        with self.assertRaises(SystemExit):
            Settings(self.path)


class ModlogCommandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.settings = Settings(Path(folder.name) / "settings.json")
        patcher = patch.multiple(bot, settings=self.settings, LOG_CHANNEL_ID=None)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.interaction = MagicMock()
        self.interaction.guild.id = 1
        self.interaction.user.mention = "<@42>"
        self.interaction.response.send_message = AsyncMock()

        self.channel = MagicMock()
        self.channel.id = 555
        self.channel.mention = "<#555>"
        self.channel.send = AsyncMock()
        self.channel.permissions_for.return_value = discord.Permissions(
            view_channel=True, send_messages=True, embed_links=True
        )

    async def run_command(self, channel=None):
        await bot.modlog.callback(self.interaction, channel)
        return self.interaction.response.send_message.await_args

    async def test_setting_a_channel_posts_there_and_saves_it(self):
        reply = await self.run_command(self.channel)
        self.channel.send.assert_awaited_once()
        self.assertEqual(self.settings.log_channel_id(1), 555)
        self.assertIn("Reports will now go to <#555>", reply.args[0])
        self.assertTrue(reply.kwargs["ephemeral"])

    async def test_missing_permission_changes_nothing(self):
        self.channel.permissions_for.return_value = discord.Permissions(
            view_channel=True, send_messages=True
        )
        reply = await self.run_command(self.channel)
        self.channel.send.assert_not_awaited()
        self.assertIsNone(self.settings.log_channel_id(1))
        self.assertIn("missing Embed Links", reply.args[0])

    async def test_refused_test_message_changes_nothing(self):
        response = MagicMock(status=403, reason="Forbidden")
        self.channel.send.side_effect = discord.Forbidden(response, "Missing Access")
        reply = await self.run_command(self.channel)
        self.assertIsNone(self.settings.log_channel_id(1))
        self.assertIn("Nothing was changed", reply.args[0])

    async def test_no_argument_shows_the_current_channel(self):
        reply = await self.run_command()
        self.assertIn("No report channel is set", reply.args[0])
        self.settings.set_log_channel(1, 555)
        reply = await self.run_command()
        self.assertIn("Reports go to <#555>", reply.args[0])

    def test_command_is_limited_to_manage_server_and_servers(self):
        self.assertTrue(bot.modlog.default_permissions.manage_guild)
        self.assertTrue(bot.modlog.guild_only)


if __name__ == "__main__":
    unittest.main()
