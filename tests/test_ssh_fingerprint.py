"""The SSH client fingerprint (HASSH) is captured for a client that logs in, not only for one
that hangs up mid-handshake. paramiko frees the client's KEXINIT once keys are exchanged, so
until 2026-10-03 only about one SSH host in eight had a fingerprint."""
import asyncio
import os
import re
import socket
import tempfile
import unittest

import paramiko

from uninvited.ssh_pot import SshPot


class FingerprintTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_login_attempt_carries_the_client_fingerprint(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        knocks: asyncio.Queue = asyncio.Queue()
        pot = SshPot("127.0.0.1", port, os.path.join(tempfile.mkdtemp(), "host_key"),
                     "SSH-2.0-OpenSSH_8.9p1", knocks.put, asyncio.get_running_loop())
        pot.start()
        try:
            def login():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect("127.0.0.1", port=port, username="root", password="hunter2",
                                   allow_agent=False, look_for_keys=False, timeout=10)
                except paramiko.AuthenticationException:
                    pass
                finally:
                    client.close()

            await asyncio.get_running_loop().run_in_executor(None, login)
            knock = await asyncio.wait_for(knocks.get(), 10)
            while knock.username != "root":                      # skip a scan record, if one came first
                knock = await asyncio.wait_for(knocks.get(), 10)
            self.assertEqual((knock.username, knock.password), ("root", "hunter2"))
            self.assertIsNotNone(knock.hassh, "the fingerprint was lost after the key exchange")
            self.assertTrue(re.fullmatch(r"[0-9a-f]{32}", knock.hassh))
        finally:
            pot.stop()


if __name__ == "__main__":
    unittest.main()
