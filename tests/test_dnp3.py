"""The DNP3 decoy. No independent DNP3 client is available, so these tests check the CRC against
the published value and check framing both ways; the application layer is documented as experimental."""
import asyncio
import random
import unittest

from uninvited import dnp3
from uninvited.listeners import Dnp3Listener

MASTER, OUTSTATION = 1024, 10


def request(function, user=b"", dest=OUTSTATION, src=MASTER):
    control = 0xC0 | function                      # from a master, primary
    return dnp3.build(control, dest, src, user)


def parse_frames(raw):
    """Every frame in a byte string, each as (header fields, user data)."""
    out, i = [], 0
    while i < len(raw):
        head = dnp3.parse_header(raw[i:i + 10])
        assert head is not None, raw[i:i + 12].hex()
        n = dnp3.data_bytes_on_wire(head["length"])
        data = dnp3.user_data(raw[i + 10:i + 10 + n], head["length"])
        assert data is not None
        out.append((head, data))
        i += 10 + n
    return out


class CrcTests(unittest.TestCase):
    def test_the_published_check_value(self):
        self.assertEqual(dnp3.crc(b"123456789"), 0xEA82)      # CRC-16/DNP in every CRC catalogue

    def test_empty_and_single_byte(self):
        self.assertEqual(dnp3.crc(b""), 0xFFFF)
        self.assertNotEqual(dnp3.crc(b"\x00"), dnp3.crc(b"\x01"))

    def test_any_single_bit_flip_changes_the_crc(self):
        data = bytes(range(16))
        base = dnp3.crc(data)
        for i in range(16):
            for bit in range(8):
                flipped = bytearray(data)
                flipped[i] ^= 1 << bit
                self.assertNotEqual(dnp3.crc(bytes(flipped)), base)


class FramingTests(unittest.TestCase):
    def test_a_header_only_frame_is_ten_bytes_with_a_valid_crc(self):
        frame = request(9)
        self.assertEqual(len(frame), 10)
        self.assertEqual(frame[:2], b"\x05\x64")
        self.assertEqual(frame[2], 5)
        head = dnp3.parse_header(frame)
        self.assertEqual((head["function"], head["dest"], head["src"], head["dir"], head["prm"]),
                         (9, OUTSTATION, MASTER, True, True))

    def test_user_data_is_split_into_16_byte_blocks_each_with_a_crc(self):
        for n in (1, 15, 16, 17, 32, 33, 100, 250):
            data = bytes(i % 251 for i in range(n))
            frame = dnp3.build(0xC4, 1, 2, data)
            self.assertEqual(len(frame), 10 + dnp3.data_bytes_on_wire(n + 5), n)
            head = dnp3.parse_header(frame[:10])
            self.assertEqual(dnp3.user_data(frame[10:], head["length"]), data, n)

    def test_a_corrupt_header_or_block_is_rejected(self):
        frame = bytearray(request(4, b"\xc0\xc0\x01"))
        bad_head = bytes(frame[:3] + bytes([frame[3] ^ 0x01]) + frame[4:])
        self.assertIsNone(dnp3.parse_header(bad_head[:10]))
        head = dnp3.parse_header(bytes(frame[:10]))
        frame[12] ^= 0xFF                                   # inside the first block
        self.assertIsNone(dnp3.user_data(bytes(frame[10:]), head["length"]))

    def test_not_dnp3_is_rejected(self):
        self.assertIsNone(dnp3.parse_header(b"GET / HTTP/"))
        self.assertIsNone(dnp3.parse_header(b"\x05\x64\x03" + bytes(7)))     # length below the minimum
        self.assertIsNone(dnp3.parse_header(b"\x05\x65" + bytes(8)))


class LinkTests(unittest.TestCase):
    def ask(self, raw, address=None):
        head = dnp3.parse_header(raw[:10])
        data = dnp3.user_data(raw[10:], head["length"])
        return dnp3.handle(head, data, address)

    def test_request_link_status_gets_link_status_with_the_addresses_swapped(self):
        r = self.ask(request(9))
        (head, data), = parse_frames(r.reply)
        self.assertEqual((head["control"], head["dest"], head["src"], data), (0x0B, MASTER, OUTSTATION, b""))
        self.assertFalse(head["dir"])                       # from an outstation
        self.assertFalse(head["prm"])                       # a secondary reply
        self.assertEqual(r.info["ics"], "identity")

    def test_reset_and_test_link_are_acknowledged(self):
        for fn in (0, 2):
            (head, _), = parse_frames(self.ask(request(fn)).reply)
            self.assertEqual(head["control"], 0x00, fn)

    def test_unknown_link_functions_are_not_supported(self):
        (head, _), = parse_frames(self.ask(request(12)).reply)
        self.assertEqual(head["control"], 0x0F)

    def test_a_secondary_frame_gets_no_reply(self):
        raw = dnp3.build(0x80 | 0x0B, OUTSTATION, MASTER)
        self.assertEqual(self.ask(raw).reply, b"")

    def test_an_address_filter_ignores_other_outstations_but_not_broadcast(self):
        other = self.ask(request(9, dest=77), address=OUTSTATION)
        self.assertEqual(other.reply, b"")
        self.assertTrue(other.info["ignored"])
        for broadcast in (0xFFFD, 0xFFFF):
            r = self.ask(request(9, dest=broadcast), address=OUTSTATION)
            (head, _), = parse_frames(r.reply)
            self.assertEqual(head["src"], OUTSTATION, hex(broadcast))     # answered as ourselves


class ApplicationTests(unittest.TestCase):
    def ask(self, function, link=4, seq=3):
        transport = 0xC0
        app = bytes([transport, 0xC0 | seq, function])
        raw = request(link, app)
        head = dnp3.parse_header(raw[:10])
        return dnp3.handle(head, dnp3.user_data(raw[10:], head["length"]))

    def test_each_application_function_is_labelled(self):
        expect = {0x01: ("read", False), 0x02: ("write", True), 0x03: ("control", True), 0x04: ("control", True),
                  0x05: ("control", True), 0x0D: ("control", True), 0x0E: ("control", True),
                  0x12: ("control", True), 0x19: ("program", True), 0x1B: ("program", True), 0x17: ("read", False)}
        for function, (label, write) in expect.items():
            info = self.ask(function).info
            self.assertEqual((info["ics"], info["write"]), (label, write), hex(function))
            self.assertEqual(info["fc"], function)

    def test_unconfirmed_data_gets_one_empty_successful_response(self):
        r = self.ask(0x01, link=4, seq=3)
        frames = parse_frames(r.reply)
        self.assertEqual(len(frames), 1)
        head, data = frames[0]
        self.assertEqual((head["control"], head["dest"], head["src"]), (0x44, MASTER, OUTSTATION))
        self.assertEqual(data, bytes([0xC0, 0xC3, 0x81, 0, 0]))   # sequence number echoed, function 0x81, IIN clear

    def test_confirmed_data_is_acknowledged_then_answered(self):
        frames = parse_frames(self.ask(0x01, link=3).reply)
        self.assertEqual([h["control"] for h, _ in frames], [0x00, 0x44])

    def test_a_confirm_gets_no_application_response(self):
        r = self.ask(0x00, link=3)
        self.assertEqual([h["control"] for h, _ in parse_frames(r.reply)], [0x00])

    def test_user_data_with_no_application_part_is_handled(self):
        raw = request(4, b"\xc0")
        head = dnp3.parse_header(raw[:10])
        r = dnp3.handle(head, dnp3.user_data(raw[10:], head["length"]))
        self.assertEqual(r.reply, b"")

    def test_unknown_functions_are_named_by_number(self):
        self.assertEqual(self.ask(0x7E).info["name"], "Function 0x7e")


class RobustnessTests(unittest.TestCase):
    def test_garbage_never_raises_and_never_answers_big(self):
        rnd = random.Random(21)
        for _ in range(4000):
            fn = rnd.randrange(16)
            data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
            raw = dnp3.build(rnd.choice([0xC0, 0x40, 0x80, 0x00]) | fn, rnd.randrange(65536), rnd.randrange(65536), data)
            head = dnp3.parse_header(raw[:10])
            payload = dnp3.user_data(raw[10:], head["length"])
            r = dnp3.handle(head, payload, rnd.choice([None, 10]))
            self.assertLess(len(r.reply), 120)


class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.l = Dnp3Listener({"port": 0}, emit, asyncio.Semaphore(10))
        self.l.server = await asyncio.start_server(self.l._wrap, "127.0.0.1", 0)
        self.port = self.l.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.l.server.close()
        await self.l.server.wait_closed()

    async def talk(self, *frames, wait=0.3):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        out = []
        for f in frames:
            w.write(f)
            await w.drain()
            try:
                out.append(await asyncio.wait_for(r.read(2000), 1.5))
            except TimeoutError:
                out.append(None)
        await asyncio.sleep(wait)
        w.close()
        await asyncio.sleep(0.05)
        return out

    async def test_a_conversation_is_answered_and_logged(self):
        out = await self.talk(request(9), request(4, bytes([0xC0, 0xC1, 0x02])), request(4, bytes([0xC0, 0xC2, 0x03])))
        self.assertEqual(parse_frames(out[0])[0][0]["control"], 0x0B)
        self.assertEqual(parse_frames(out[1])[0][1], bytes([0xC0, 0xC1, 0x81, 0, 0]))
        self.assertEqual([k.detail["ics"] for k in self.knocks], ["identity", "write", "control"])
        self.assertTrue(all(not k.detail.get("scan") for k in self.knocks))

    async def test_reads_are_capped_but_writes_always_log(self):
        frames = [request(9)] * 20 + [request(4, bytes([0xC0, 0xC1, 0x02]))]
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(b"".join(frames))
        await w.drain()
        await asyncio.sleep(0.6)
        w.close()
        await asyncio.sleep(0.05)
        writes = [k for k in self.knocks if k.detail.get("ics") == "write"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(len(self.knocks) - 1, Dnp3Listener.MAX_READS_LOGGED)

    async def test_frame_limit(self):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(request(9) * (Dnp3Listener.MAX_FRAMES + 10))
        await w.drain()
        total = b""
        while True:
            chunk = await asyncio.wait_for(r.read(4096), 3)
            if not chunk:
                break
            total += chunk
        w.close()
        self.assertEqual(len(total), Dnp3Listener.MAX_FRAMES * 10)

    async def test_http_on_the_port_is_logged_as_not_dnp3(self):
        await self.talk(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", wait=0.2)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])
        self.assertIn("not DNP3", self.knocks[0].lines[0][1])

    async def test_a_corrupt_block_is_logged_and_closes(self):
        bad = bytearray(request(4, bytes([0xC0, 0xC1, 0x01])))
        bad[-1] ^= 0xFF
        await self.talk(bytes(bad), wait=0.2)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])

    async def test_connect_and_leave_is_a_scan(self):
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.close()
        await asyncio.sleep(0.3)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])


if __name__ == "__main__":
    unittest.main()
