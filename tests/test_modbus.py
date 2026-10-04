"""Tests for the Modbus decoy. Run from the repo root:  python -m unittest discover tests -v"""
import asyncio
import struct
import unittest

from uninvited import modbus
from uninvited.listeners import ModbusListener

IDENT = modbus.Identity()
NOW = 1_700_000_000.0


def run(pdu, state=None):
    return modbus.handle(pdu, state or modbus.State(), IDENT, NOW)


class ParseTests(unittest.TestCase):
    def test_good_header(self):
        self.assertEqual(modbus.parse_mbap(struct.pack(">HHHB", 7, 0, 6, 1)), (7, 6, 1))

    def test_rejects_bad_protocol_id_and_lengths(self):
        self.assertIsNone(modbus.parse_mbap(struct.pack(">HHHB", 1, 1, 6, 1)))
        self.assertIsNone(modbus.parse_mbap(struct.pack(">HHHB", 1, 0, 1, 1)))
        self.assertIsNone(modbus.parse_mbap(struct.pack(">HHHB", 1, 0, 255, 1)))
        self.assertIsNone(modbus.parse_mbap(b"GET / H"))
        self.assertIsNone(modbus.parse_mbap(b"\x00"))


class ReadTests(unittest.TestCase):
    def test_read_holding_registers(self):
        r = run(struct.pack(">BHH", 3, 0, 10))
        self.assertEqual(r.pdu[0], 3)
        self.assertEqual(r.pdu[1], 20)
        self.assertEqual(len(r.pdu), 22)
        self.assertFalse(r.info["write"])

    def test_read_coils_packs_bits(self):
        r = run(struct.pack(">BHH", 1, 0, 9))
        self.assertEqual(r.pdu[:2], bytes([1, 2]))
        self.assertEqual(len(r.pdu), 4)

    def test_quantity_limits(self):
        for fc, qty in ((3, 0), (3, 126), (1, 0), (1, 2001)):
            r = run(struct.pack(">BHH", fc, 0, qty))
            self.assertEqual(r.pdu, bytes([fc | 0x80, 3]), (fc, qty))

    def test_address_overflow(self):
        r = run(struct.pack(">BHH", 3, 0xFFFF, 2))
        self.assertEqual(r.pdu, bytes([0x83, 2]))

    def test_short_and_long_bodies(self):
        self.assertEqual(run(b"\x03\x00").pdu, bytes([0x83, 3]))
        self.assertEqual(run(b"\x03" + b"\x00" * 9).pdu, bytes([0x83, 3]))


class WriteTests(unittest.TestCase):
    def test_single_register_sticks_within_a_connection(self):
        st = modbus.State()
        w = run(struct.pack(">BHH", 6, 5, 1234), st)
        self.assertTrue(w.info["write"])
        self.assertEqual(w.pdu, struct.pack(">BHH", 6, 5, 1234))
        r = run(struct.pack(">BHH", 3, 5, 1), st)
        self.assertEqual(struct.unpack(">H", r.pdu[2:4])[0], 1234)

    def test_fresh_state_does_not_remember(self):
        run(struct.pack(">BHH", 6, 5, 1234))
        r = run(struct.pack(">BHH", 3, 5, 1))
        self.assertNotEqual(struct.unpack(">H", r.pdu[2:4])[0], 1234)

    def test_single_coil_values(self):
        self.assertEqual(run(struct.pack(">BHH", 5, 1, 0xFF00)).pdu[0], 5)
        self.assertEqual(run(struct.pack(">BHH", 5, 1, 0x1234)).pdu, bytes([0x85, 3]))

    def test_write_multiple_registers(self):
        pdu = struct.pack(">BHHB", 16, 10, 2, 4) + struct.pack(">HH", 1, 2)
        r = run(pdu)
        self.assertEqual(r.pdu, struct.pack(">BHH", 16, 10, 2))
        self.assertTrue(r.info["write"])

    def test_write_multiple_rejects_bad_byte_count(self):
        pdu = struct.pack(">BHHB", 16, 10, 2, 3) + b"\x00\x01\x00"
        self.assertEqual(run(pdu).pdu, bytes([0x90, 3]))

    def test_write_multiple_coils(self):
        pdu = struct.pack(">BHHB", 15, 0, 10, 2) + b"\xff\x03"
        self.assertEqual(run(pdu).pdu, struct.pack(">BHH", 15, 0, 10))

    def test_state_is_capped(self):
        st = modbus.State()
        for a in range(modbus.MAX_STATE + 50):
            run(struct.pack(">BHH", 6, a, 1), st)
        self.assertLessEqual(len(st.regs) + len(st.coils), modbus.MAX_STATE)


class IdentityTests(unittest.TestCase):
    def test_report_server_id(self):
        r = run(b"\x11")
        self.assertEqual(r.pdu[0], 0x11)
        self.assertEqual(r.pdu[1], len(r.pdu) - 2)
        self.assertIn(b"LC-2200", r.pdu)

    def test_device_identification_stream(self):
        r = run(bytes([0x2B, 0x0E, 1, 0]))
        self.assertEqual(r.pdu[:3], bytes([0x2B, 0x0E, 1]))
        self.assertEqual(r.pdu[6], 3)
        self.assertIn(b"Lakeside Controls", r.pdu)

    def test_device_identification_single_object(self):
        r = run(bytes([0x2B, 0x0E, 4, 1]))
        self.assertEqual(r.pdu[6], 1)
        self.assertIn(b"LC-2200 Controller", r.pdu)
        self.assertEqual(run(bytes([0x2B, 0x0E, 4, 9])).pdu, bytes([0xAB, 2]))

    def test_device_identification_has_a_readable_name(self):
        self.assertEqual(run(bytes([0x2B, 0x0E, 1, 0])).info["name"], "Read Device Identification")

    def test_other_mei_type_refused(self):
        self.assertEqual(run(bytes([0x2B, 0x0D, 1, 0])).pdu, bytes([0xAB, 1]))

    def test_identity_from_config_is_bounded(self):
        ident = modbus.Identity.from_cfg({"vendor": "x" * 500})
        self.assertEqual(len(ident.vendor), 64)


class OtherTests(unittest.TestCase):
    def test_unknown_function_is_illegal(self):
        self.assertEqual(run(b"\x63").pdu, bytes([0xE3, 1]))

    def test_empty_pdu_does_not_raise(self):
        self.assertEqual(run(b"").pdu[1], 1)

    def test_diagnostics_echo_is_bounded(self):
        r = run(b"\x08\x00\x00" + b"A" * 200)
        self.assertLessEqual(len(r.pdu), 1 + modbus.MAX_ECHO)

    def test_no_input_raises(self):
        import random
        rnd = random.Random(1)
        for _ in range(3000):
            pdu = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 20)))
            run(pdu)


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.listener = ModbusListener({"port": 0}, emit, asyncio.Semaphore(10))
        self.listener.server = await asyncio.start_server(self.listener._wrap, "127.0.0.1", 0)
        self.port = self.listener.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.listener.server.close()
        await self.listener.server.wait_closed()

    async def talk(self, *payloads, read=True):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        out = []
        for p in payloads:
            w.write(p)
            await w.drain()
            if read:
                try:
                    out.append(await asyncio.wait_for(r.read(300), 2))
                except TimeoutError:
                    out.append(None)
        w.close()
        await w.wait_closed()
        await asyncio.sleep(0.05)
        return out

    @staticmethod
    def req(tid, unit, pdu):
        return modbus.frame(tid, unit, pdu)

    async def test_read_is_answered_and_counts_as_engaged_read(self):
        (resp,) = await self.talk(self.req(9, 1, struct.pack(">BHH", 3, 0, 2)))
        self.assertEqual(struct.unpack(">HHH", resp[:6]), (9, 0, 7))
        self.assertEqual(resp[7], 3)
        self.assertEqual(len(self.knocks), 1)
        k = self.knocks[0]
        self.assertEqual(k.proto, "MODBUS")
        self.assertNotIn("scan", k.detail)
        self.assertEqual(k.detail["ics"], "read")
        self.assertFalse(k.detail["write"])

    async def test_identity_requests_are_labelled(self):
        await self.talk(self.req(1, 1, bytes([0x2B, 0x0E, 1, 0])))
        self.assertEqual(self.knocks[0].detail["ics"], "identity")

    async def test_write_is_answered_and_not_a_scan(self):
        (resp,) = await self.talk(self.req(1, 1, struct.pack(">BHH", 6, 4, 99)))
        self.assertEqual(resp[7:], struct.pack(">BHH", 6, 4, 99))
        self.assertEqual(self.knocks[0].detail["ics"], "write")
        self.assertTrue(self.knocks[0].detail["write"])

    async def test_pipelined_requests_are_both_served(self):
        a = self.req(1, 1, b"\x11")
        b = self.req(2, 1, struct.pack(">BHH", 3, 0, 1))
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(a + b)
        await w.drain()
        data = b""
        while len(data) < 40:
            chunk = await asyncio.wait_for(r.read(300), 2)
            if not chunk:
                break
            data += chunk
        w.close()
        self.assertIn(struct.pack(">H", 1), data[:2])
        self.assertIn(struct.pack(">HHH", 2, 0, 5), data)

    async def test_http_on_the_port_is_logged_as_not_modbus(self):
        await self.talk(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", read=False)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])
        self.assertIn("not Modbus", self.knocks[0].lines[0][1])

    async def test_connect_and_leave_is_logged_as_a_scan(self):
        await self.talk(read=False)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])

    async def test_read_logging_is_capped_but_writes_always_log(self):
        read = self.req(1, 1, struct.pack(">BHH", 3, 0, 1))
        write = self.req(2, 1, struct.pack(">BHH", 6, 0, 1))
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(read * 20 + write)
        await w.drain()
        await asyncio.sleep(0.3)
        w.close()
        await asyncio.sleep(0.05)
        reads = [k for k in self.knocks if not k.detail["write"]]
        writes = [k for k in self.knocks if k.detail["write"]]
        self.assertEqual(len(reads), ModbusListener.MAX_READS_LOGGED)
        self.assertEqual(len(writes), 1)

    async def test_frame_limit_closes_the_connection(self):
        read = self.req(1, 1, struct.pack(">BHH", 3, 0, 1))
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(read * (ModbusListener.MAX_FRAMES + 10))
        await w.drain()
        total = b""
        while True:
            chunk = await asyncio.wait_for(r.read(4096), 3)
            if not chunk:
                break
            total += chunk
        w.close()
        self.assertEqual(len(total), ModbusListener.MAX_FRAMES * 11)   # 7 header + 4 pdu each


if __name__ == "__main__":
    unittest.main()
