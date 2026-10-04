"""Ask a Modbus decoy a few questions, the way a scanner would.

    python tools/modbus_probe.py 203.0.113.10         (port 502)
    python tools/modbus_probe.py 127.0.0.1 15020

Needs:  python -m pip install pymodbus
Each request shows up on the dashboard as a Modbus event from this machine.
"""
import asyncio
import sys

from pymodbus.client import AsyncModbusTcpClient


async def main(host: str, port: int) -> int:
    c = AsyncModbusTcpClient(host, port=port, timeout=6)
    if not await c.connect():
        print(f"could not connect to {host}:{port}")
        return 1
    try:
        r = await c.read_holding_registers(0, count=2, device_id=1)
        print("read registers 0-1:", "ERROR" if r.isError() else r.registers)
        r = await c.read_device_information(read_code=1, object_id=0, device_id=1)
        print("device identity:   ", "ERROR" if r.isError() else
              {k: v.decode() for k, v in r.information.items()})
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    sys.exit(asyncio.run(main(host, port)))
