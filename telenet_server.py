# telnet_server.py
import asyncio
import datetime
from logger import log_request

HOST = "0.0.0.0"
PORT = 2323
SERVICE = "virtual-iot-telnet"

async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "unknown"
    session_start = datetime.datetime.utcnow().isoformat() + "Z"

    # session transcript: list of {"ts":..., "dir":"in"/"out", "text":...}
    transcript = []
    username = None

    def add(dir_, text):
        transcript.append({
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "dir": dir_,
            "text": text
        })

    try:
        # send initial banner + login prompt
        banner = "RouterOS v1.0 (simulated)\r\nlogin: "
        writer.write(banner.encode())
        await writer.drain()
        add("out", banner)

        # read username
        data = await reader.readline()
        if not data:
            writer.close()
            await writer.wait_closed()
            return
        username = data.decode(errors="ignore").strip()
        add("in", username)

        # ask for password
        writer.write(b"Password: ")
        await writer.drain()
        add("out", "Password: ")

        data = await reader.readline()
        if not data:
            writer.close()
            await writer.wait_closed()
            return
        password = data.decode(errors="ignore").strip()
        add("in", "<password>")  # do not store raw password text in transcript for safety
        # log credential attempt as part of session data below

        # fake auth result (always fail once, then accept) - mimic routers that lock or reject then accept
        writer.write(b"Login incorrect\r\nlogin: ")
        await writer.drain()
        add("out", "Login incorrect")

        # read another username (simulate retry)
        data = await reader.readline()
        if not data:
            writer.close()
            await writer.wait_closed()
            return
        username = data.decode(errors="ignore").strip()
        add("in", username)

        writer.write(b"Password: ")
        await writer.drain()
        add("out", "Password: ")
        data = await reader.readline()
        if not data:
            writer.close()
            await writer.wait_closed()
            return
        password = data.decode(errors="ignore").strip()
        add("in", "<password>")

        # accept and drop to fake shell
        writer.write(b"\r\nWelcome to RouterOS CLI\r\n> ")
        await writer.drain()
        add("out", "Welcome to RouterOS CLI")

        # handle simple commands until client closes
        while True:
            data = await reader.readline()
            if not data:
                break
            cmd = data.decode(errors="ignore").rstrip("\r\n")
            add("in", cmd)

            # RouterOS + Linux command emulation
            if cmd.lower() in ("exit", "quit", "logout"):
                resp = "Logout\r\n"
                writer.write(resp.encode())
                add("out", resp.strip())
                await writer.drain()
                break

            elif cmd == "/system resource print":
                resp = (
                    "uptime: 1d2h3m\r\n"
                    "version: 6.48.6\r\n"
                    "cpu: MIPS 24Kc\r\n"
                    "cpu-frequency: 600MHz\r\n"
                    "free-memory: 128MiB\r\n"
                    "total-memory: 256MiB\r\n"
                )

            elif cmd == "/system identity print":
                resp = 'name="MikroTik"\r\n'

            elif cmd == "/interface print":
                resp = (
                    "Flags: X - disabled, R - running\r\n"
                    " #   NAME       TYPE\r\n"
                    " 0   ether1     ether\r\n"
                    " 1   ether2     ether\r\n"
                )

            elif cmd == "/ip address print":
                resp = "0   192.168.88.1/24    ether1\r\n"

            elif cmd == "/system clock print":
                resp = "time: 12:32:10\r\ndate: nov/20/2025\r\n"

            elif cmd == "/user print":
                resp = "0   admin    full\r\n"

            elif cmd == "/ip route print":
                resp = "0   0.0.0.0/0   192.168.88.1   1\r\n"

            elif cmd == "/system routerboard print":
                resp = (
                    "routerboard: yes\r\n"
                    "model: RB750Gr3\r\n"
                    "serial-number: A1B2C3D4E5\r\n"
                    "firmware-type: qca9531L\r\n"
                )

            # common attacker / Linux-style commands
            elif cmd.lower() == "ls":
                resp = "bin  etc  lib  usr  tmp\r\n"

            elif cmd.lower().startswith("cat "):
                resp = "root:x:0:0:root:/root:/bin/sh\r\n"

            elif "wget" in cmd or "curl" in cmd:
                resp = (
                    "Downloading...\r\n"
                    "sh: 1: ./payload: Permission denied\r\n"
                )

            elif cmd.strip() == "":
                resp = ""

            else:
                resp = f"sh: {cmd}: command not found\r\n"

            # send response and prompt again
            writer.write(resp.encode() + b"> ")
            add("out", resp)
            await writer.drain()

    except Exception as e:
        # log exception to transcript
        add("out", f"ERROR: {e}")
    finally:
        # log the session as one JSON entry via logger.log_request
        session_data = {
            "session_start": session_start,
            "username": username or "",
            "transcript": transcript
        }
        # Use path "/telnet" and method "SESSION" to differentiate from HTTP logs
        log_request(src_ip, SERVICE, "/telnet", "SESSION", session_data)

        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Telnet honeypot listening on {addrs} (PID will be this process).")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
