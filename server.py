# server.py
from aiohttp import web
from logger import log_request
import asyncio

# Config
HOST = "0.0.0.0"
PORT = 8080
SERVICE_NAME = "virtual-iot-http"

async def index(request):
    ip = request.remote or request.transport.get_extra_info('peername')[0]
    # log GET to /
    log_request(ip, SERVICE_NAME, "/", "GET", {})
    return web.Response(text="Device status: OK\n", content_type='text/plain')

async def login(request):
    ip = request.remote or request.transport.get_extra_info('peername')[0]
    try:
        post = await request.post()
        data = dict(post)
    except Exception:
        # fallback to raw body
        body = await request.text()
        data = {"raw": body}
    # log the POSTed credentials / body
    log_request(ip, SERVICE_NAME, "/login", "POST", data)
    # Return a plausible-but-fake response
    return web.Response(text="Invalid credentials\n", content_type='text/plain')

async def status(request):
    ip = request.remote or request.transport.get_extra_info('peername')[0]
    log_request(ip, SERVICE_NAME, "/status", "GET", {})
    fake_json = {"device":"SmartCam-1000","uptime":"3 days","status":"ok"}
    return web.json_response(fake_json)

app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/status", status)
app.router.add_post("/login", login)

if __name__ == "__main__":
    web.run_app(app, host=HOST, port=PORT)
