# relay.py
import asyncio
import websockets
import json
import ssl
from urllib.parse import urlparse, parse_qs

"""
Protocol (messages are JSON):
Client -> Server
  {type:"hello"}                                      # optional; ignored
  {type:"iam_host"}                                   # ignored unless room has no host yet
  {type:"host_mute_all"}                              # host only
  {type:"host_kick", target:"username"}               # host only
  {type:"transfer_host", to:"username"}               # host only
  {type:"introduce_pair", a:"userA", b:"userB"}       # host only
  {type:"signal", to:"username", data:{...}}          # directed relay (opaque payload)

Server -> Client
  {type:"peer_list", users:[...], host:"username"|null}
  {type:"peer_joined", user:"username"}
  {type:"peer_left",   user:"username"}
  {type:"host_changed", host:"username"|null}
  {type:"host_mute"}                                  # received by non-hosts
  {type:"host_kick", to:"username"}                   # warning before close
  {type:"signal", to:"username", from:"username", data:{...}}
  # and directed intros:
  {type:"signal", to:"userA", from:"host", data:{type:"intro", other:"userB"}}
"""

# rooms = {
#   room_id: {
#       "clients": { ws: "username", ... },
#       "host": "username or None"
#   }
# }
rooms = {}


# ----------------- helpers -----------------
def usernames_in_room(room):
    return list(room["clients"].values())

def ws_for_username(room, username):
    for peer, uname in room["clients"].items():
        if uname == username:
            return peer
    return None

async def broadcast(room, payload, except_ws=None):
    """Send to all clients in room (optionally excluding one)."""
    data = json.dumps(payload)
    dead = []
    for peer in list(room["clients"].keys()):
        if peer is except_ws:
            continue
        try:
            if peer.open:
                await peer.send(data)
        except Exception:
            dead.append(peer)
    # cleanup dead sockets if any
    for peer in dead:
        room["clients"].pop(peer, None)

async def send_to_user(room, username, payload):
    """Send to a specific username (if present)."""
    peer = ws_for_username(room, username)
    if peer and peer.open:
        try:
            await peer.send(json.dumps(payload))
            return True
        except Exception:
            pass
    return False
    


# ----------------- core handler -----------------
async def handler(ws, path):
    # Parse query params: ?room=ROOM&user=USERNAME
    query = parse_qs(urlparse(path).query)
    room_id = query.get("room", ["default"])[0]
    user    = query.get("user", ["anon"])[0]

    # Create room if missing
    if room_id not in rooms:
        rooms[room_id] = {"clients": {}, "host": None}
    room = rooms[room_id]

    # Register client
    room["clients"][ws] = user
    print(f"[INFO] {user} joined {room_id}")

    # Initial host selection (first user becomes host)
    if room["host"] is None:
        room["host"] = user
        # Announce host to all (including the new joiner)
        await broadcast(room, {"type": "host_changed", "host": user})

    # Send current peer list (and host) to the new client
    users = usernames_in_room(room)
    await ws.send(json.dumps({"type": "peer_list", "users": users, "host": room["host"]}))

    # Notify others someone joined
    await broadcast(room, {"type": "peer_joined", "user": user}, except_ws=ws)

    try:
        async for raw in ws:
            # Try to parse JSON; if not JSON → blind relay to others
            try:
                msg = json.loads(raw)
            except Exception:
                await broadcast(room, raw, except_ws=ws)
                continue

            sender_name = room["clients"].get(ws, "anon")

            # ---- Host designation (only if no host yet) ----
            if msg.get("type") == "iam_host":
                if room["host"] is None:
                    room["host"] = sender_name
                    print(f"[HOST] {sender_name} is host of {room_id}")
                    await broadcast(room, {"type": "host_changed", "host": sender_name})
                continue

            # ---- Host: mute all ----
            if msg.get("type") == "host_mute_all":
                if sender_name == room.get("host"):
                    # broadcast only to non-hosts
                    for peer, uname in list(room["clients"].items()):
                        if peer.open and uname != sender_name:
                            try:
                                await peer.send(json.dumps({"type": "host_mute"}))
                            except Exception:
                                pass
                continue

            # ---- Host: kick specific user ----
            if msg.get("type") == "host_kick":
                if sender_name == room.get("host"):
                    target = msg.get("target")
                    if not target:
                        continue
                    target_ws = ws_for_username(room, target)
                    if target_ws and target_ws.open:
                        try:
                            await target_ws.send(json.dumps({"type": "host_kick", "to": target}))
                        except Exception:
                            pass
                        # Close their socket
                        try:
                            await target_ws.close()
                        except Exception:
                            pass
                continue

            # ---- Host: transfer host role ----
            if msg.get("type") == "transfer_host":
                target = msg.get("to")
                if sender_name == room.get("host") and target in usernames_in_room(room):
                    room["host"] = target
                    await broadcast(room, {"type": "host_changed", "host": target})
                continue

            # ---- Host: introduce two peers (A <-> B) ----
            if msg.get("type") == "introduce_pair":
                a, b = msg.get("a"), msg.get("b")
                if sender_name != room.get("host") or not a or not b:
                    continue
                # send directed "intro" signal to both sides
                for target, other in ((a, b), (b, a)):
                    await send_to_user(room, target, {
                        "type": "signal", "to": target, "from": "host",
                        "data": {"type": "intro", "other": other}
                    })
                continue

            # ---- Directed signaling relay ----
            if msg.get("type") == "signal" and "to" in msg:
                target = msg["to"]
                # enforce 'from' sender name
                msg["from"] = sender_name
                await send_to_user(room, target, msg)
                continue

                        # ---- Chat messages (room-wide or private) ----
            if msg.get("type") == "chat":
                txt = (msg.get("text") or "").strip()
                if not txt:
                    continue

                target = msg.get("to")  # optional, for private chats later
                payload = {
                    "type": "chat",
                    "from": sender_name,
                    "text": txt,
                }

                if target and target != "*":
                    # private message: send to target + echo back to sender
                    await send_to_user(room, target, {**payload, "private": True})
                    await send_to_user(
                        room,
                        sender_name,
                        {**payload, "private": True, "to": target},
                    )
                else:
                    # room-wide message
                    await broadcast(room, payload)
                continue


            # ---- Fallback: broadcast inside room ----
            await broadcast(room, msg, except_ws=ws)

    except websockets.ConnectionClosed:
        pass
    finally:
        # Cleanup on disconnect
        user_left = room["clients"].pop(ws, None)
        print(f"[INFO] {user_left} left {room_id}")

        # Notify others
        await broadcast(room, {"type": "peer_left", "user": user_left})

        # If host left, promote deterministically (alphabetical)
        if user_left and room.get("host") == user_left:
            remaining = usernames_in_room(room)
            new_host = min(remaining) if remaining else None
            room["host"] = new_host
            await broadcast(room, {"type": "host_changed", "host": new_host})

        if not room["clients"]:
            rooms.pop(room_id, None)


# ----------------- entrypoint -----------------
async def main():
    # TLS context
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain("crt/server.crt", "crt/server.key")

    print("🔒 Secure WebSocket signaling server on wss://0.0.0.0:8000")

    async with websockets.serve(
        handler,
        "0.0.0.0",
        8000,
        ssl=ssl_ctx,
        ping_interval=20,
        ping_timeout=20,
        max_size=2**20,
        max_queue=64
    ):
        try:
            await asyncio.Future()  # run forever
        except asyncio.CancelledError:
            # Normal shutdown (Ctrl+C / loop stop)
            print("[INFO] Signaling server is shutting down...")
            # let the context manager exit cleanly
            raise



if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Signaling server stopped by user (Ctrl+C)")

