"""WebSocket connection manager + broadcast router."""
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from server.config import get_settings
import jwt

settings = get_settings()
router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active = [c for c in self.active if c is not ws]

    async def broadcast(self, payload: dict):
        message = json.dumps(payload)
        dead = []
        for connection in self.active:
            try:
                await connection.send_text(message)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()


@router.websocket("/ws/events")
async def websocket_endpoint(ws: WebSocket, token: str = Query(...)):
    try:
        jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        await ws.close(code=4001)
        return

    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keep-alive ping from client
    except WebSocketDisconnect:
        manager.disconnect(ws)
