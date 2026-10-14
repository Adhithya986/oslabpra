import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.config import STATIC_DIR, APP_NAME, VERSION
from app.api import router as api_router
from app.websocket_manager import ws_manager
from app.monitor import monitor
from app.threat_engine import threat_engine

# Background metrics streaming task
bg_task = None

async def metrics_broadcaster():
    while True:
        try:
            snapshot = monitor.snapshot()
            cpu_p = snapshot['cpu']['overall_percent']
            ram_p = snapshot['memory']['ram']['percent']
            disk_p = snapshot['disk']['partitions'][0]['percent'] if snapshot['disk']['partitions'] else 0.0

            threat_summary = threat_engine.run_full_scan(cpu_p, ram_p, disk_p)

            payload = {
                "type": "METRICS_UPDATE",
                "timestamp": snapshot["timestamp"],
                "metrics": snapshot,
                "security": {
                    "health": threat_summary["health"],
                    "threat_count": threat_summary["threat_count"],
                    "threats": threat_summary["threats"]
                }
            }
            await ws_manager.broadcast(payload)
        except Exception as e:
            # Prevent background loop crash
            pass
        await asyncio.sleep(1.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    bg_task = asyncio.create_task(metrics_broadcaster())
    yield
    # Shutdown
    bg_task.cancel()

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    lifespan=lifespan
)

# API Routes
app.include_router(api_router, prefix="/api")

# Serve Frontend Static Assets
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep socket open and listen for any client messages or pings
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

@app.get("/")
def read_root():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": f"{APP_NAME} API running. Web UI loading..."}
