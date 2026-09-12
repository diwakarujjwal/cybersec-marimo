"""FastAPI main entrypoint for CyberLab Platform."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from cyberlab.core.config import settings
from cyberlab.db.database import init_db, SessionLocal
from cyberlab.db.models import ChallengeInstance
from cyberlab.services.lms_service import lms_service
from cyberlab.services.challenge_loader import challenge_loader
from cyberlab.services.janitor import janitor_service
from cyberlab.services.proxy import proxy_service
from cyberlab.api.routes_auth import router as auth_router
from cyberlab.api.routes_challenges import router as challenges_router
from cyberlab.api.routes_instances import router as instances_router
from cyberlab.api.routes_submissions import router as submissions_router
from cyberlab.api.routes_competencies import router as competencies_router
from cyberlab.api.routes_instructor import router as instructor_router
from cyberlab.api.routes_generator import router as generator_router

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cyberlab.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing CyberLab Database...")
    init_db()

    db = SessionLocal()
    try:
        lms_service.seed_competencies(db)
        # Create default demo student and instructor
        lms_service.get_or_create_student(
            db,
            lms_user_id="student-alice",
            username="alice",
            email="alice@cyberlab.edu",
            role="student",
        )
        lms_service.get_or_create_student(
            db,
            lms_user_id="instructor-prof",
            username="prof_moriarty",
            email="prof@cyberlab.edu",
            role="instructor",
        )
        # Clean up any orphaned sessions from previous server runs
        stale_count = (
            db.query(ChallengeInstance)
            .filter(ChallengeInstance.status.in_(["starting", "running"]))
            .update({"status": "stopped"})
        )
        if stale_count > 0:
            logger.info(
                f"Reclaimed {stale_count} orphaned sessions from previous server run."
            )

        # Scan and sync challenge packages
        synced = await challenge_loader.sync_to_db_and_ctfd(db)
        logger.info(f"Loaded {synced} challenge packages into database and CTFd.")
    finally:
        db.close()

    # Start background cleanup janitor
    await janitor_service.start()
    yield

    # Shutdown
    await janitor_service.stop()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth_router)
app.include_router(challenges_router)
app.include_router(instances_router)
app.include_router(submissions_router)
app.include_router(competencies_router)
app.include_router(instructor_router)
app.include_router(generator_router)


# Reverse Proxy Endpoints for Student Marimo & Web App Sessions
@app.websocket("/session/{session_id}")
@app.websocket("/session/{session_id}/")
async def proxy_ws_route_root(websocket: WebSocket, session_id: str):
    await proxy_service.handle_websocket(websocket, session_id, "")


@app.websocket("/session/{session_id}/{path:path}")
async def proxy_ws_route_path(websocket: WebSocket, session_id: str, path: str):
    await proxy_service.handle_websocket(websocket, session_id, path)


@app.api_route(
    "/session/{session_id}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
@app.api_route(
    "/session/{session_id}/",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_http_route_root(request: Request, session_id: str):
    return await proxy_service.handle_http(request, session_id, "")


@app.api_route(
    "/session/{session_id}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_http_route_path(request: Request, session_id: str, path: str):
    return await proxy_service.handle_http(request, session_id, path)


# Mount static files and UI
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse(
        "<h1>CyberLab Platform Initialized</h1><p>Visit /docs for API schema.</p>"
    )
