from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database import (
    init_db,
    save_blocked_event,
    get_stats,
    get_recent_events,
    get_all_rules,
    add_rule,
    delete_rule,
)

from filter import check_domain


BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "dashboard"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Sarmoya Security API",
    description="AI-powered Internet Safety API",
    version="4.0.0",
    lifespan=lifespan,
)


# =========================================
# CORS
# =========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sarmoyasecurity.lovable.app",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================
# FRONTEND
# =========================================

@app.get("/")
def root():
    return FileResponse(
        DASHBOARD_DIR / "index.html"
    )


# =========================================
# HEALTH
# =========================================

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "Sarmoya Security",
        "version": "4.0.0",
    }


# =========================================
# URL CHECK
# =========================================

class URLCheckRequest(BaseModel):
    domain: str


@app.post("/api/check-url")
def check_url(data: URLCheckRequest):
    result = check_domain(data.domain)

    if result["blocked"]:
        save_blocked_event(
            domain=result["domain"],
            category=result["category"],
        )

    return result


# =========================================
# STATISTICS
# =========================================

@app.get("/api/stats")
def stats():
    return get_stats()


# =========================================
# BLOCKED EVENTS
# =========================================

@app.get("/api/blocked")
def blocked_events():
    return {
        "events": get_recent_events()
    }


# =========================================
# RULES
# =========================================

class RuleRequest(BaseModel):
    domain: str
    action: str
    category: str = "custom"


@app.get("/api/rules")
def rules():
    return {
        "rules": get_all_rules()
    }


@app.post("/api/rules")
def create_rule(data: RuleRequest):

    action = data.action.strip().upper()

    if action not in {"ALLOW", "BLOCK"}:
        return {
            "success": False,
            "message": "Action must be ALLOW or BLOCK"
        }

    checked = check_domain(data.domain)
    normalized_domain = checked["domain"]

    if not normalized_domain:
        return {
            "success": False,
            "message": "Domain is invalid"
        }

    category = (
        data.category.strip().lower()
        or "custom"
    )

    add_rule(
        domain=normalized_domain,
        action=action,
        category=category,
    )

    return {
        "success": True,
        "domain": normalized_domain,
        "action": action,
        "category": category,
    }


@app.delete("/api/rules/{rule_id}")
def remove_rule(rule_id: int):

    delete_rule(rule_id)

    return {
        "success": True,
        "deleted_id": rule_id,
    }


# =========================================
# STATIC DASHBOARD
# =========================================

app.mount(
    "/",
    StaticFiles(
        directory=DASHBOARD_DIR,
        html=True
    ),
    name="dashboard",
)
