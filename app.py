# Some of the route structure and wording were helped by ChatGPT.
# Final code decisions, testing, and database setup were done by me.
# Reference: Flask Documentation - Routing, Templates & Sessions (2025)
# Reference: SQLAlchemy ORM Tutorial (2025)

from datetime import datetime, timedelta
import os
import requests
from typing import Optional, Dict, Any  # ✅ Python 3.9-compatible typing

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# ✅ NEW: for eager loading (prevents N+1 queries in templates)
from sqlalchemy.orm import joinedload

# ================================
# ✅ NEW: CLOUDINARY (Production Image Storage)
# ================================
import cloudinary
import cloudinary.uploader
import cloudinary.api

CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME", "").strip()
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY", "").strip()
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET", "").strip()

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)
CLOUDINARY_ENABLED = all([
    os.getenv("CLOUDINARY_CLOUD_NAME"),
    os.getenv("CLOUDINARY_API_KEY"),
    os.getenv("CLOUDINARY_API_SECRET"),
])
print("Cloudinary configured:", CLOUDINARY_ENABLED)

print("Cloudinary configured:", bool(CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET))

# ================================
# FLASK APP SETUP
# ================================

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")  # Render: set SECRET_KEY env var

# ================================
# DATABASE CONFIG (PostgreSQL)
# Works locally + on Render
# ================================

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

if DATABASE_URL:
    # Render sometimes provides postgres://... but SQLAlchemy wants postgresql://...
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    # Local fallback (your Mac Postgres)
    DB_USER = "postgres"
    DB_PASS = ""          # if you set a password later, put it here
    DB_HOST = "127.0.0.1"
    DB_PORT = "5432"
    DB_NAME = "swimsafe"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
print("DB URI =", app.config["SQLALCHEMY_DATABASE_URI"])

db = SQLAlchemy(app)

# ================================
# STORMGLASS API
# ================================

STORMGLASS_API_KEY = os.getenv("STORMGLASS_API_KEY", "").strip()
print("Stormglass key loaded:", bool(STORMGLASS_API_KEY))

# Weather/marine point (what you already use)
STORMGLASS_ENDPOINT = "https://api.stormglass.io/v2/weather/point"

# Tide endpoints (sea-level + extremes)
STORMGLASS_TIDE_SEA_LEVEL_ENDPOINT = "https://api.stormglass.io/v2/tide/sea-level/point"
STORMGLASS_TIDE_EXTREMES_ENDPOINT = "https://api.stormglass.io/v2/tide/extremes/point"

# ================================
# UPLOADS (Beach photos)
# ================================

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


# ================================
# SESSION PRESETS (NEW)
# ================================
SESSION_PRESETS = [
    {
        "id": "easy_recovery",
        "name": "Easy Recovery (20–30 min)",
        "goal": "Endurance",
        "intensity": "Easy",
        "skill_level": "Beginner",
        "duration_min": 25,
        "distance_m": None,
        "notes": "Easy continuous swim. Focus on relaxed breathing and sighting.",
    },
    {
        "id": "endurance_steady",
        "name": "Steady Endurance (45 min / ~1500m)",
        "goal": "Endurance",
        "intensity": "Moderate",
        "skill_level": "Intermediate",
        "duration_min": 45,
        "distance_m": 1500,
        "notes": "Steady pace. Practice sighting every 6–10 strokes. Keep effort controlled.",
    },
    {
        "id": "technique_drills",
        "name": "Technique Focus (30 min drills)",
        "goal": "Technique",
        "intensity": "Easy",
        "skill_level": "Intermediate",
        "duration_min": 30,
        "distance_m": None,
        "notes": "Include a drill block (catch, body position, bilateral breathing) + short easy swims.",
    },
    {
        "id": "race_pace",
        "name": "Race-Pace Intervals (advanced)",
        "goal": "Race-pace",
        "intensity": "Hard",
        "skill_level": "Advanced",
        "duration_min": 40,
        "distance_m": 2000,
        "notes": "Warm up → 6–10 x hard efforts with rest → cool down. Only if conditions are safe.",
    },
]

# ---- Models ----
class Beach(db.Model):
    __tablename__ = "beaches"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    county = db.Column(db.String(100))
    latitude = db.Column(db.Numeric(9, 6))
    longitude = db.Column(db.Numeric(9, 6))


class SeaReport(db.Model):
    __tablename__ = "sea_reports"
    id = db.Column(db.Integer, primary_key=True)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)
    reported_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    tide = db.Column(db.String(20))
    temp_c = db.Column(db.Numeric(4, 1))
    flag_status = db.Column(db.String(20))
    notes = db.Column(db.String(255))

    beach = db.relationship("Beach", backref="reports")


class SwimmerIssue(db.Model):
    __tablename__ = "swimmer_issues"
    id = db.Column(db.Integer, primary_key=True)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    issue_type = db.Column(db.String(100))
    description = db.Column(db.String(255))
    resolved = db.Column(db.Boolean, nullable=False, default=False)

    beach = db.relationship("Beach")


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # plain text for this project
    role = db.Column(db.String(20), nullable=False)       # swimmer or lifeguard


# ================================
# --- SwimSafe: FAVOURITE BEACHES (NEW) ---
# ================================
class FavoriteBeach(db.Model):
    __tablename__ = "favorite_beaches"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User")
    beach = db.relationship("Beach")

    __table_args__ = (
        db.UniqueConstraint("user_id", "beach_id", name="uq_favorite_user_beach"),
    )


# ================================
# --- SwimSafe: SWIM SESSION PLANNER (NEW) ---
# ================================
class SwimSessionPlan(db.Model):
    __tablename__ = "swim_session_plans"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)

    # When the swimmer plans to swim (stored as UTC or naive datetime like your reports)
    planned_for = db.Column(db.DateTime, nullable=False)

    # Training details
    goal = db.Column(db.String(80), nullable=False, default="Endurance")  # Endurance/Speed/Technique/Acclimation/Race-pace
    duration_min = db.Column(db.Integer)  # optional
    distance_m = db.Column(db.Integer)    # optional
    intensity = db.Column(db.String(30), default="Easy")  # Easy/Moderate/Hard
    skill_level = db.Column(db.String(30), default="Intermediate")  # Beginner/Intermediate/Advanced

    notes = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User")
    beach = db.relationship("Beach")

    __table_args__ = (
        db.Index("ix_swim_session_user_time", "user_id", "planned_for"),
    )


# ================================
# --- SwimSafe: SWIM SESSION OUTCOME / TRAINING LOG (NEW) ---
# ================================
class SwimSessionOutcome(db.Model):
    __tablename__ = "swim_session_outcomes"
    id = db.Column(db.Integer, primary_key=True)

    session_id = db.Column(db.Integer, db.ForeignKey("swim_session_plans.id"), nullable=False, unique=True)

    # planned / completed / skipped
    status = db.Column(db.String(20), nullable=False, default="planned")

    # optional “how it went”
    rpe = db.Column(db.Integer)  # 1–10
    actual_duration_min = db.Column(db.Integer)
    actual_distance_m = db.Column(db.Integer)
    outcome_notes = db.Column(db.String(255))

    completed_at = db.Column(db.DateTime)

    session = db.relationship("SwimSessionPlan")


# ---- Beach Photos ----
class BeachPhoto(db.Model):
    __tablename__ = "beach_photos"
    id = db.Column(db.Integer, primary_key=True)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)

    image_url = db.Column(db.String(500), nullable=False)   # Cloudinary secure_url
    public_id = db.Column(db.String(255), nullable=True)    # Cloudinary public_id (optional)

    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    uploaded_by = db.Column(db.String(100))

    beach = db.relationship("Beach")


# ---- Helpers ----
def current_user_role():
    return session.get("role")


def login_required(role=None):
    r = current_user_role()
    if r is None:
        return False
    if role is None:
        return True
    return r == role


def _require_user_id() -> Optional[int]:
    """✅ Common guard used in multiple routes."""
    uid = session.get("user_id")
    if not uid:
        flash("Please log in again.", "error")
        return None
    return uid


def _safe_hour_value(hour: dict, key: str):
    """
    Stormglass v2 returns values as objects keyed by source
    (e.g. metno, ecmwf, noaa, sg)
    Prefer 'sg' → fallback to first available source
    """
    try:
        data = hour.get(key)
        if not isinstance(data, dict):
            return None

        # Prefer Stormglass source if available
        if "sg" in data:
            return data["sg"]

        # Otherwise take the first available value
        return next(iter(data.values()), None)
    except Exception:
        return None


def _stormglass_headers():
    return {"Authorization": STORMGLASS_API_KEY}


def _utc_hour_str(dt: datetime) -> str:
    """
    Stormglass tide endpoints accept start/end like 'YYYY-MM-DDTHH' in UTC.
    We round down to the hour to keep it simple & predictable.
    """
    dt2 = dt.replace(minute=0, second=0, microsecond=0)
    return dt2.strftime("%Y-%m-%dT%H")


def _to_float(x):
    try:
        return float(x)
    except Exception:
        return None


def get_marine_conditions(lat: float, lng: float):
    """
    Fetch current-ish marine conditions from Stormglass using lat/lng.
    Returns a dict or None.
    """
    if not STORMGLASS_API_KEY:
        return None

    params = ",".join([
        "waveHeight",
        "waveDirection",
        "wavePeriod",
        "swellHeight",
        "swellDirection",
        "windSpeed",
        "windDirection",
        "waterTemperature",
        "currentSpeed",
        "currentDirection",
    ])

    now = datetime.utcnow()
    start = int(now.timestamp())
    end = int((now + timedelta(hours=1)).timestamp())

    try:
        r = requests.get(
            STORMGLASS_ENDPOINT,
            params={
                "lat": lat,
                "lng": lng,
                "params": params,
                "source": "noaa",
                "start": start,
                "end": end,
            },
            headers=_stormglass_headers(),
            timeout=10,
        )

        print("Stormglass response:", r.status_code, r.text[:200])

        if r.status_code != 200:
            return None

        data = r.json()
        hours = data.get("hours", [])
        if not hours:
            return None

        hour0 = hours[0]

        return {
            "wave_height": _safe_hour_value(hour0, "waveHeight"),
            "wave_direction": _safe_hour_value(hour0, "waveDirection"),
            "wave_period": _safe_hour_value(hour0, "wavePeriod"),
            "swell_height": _safe_hour_value(hour0, "swellHeight"),
            "swell_direction": _safe_hour_value(hour0, "swellDirection"),
            "wind_speed": _safe_hour_value(hour0, "windSpeed"),
            "wind_direction": _safe_hour_value(hour0, "windDirection"),
            "water_temp": _safe_hour_value(hour0, "waterTemperature"),
            "current_speed": _safe_hour_value(hour0, "currentSpeed"),
            "current_direction": _safe_hour_value(hour0, "currentDirection"),
            "time": hour0.get("time"),
        }

    except Exception:
        return None


# ================================
# --- SwimSafe: Forecast at planned session time (NEW)
# ================================
def get_marine_conditions_at(lat: float, lng: float, when_dt: datetime):
    """
    Fetch marine conditions around a planned datetime (UTC/naive).
    Returns same structure as get_marine_conditions() or None.
    """
    if not STORMGLASS_API_KEY:
        return None

    params = ",".join([
        "waveHeight",
        "waveDirection",
        "wavePeriod",
        "swellHeight",
        "swellDirection",
        "windSpeed",
        "windDirection",
        "waterTemperature",
        "currentSpeed",
        "currentDirection",
    ])

    dt = when_dt.replace(minute=0, second=0, microsecond=0)
    start = int((dt - timedelta(hours=1)).timestamp())
    end = int((dt + timedelta(hours=1)).timestamp())

    try:
        r = requests.get(
            STORMGLASS_ENDPOINT,
            params={
                "lat": lat,
                "lng": lng,
                "params": params,
                "source": "noaa",
                "start": start,
                "end": end,
            },
            headers=_stormglass_headers(),
            timeout=10,
        )

        if r.status_code != 200:
            return None

        data = r.json()
        hours = data.get("hours", [])
        if not hours:
            return None

        def parse_time(s):
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                return None

        best = None
        best_diff = None
        for h in hours:
            t = parse_time(h.get("time", ""))
            if not t:
                continue
            diff = abs((t - dt).total_seconds())
            if best is None or diff < best_diff:
                best = h
                best_diff = diff

        if not best:
            best = hours[0]

        return {
            "wave_height": _safe_hour_value(best, "waveHeight"),
            "wave_direction": _safe_hour_value(best, "waveDirection"),
            "wave_period": _safe_hour_value(best, "wavePeriod"),
            "swell_height": _safe_hour_value(best, "swellHeight"),
            "swell_direction": _safe_hour_value(best, "swellDirection"),
            "wind_speed": _safe_hour_value(best, "windSpeed"),
            "wind_direction": _safe_hour_value(best, "windDirection"),
            "water_temp": _safe_hour_value(best, "waterTemperature"),
            "current_speed": _safe_hour_value(best, "currentSpeed"),
            "current_direction": _safe_hour_value(best, "currentDirection"),
            "time": best.get("time"),
        }

    except Exception:
        return None


def get_tide_sea_level(lat: float, lng: float, start_dt: datetime, end_dt: datetime, datum: str = "MSL"):
    if not STORMGLASS_API_KEY:
        return None

    try:
        r = requests.get(
            STORMGLASS_TIDE_SEA_LEVEL_ENDPOINT,
            params={
                "lat": lat,
                "lng": lng,
                "start": _utc_hour_str(start_dt),
                "end": _utc_hour_str(end_dt),
                "datum": datum,
            },
            headers=_stormglass_headers(),
            timeout=10,
        )

        print("Stormglass tide sea-level:", r.status_code, r.text[:200])

        if r.status_code != 200:
            return None

        data = r.json()
        return data.get("data", []) or None

    except Exception:
        return None


def get_tide_extremes(lat: float, lng: float, start_dt: datetime, end_dt: datetime, datum: str = "MSL"):
    if not STORMGLASS_API_KEY:
        return None

    try:
        r = requests.get(
            STORMGLASS_TIDE_EXTREMES_ENDPOINT,
            params={
                "lat": lat,
                "lng": lng,
                "start": _utc_hour_str(start_dt),
                "end": _utc_hour_str(end_dt),
                "datum": datum,
            },
            headers=_stormglass_headers(),
            timeout=10,
        )

        print("Stormglass tide extremes:", r.status_code, r.text[:200])

        if r.status_code != 200:
            return None

        data = r.json()
        return data.get("data", []) or None

    except Exception:
        return None


def compute_tide_assist(
    lat: float,
    lng: float,
    marine_data: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, str]]:
    if not STORMGLASS_API_KEY:
        return None

    now = datetime.utcnow()

    sea = get_tide_sea_level(lat, lng, now, now + timedelta(hours=2))

    sea_now = None
    sea_next = None

    if sea and len(sea) >= 2:
        def extract_height(item: dict):
            if not isinstance(item, dict):
                return None
            if "sg" in item:
                return _to_float(item.get("sg"))
            return _to_float(item.get("height") or item.get("value") or item.get("seaLevel"))

        sea_now = extract_height(sea[0])
        sea_next = extract_height(sea[1])

    delta_m = None
    if sea_now is not None and sea_next is not None:
        delta_m = sea_next - sea_now

    extremes = get_tide_extremes(lat, lng, now - timedelta(hours=3), now + timedelta(hours=9))
    nearest = None

    if extremes:
        for e in extremes:
            try:
                t_str = e.get("time")
                if not t_str:
                    continue
                t = datetime.fromisoformat(t_str.replace("Z", "+00:00")).replace(tzinfo=None)
                diff = abs((t - now).total_seconds())
                if nearest is None or diff < nearest["diff"]:
                    nearest = {
                        "diff": diff,
                        "type": (e.get("type") or "").lower(),
                        "time": t_str,
                        "height": e.get("height"),
                    }
            except Exception:
                continue

    tide_state = None

    if nearest and nearest["type"] in {"high", "low"} and nearest["diff"] <= 60 * 60:
        tide_state = "High" if nearest["type"] == "high" else "Low"
    else:
        if delta_m is not None:
            tide_state = "Rising" if delta_m >= 0 else "Falling"

    tide_strength = None
    tide_basis = None

    current_speed = None
    if marine_data:
        current_speed = _to_float(marine_data.get("current_speed"))

    if current_speed is not None:
        if current_speed >= 0.8:
            tide_strength = "Strong"
        elif current_speed >= 0.3:
            tide_strength = "Moderate"
        else:
            tide_strength = "Weak"
        tide_basis = f"currentSpeed {current_speed:.2f} m/s"
    else:
        if delta_m is not None:
            rate = abs(delta_m)
            if rate >= 0.15:
                tide_strength = "Strong"
            elif rate >= 0.05:
                tide_strength = "Moderate"
            else:
                tide_strength = "Weak"
            tide_basis = f"Δsea level {rate:.2f} m/hr (proxy)"
        else:
            tide_basis = "no tide data available"

    if not tide_state and not tide_strength:
        return None

    return {
        "tide_state": tide_state or "",
        "tide_strength": tide_strength or "",
        "tide_basis": tide_basis or "",
    }


def build_safety_advisory(api_data: dict):
    if not api_data:
        return None

    wave_h = _to_float(api_data.get("wave_height"))
    wind_s = _to_float(api_data.get("wind_speed"))
    wave_p = _to_float(api_data.get("wave_period"))

    reasons = []
    level = "Low risk"
    level_class = "low"

    if wave_h is not None:
        if wave_h > 2.5:
            reasons.append(f"Wave height {wave_h:.1f}m is above unsafe threshold (2.5m).")
        elif wave_h > 1.5:
            reasons.append(f"Wave height {wave_h:.1f}m is above caution threshold (1.5m).")

    if wind_s is not None:
        if wind_s > 14:
            reasons.append(f"Wind speed {wind_s:.1f}m/s is above unsafe threshold (14m/s).")
        elif wind_s > 9:
            reasons.append(f"Wind speed {wind_s:.1f}m/s is above caution threshold (9m/s).")

    if wave_p is not None and wave_h is not None:
        if wave_p > 14 and wave_h > 1.5:
            reasons.append(f"Long wave period {wave_p:.0f}s with wave height {wave_h:.1f}m suggests powerful swell.")
        elif wave_p > 12 and wave_h > 1.2:
            reasons.append(f"Wave period {wave_p:.0f}s with wave height {wave_h:.1f}m suggests stronger sets.")

    unsafe_hit = any("unsafe threshold" in r for r in reasons)
    caution_hit = (not unsafe_hit) and len(reasons) > 0

    if unsafe_hit:
        level = "UNSAFE"
        level_class = "unsafe"
    elif caution_hit:
        level = "CAUTION"
        level_class = "caution"
    else:
        level = "LOW RISK"
        level_class = "low"

    if wave_h is None and wind_s is None and wave_p is None:
        return {
            "level": "NO DATA",
            "level_class": "caution",
            "reasons": ["API returned no usable numeric data for this beach/time window."]
        }

    return {
        "level": level,
        "level_class": level_class,
        "reasons": reasons if reasons else ["Conditions are within basic low-risk thresholds."]
    }


# ================================
# --- SwimSafe: ADDED for Swimmer Dashboard (safe additions) ---
# ================================
def _pick_primary_beach_for_swimmer(beach_id_str: str, reports: list, beaches_list: list):
    try:
        if beach_id_str and beach_id_str.isdigit():
            return Beach.query.get(int(beach_id_str))
    except Exception:
        pass

    try:
        if reports and len(reports) > 0 and getattr(reports[0], "beach", None):
            return reports[0].beach
    except Exception:
        pass

    try:
        if beaches_list and len(beaches_list) > 0:
            return beaches_list[0]
    except Exception:
        pass

    return None


def _swimmer_context_tips(latest_report: Optional["SeaReport"], advisory: Optional[dict], tide: Optional[dict]):
    tips = []

    flag = None
    if latest_report:
        flag = (latest_report.flag_status or "").strip().lower()

    if flag == "red":
        tips.append("Red flag: conditions may be unsafe. Consider postponing or choosing a sheltered location.")
    elif flag == "yellow":
        tips.append("Yellow flag: use caution. Stay close to shore and swim within your limits.")
    elif flag == "green":
        tips.append("Green flag: conditions are generally safer, but always remain vigilant and assess entry/exit points.")

    if tide:
        state = (tide.get("tide_state") or "").strip().lower()
        strength = (tide.get("tide_strength") or "").strip().lower()

        if state in {"falling", "low"}:
            tips.append("Falling/low tide can increase outgoing flow around rocks and channels — watch for rips.")
        elif state in {"rising", "high"}:
            tips.append("Rising/high tide can cover hazards on entry/exit — check footing and shore break.")

        if strength == "strong":
            tips.append("Strong tidal flow detected — avoid swimming near piers, headlands, or narrow channels.")
        elif strength == "moderate":
            tips.append("Moderate tidal flow — stay aware of drift and choose a clear landmark for navigation.")

    if advisory:
        level = (advisory.get("level") or "").strip().upper()
        if level == "UNSAFE":
            tips.append("API advisory indicates UNSAFE conditions — only proceed with lifeguard guidance or do not enter.")
        elif level == "CAUTION":
            tips.append("API advisory indicates CAUTION — consider a shorter swim and avoid exposed sections.")
        elif level == "LOW RISK":
            tips.append("API advisory indicates lower risk — still check wind, swell sets, and visibility before entering.")
        elif level == "NO DATA":
            tips.append("Limited API data available — rely more heavily on flags, local knowledge, and conditions on arrival.")

    deduped = []
    seen = set()
    for t in tips:
        if t not in seen:
            deduped.append(t)
            seen.add(t)

    return deduped[:4]


# ---- Register ----
ALLOWED_ROLES = {"swimmer", "lifeguard"}

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "swimmer").strip().lower()

        if not username or not password:
            flash("Please complete all fields.", "error")
            return redirect(url_for("register"))

        if role not in ALLOWED_ROLES:
            flash("Invalid account type selected.", "error")
            return redirect(url_for("register"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already in use. Please choose another.", "error")
            return redirect(url_for("register"))

        try:
            user = User(username=username, password=password, role=role)
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {e}", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


# ---- Auth ----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash("Logged in successfully.", "success")

            if user.role == "lifeguard":
                return redirect(url_for("lifeguard"))
            return redirect(url_for("swimmer"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---- Home ----
@app.route("/", methods=["GET"])
def home():
    return render_template("home.html", role=current_user_role())


# ---- Beaches directory + search ----
@app.route("/beaches", methods=["GET"])
def beaches():
    if not login_required():
        return redirect(url_for("login"))

    q = request.args.get("q", "").strip()
    county = request.args.get("county", "").strip()

    query = Beach.query
    if q:
        query = query.filter(Beach.name.ilike(f"%{q}%"))
    if county:
        query = query.filter(Beach.county == county)

    beaches_list = query.order_by(Beach.county.asc(), Beach.name.asc()).all()
    counties = [
        c[0] for c in db.session.query(Beach.county).distinct().order_by(Beach.county.asc()).all()
        if c[0]
    ]

    return render_template(
        "beaches.html",
        beaches=beaches_list,
        counties=counties,
        q=q,
        county=county,
        role=current_user_role()
    )


# ---- Beach detail page (single beach view) ----
@app.route("/beach/<int:beach_id>", methods=["GET"])
def beach_detail(beach_id):
    if not login_required():
        return redirect(url_for("login"))

    beach = Beach.query.get_or_404(beach_id)

    latest_report = (
        SeaReport.query.filter_by(beach_id=beach_id)
        .order_by(SeaReport.reported_at.desc())
        .first()
    )

    recent_reports = (
        SeaReport.query.filter_by(beach_id=beach_id)
        .order_by(SeaReport.reported_at.desc())
        .limit(10)
        .all()
    )

    # ==========================
    # Beach trends (last 7 days) from official reports (NEW)
    # ==========================
    since = datetime.utcnow() - timedelta(days=7)
    week_reports = (
        SeaReport.query
        .filter(SeaReport.beach_id == beach_id, SeaReport.reported_at >= since)
        .order_by(SeaReport.reported_at.desc())
        .all()
    )

    trend = {
        "count_7d": len(week_reports),
        "flag_green": sum(1 for r in week_reports if (r.flag_status or "") == "Green"),
        "flag_yellow": sum(1 for r in week_reports if (r.flag_status or "") == "Yellow"),
        "flag_red": sum(1 for r in week_reports if (r.flag_status or "") == "Red"),
        "avg_temp": None,
    }

    temps = []
    for r in week_reports:
        try:
            if r.temp_c is not None:
                temps.append(float(r.temp_c))
        except Exception:
            pass
    if temps:
        trend["avg_temp"] = round(sum(temps) / len(temps), 1)

    open_issues = (
        SwimmerIssue.query.filter_by(beach_id=beach_id, resolved=False)
        .order_by(SwimmerIssue.submitted_at.desc())
        .all()
    )

    photos = (
        BeachPhoto.query.filter_by(beach_id=beach_id)
        .order_by(BeachPhoto.uploaded_at.desc())
        .all()
    )

    return render_template(
        "beach_detail.html",
        beach=beach,
        latest_report=latest_report,
        reports=recent_reports,
        issues=open_issues,
        photos=photos,
        trend=trend,  # ✅ NEW
        role=current_user_role(),
        username=session.get("username")
    )


# ---- Serve uploaded files (kept behind login) ----
@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    if not login_required():
        return redirect(url_for("login"))
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---- Lifeguard uploads a photo for a beach ----
@app.post("/beach/<int:beach_id>/photo")
def upload_beach_photo(beach_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    beach = Beach.query.get_or_404(beach_id)

    f = request.files.get("photo")
    if not f or not f.filename:
        flash("No file selected.", "error")
        return redirect(url_for("beach_detail", beach_id=beach.id))

    if not allowed_file(f.filename):
        flash("Invalid file type. Use png/jpg/jpeg.", "error")
        return redirect(url_for("beach_detail", beach_id=beach.id))

    if not CLOUDINARY_ENABLED:
        flash("Cloudinary is not configured on Render (missing env vars).", "error")
        return redirect(url_for("beach_detail", beach_id=beach.id))

    try:
        res = cloudinary.uploader.upload(
            f,
            folder=f"swimsafe/beaches/{beach.id}",
            resource_type="image"
        )

        p = BeachPhoto(
            beach_id=beach.id,
            image_url=res.get("secure_url"),
            public_id=res.get("public_id"),
            uploaded_by=session.get("username"),
        )
        db.session.add(p)
        db.session.commit()
        flash("Photo uploaded.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error uploading photo: {e}", "error")

    return redirect(url_for("beach_detail", beach_id=beach.id))


# ================================
# --- SwimSafe: FAVOURITES ROUTES (NEW) ---
# ================================
@app.post("/favourite/<int:beach_id>/add")
def add_favourite(beach_id):
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        existing = FavoriteBeach.query.filter_by(user_id=uid, beach_id=beach_id).first()
        if existing:
            flash("Beach already in favourites.", "success")
            return redirect(url_for("swimmer"))

        fav = FavoriteBeach(user_id=uid, beach_id=beach_id)
        db.session.add(fav)
        db.session.commit()
        flash("Added to favourites.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding favourite: {e}", "error")

    return redirect(url_for("swimmer"))

@app.get("/admin/reset-beach-photos")
def admin_reset_beach_photos():
    # TEMP: remove after running once
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        BeachPhoto.__table__.drop(db.engine, checkfirst=True)
        db.create_all()
        return "✅ beach_photos dropped + recreated"
    except Exception as e:
        return f"❌ error: {e}", 500

@app.post("/favourite/<int:beach_id>/remove")
def remove_favourite(beach_id):
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        fav = FavoriteBeach.query.filter_by(user_id=uid, beach_id=beach_id).first()
        if fav:
            db.session.delete(fav)
            db.session.commit()
            flash("Removed from favourites.", "success")
        else:
            flash("Favourite not found.", "error")
    except Exception as e:
        db.session.rollback()
        flash(f"Error removing favourite: {e}", "error")

    return redirect(url_for("swimmer"))


# ================================
# --- SwimSafe: SESSION PLANNER ROUTES (UPDATED) ---
# ================================
@app.route("/swimmer/sessions", methods=["GET"])
def swimmer_sessions():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    beaches_list = Beach.query.order_by(Beach.name.asc()).all()

    now = datetime.utcnow()

    # ✅ joinedload() prevents extra queries when template accesses s.beach.*
    upcoming = (
        SwimSessionPlan.query
        .options(joinedload(SwimSessionPlan.beach))
        .filter(SwimSessionPlan.user_id == uid, SwimSessionPlan.planned_for >= now)
        .order_by(SwimSessionPlan.planned_for.asc())
        .limit(20)
        .all()
    )
    recent = (
        SwimSessionPlan.query
        .options(joinedload(SwimSessionPlan.beach))
        .filter(SwimSessionPlan.user_id == uid, SwimSessionPlan.planned_for < now)
        .order_by(SwimSessionPlan.planned_for.desc())
        .limit(10)
        .all()
    )

    # ✅ Training log outcomes for these sessions (NEW)
    session_ids = [s.id for s in upcoming] + [s.id for s in recent]
    outcomes = (
        SwimSessionOutcome.query
        .filter(SwimSessionOutcome.session_id.in_(session_ids))
        .all()
        if session_ids else []
    )
    outcome_by_session = {o.session_id: o for o in outcomes}

    # ✅ Session Safety (API) — for upcoming sessions only (NEW)
    # Light: cap + cache per beach+hour to reduce API calls
    safety_by_session = {}
    cache = {}  # (beach_id, hour_key) -> advisory dict

    for s in upcoming[:8]:
        try:
            b = s.beach
            if not b or b.latitude is None or b.longitude is None:
                safety_by_session[s.id] = None
                continue

            lat = float(b.latitude)
            lng = float(b.longitude)
            hour_key = s.planned_for.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H")
            key = (s.beach_id, hour_key)

            if key in cache:
                safety_by_session[s.id] = cache[key]
                continue

            api_data = get_marine_conditions_at(lat, lng, s.planned_for) or {}
            tide = compute_tide_assist(lat, lng, marine_data=api_data)

            if tide:
                api_data["tide_state"] = tide.get("tide_state", "")
                api_data["tide_strength"] = tide.get("tide_strength", "")
                api_data["tide_basis"] = tide.get("tide_basis", "")

            advisory = build_safety_advisory(api_data if api_data else None)
            cache[key] = advisory
            safety_by_session[s.id] = advisory

        except Exception:
            safety_by_session[s.id] = None

    return render_template(
        "swimmer_sessions.html",
        beaches=beaches_list,
        upcoming_sessions=upcoming,
        recent_sessions=recent,
        role=current_user_role(),
        username=session.get("username"),
        # ✅ NEW
        presets=SESSION_PRESETS,
        safety_by_session=safety_by_session,
        outcome_by_session=outcome_by_session,
    )


@app.post("/swimmer/sessions/create")
def create_swimmer_session():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        beach_id_raw = (request.form.get("beach_id") or "").strip()
        planned_for_str = (request.form.get("planned_for") or "").strip()

        if not beach_id_raw.isdigit() or not planned_for_str:
            flash("Please select a beach and date/time.", "error")
            return redirect(url_for("swimmer_sessions"))

        beach_id = int(beach_id_raw)

        planned_for = datetime.strptime(planned_for_str, "%Y-%m-%dT%H:%M")

        goal = (request.form.get("goal") or "Endurance").strip()
        intensity = (request.form.get("intensity") or "Easy").strip()
        skill_level = (request.form.get("skill_level") or "Intermediate").strip()

        duration_min_raw = (request.form.get("duration_min") or "").strip()
        distance_m_raw = (request.form.get("distance_m") or "").strip()
        notes = (request.form.get("notes") or "").strip()

        duration_min = int(duration_min_raw) if duration_min_raw.isdigit() else None
        distance_m = int(distance_m_raw) if distance_m_raw.isdigit() else None

        if duration_min is None and distance_m is None:
            flash("Add at least a duration (min) or distance (m) for the session.", "error")
            return redirect(url_for("swimmer_sessions"))

        b = Beach.query.get(beach_id)
        if not b:
            flash("Selected beach not found.", "error")
            return redirect(url_for("swimmer_sessions"))

        s = SwimSessionPlan(
            user_id=uid,
            beach_id=beach_id,
            planned_for=planned_for,
            goal=goal,
            duration_min=duration_min,
            distance_m=distance_m,
            intensity=intensity,
            skill_level=skill_level,
            notes=notes if notes else None,
        )
        db.session.add(s)
        db.session.commit()
        flash("Session planned successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error creating session: {e}", "error")

    return redirect(url_for("swimmer_sessions"))


@app.post("/swimmer/sessions/<int:session_id>/delete")
def delete_swimmer_session(session_id):
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        s = SwimSessionPlan.query.filter_by(id=session_id, user_id=uid).first()
        if not s:
            flash("Session not found.", "error")
            return redirect(url_for("swimmer_sessions"))

        # ✅ delete related outcome if it exists (keeps DB clean)
        o = SwimSessionOutcome.query.filter_by(session_id=s.id).first()
        if o:
            db.session.delete(o)

        db.session.delete(s)
        db.session.commit()
        flash("Session deleted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting session: {e}", "error")

    return redirect(url_for("swimmer_sessions"))


# ================================
# --- SwimSafe: TRAINING LOG ACTIONS (NEW) ---
# ================================
@app.post("/swimmer/sessions/<int:session_id>/complete")
def complete_swimmer_session(session_id):
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        s = SwimSessionPlan.query.filter_by(id=session_id, user_id=uid).first()
        if not s:
            flash("Session not found.", "error")
            return redirect(url_for("swimmer_sessions"))

        outcome = SwimSessionOutcome.query.filter_by(session_id=s.id).first()
        if not outcome:
            outcome = SwimSessionOutcome(session_id=s.id)
            db.session.add(outcome)

        outcome.status = "completed"
        outcome.completed_at = datetime.utcnow()

        rpe_raw = (request.form.get("rpe") or "").strip()
        dur_raw = (request.form.get("actual_duration_min") or "").strip()
        dist_raw = (request.form.get("actual_distance_m") or "").strip()
        notes = (request.form.get("outcome_notes") or "").strip()

        outcome.rpe = int(rpe_raw) if rpe_raw.isdigit() else None
        outcome.actual_duration_min = int(dur_raw) if dur_raw.isdigit() else None
        outcome.actual_distance_m = int(dist_raw) if dist_raw.isdigit() else None
        outcome.outcome_notes = notes if notes else None

        db.session.commit()
        flash("Session marked as completed.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating session outcome: {e}", "error")

    return redirect(url_for("swimmer_sessions"))


@app.post("/swimmer/sessions/<int:session_id>/skip")
def skip_swimmer_session(session_id):
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        s = SwimSessionPlan.query.filter_by(id=session_id, user_id=uid).first()
        if not s:
            flash("Session not found.", "error")
            return redirect(url_for("swimmer_sessions"))

        outcome = SwimSessionOutcome.query.filter_by(session_id=s.id).first()
        if not outcome:
            outcome = SwimSessionOutcome(session_id=s.id)
            db.session.add(outcome)

        outcome.status = "skipped"
        outcome.completed_at = datetime.utcnow()
        outcome.outcome_notes = (request.form.get("outcome_notes") or "").strip() or None

        db.session.commit()
        flash("Session marked as skipped.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating session outcome: {e}", "error")

    return redirect(url_for("swimmer_sessions"))


# ---- Swimmer page (view/filter reports + submit issues) ----
@app.route("/swimmer", methods=["GET"])
def swimmer():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    beaches_list = Beach.query.order_by(Beach.name.asc()).all()
    beach_id = request.args.get("beach_id", "").strip()

    report_query = SeaReport.query.order_by(SeaReport.reported_at.desc())
    if beach_id.isdigit():
        report_query = report_query.filter(SeaReport.beach_id == int(beach_id))

    reports = report_query.limit(20).all()

    latest_report = reports[0] if reports else None

    api_data = None
    tide = None
    advisory = None
    swimmer_tips = []

    primary_beach = _pick_primary_beach_for_swimmer(beach_id, reports, beaches_list)

    if primary_beach and primary_beach.latitude is not None and primary_beach.longitude is not None:
        try:
            lat = float(primary_beach.latitude)
            lng = float(primary_beach.longitude)

            api_data = get_marine_conditions(lat, lng)
            tide = compute_tide_assist(lat, lng, marine_data=api_data)

            if api_data is None:
                api_data = {}

            if tide:
                api_data["tide_state"] = tide.get("tide_state", "")
                api_data["tide_strength"] = tide.get("tide_strength", "")
                api_data["tide_basis"] = tide.get("tide_basis", "")

            advisory = build_safety_advisory(api_data if api_data else None)
            swimmer_tips = _swimmer_context_tips(latest_report, advisory, tide)
        except Exception:
            api_data = None
            tide = None
            advisory = None
            swimmer_tips = []

    kpis = {
        "report_count": len(reports),
        "beach_count": len(beaches_list),
        "latest_report_time": latest_report.reported_at.strftime("%Y-%m-%d %H:%M") if latest_report else "—",
    }

    uid = session.get("user_id")
    favourites = []
    favourite_beach_ids = set()

    if uid:
        favourites = (
            FavoriteBeach.query
            .filter_by(user_id=uid)
            .join(Beach, FavoriteBeach.beach_id == Beach.id)
            .order_by(Beach.name.asc())
            .all()
        )
        favourite_beach_ids = {f.beach_id for f in favourites}

    now = datetime.utcnow()
    upcoming_count = (
        SwimSessionPlan.query
        .filter(SwimSessionPlan.user_id == uid, SwimSessionPlan.planned_for >= now)
        .count()
        if uid else 0
    )

    return render_template(
        "swimmer.html",
        beaches=beaches_list,
        reports=reports,
        role=current_user_role(),
        selected_beach_id=beach_id,
        latest_report=latest_report,
        api_data=api_data,
        tide=tide,
        advisory=advisory,
        swimmer_tips=swimmer_tips,
        kpis=kpis,
        username=session.get("username"),
        primary_beach=primary_beach,
        favourites=favourites,
        favourite_beach_ids=favourite_beach_ids,
        upcoming_count=upcoming_count,
    )


# ---- Lifeguard dashboard ----
@app.route("/lifeguard", methods=["GET"])
def lifeguard():
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    beaches_list = Beach.query.order_by(Beach.name.asc()).all()
    reports = SeaReport.query.order_by(SeaReport.reported_at.desc()).limit(20).all()
    issues = SwimmerIssue.query.filter_by(resolved=False).order_by(SwimmerIssue.submitted_at.desc()).all()

    api_data = None
    selected_beach_id = request.args.get("beach_id", "").strip()
    advisory = None

    if selected_beach_id.isdigit():
        b = Beach.query.get(int(selected_beach_id))
        if b and b.latitude is not None and b.longitude is not None:
            lat = float(b.latitude)
            lng = float(b.longitude)

            api_data = get_marine_conditions(lat, lng)
            tide = compute_tide_assist(lat, lng, marine_data=api_data)

            if api_data is None:
                api_data = {}

            if tide:
                api_data["tide_state"] = tide.get("tide_state", "")
                api_data["tide_strength"] = tide.get("tide_strength", "")
                api_data["tide_basis"] = tide.get("tide_basis", "")

            advisory = build_safety_advisory(api_data if api_data else None)
        else:
            flash("Selected beach has no latitude/longitude saved.", "error")

    return render_template(
        "lifeguard.html",
        beaches=beaches_list,
        reports=reports,
        issues=issues,
        role=current_user_role(),
        api_data=api_data,
        selected_beach_id=selected_beach_id,
        advisory=advisory
    )


# ---- Lifeguard: create report ----
@app.route("/report", methods=["POST"])
def create_report():
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        beach_id = int(request.form.get("beach_id"))
        tide = request.form.get("tide") or None
        temp_raw = request.form.get("temp_c")
        temp_c = float(temp_raw) if temp_raw else None
        flag_status = request.form.get("flag_status") or None
        notes = request.form.get("notes") or None

        advisory_level = request.form.get("advisory_level")

        if advisory_level:
            advisory_text = f"[API ADVISORY: {advisory_level}]"
            if notes:
                if advisory_text not in notes:
                    notes = notes + "\n" + advisory_text
            else:
                notes = advisory_text

        tide_strength = (request.form.get("tide_strength") or "").strip()
        if tide_strength:
            tide_text = f"[TIDE STRENGTH: {tide_strength}]"
            if notes:
                if tide_text not in notes:
                    notes = notes + "\n" + tide_text
            else:
                notes = tide_text

        report = SeaReport(
            beach_id=beach_id,
            tide=tide,
            temp_c=temp_c,
            flag_status=flag_status,
            notes=notes,
        )
        db.session.add(report)
        db.session.commit()
        flash("Sea report saved.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error saving report: {e}", "error")

    return redirect(url_for("lifeguard"))


# ---- Lifeguard: delete report ----
@app.post("/report/<int:report_id>/delete")
def delete_report(report_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        report = SeaReport.query.get(report_id)
        if not report:
            flash("Report not found.", "error")
            return redirect(url_for("lifeguard"))
        db.session.delete(report)
        db.session.commit()
        flash("Report deleted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting report: {e}", "error")

    return redirect(url_for("lifeguard"))


# ---- Lifeguard: edit/update report ----
@app.route("/report/<int:report_id>/edit", methods=["GET", "POST"])
def edit_report(report_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    report = SeaReport.query.get_or_404(report_id)
    beaches_list = Beach.query.order_by(Beach.name.asc()).all()

    if request.method == "POST":
        try:
            report.beach_id = int(request.form.get("beach_id"))
            report.tide = request.form.get("tide") or None

            temp_raw = request.form.get("temp_c")
            report.temp_c = float(temp_raw) if temp_raw else None

            report.flag_status = request.form.get("flag_status") or None
            report.notes = request.form.get("notes") or None

            db.session.commit()
            flash("Report updated.", "success")
            return redirect(url_for("lifeguard"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating report: {e}", "error")

    return render_template(
        "edit_report.html",
        report=report,
        beaches=beaches_list,
        role=current_user_role()
    )


# ---- Swimmer submits issue ----
@app.post("/issue")
def create_issue():
    if not login_required():
        return redirect(url_for("login"))

    try:
        beach_id = int(request.form.get("issue_beach_id"))
        issue_type = request.form.get("issue_type") or None
        description = request.form.get("issue_desc") or None

        issue = SwimmerIssue(
            beach_id=beach_id,
            issue_type=issue_type,
            description=description
        )
        db.session.add(issue)
        db.session.commit()
        flash("Issue submitted for lifeguard review.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error submitting issue: {e}", "error")

    return redirect(url_for("swimmer"))


# ---- Lifeguard resolves issue ----
@app.post("/issue/<int:issue_id>/resolve")
def resolve_issue(issue_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        issue = SwimmerIssue.query.get(issue_id)
        if not issue:
            flash("Issue not found.", "error")
            return redirect(url_for("lifeguard"))
        issue.resolved = True
        db.session.commit()
        flash("Issue marked as resolved.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error resolving issue: {e}", "error")

    return redirect(url_for("lifeguard"))


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)





