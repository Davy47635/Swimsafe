# Some of the route structure and wording were helped by ChatGPT.
# Final code decisions, testing, and database setup were done by me.
# Reference: Flask Documentation - Routing, Templates & Sessions (2025)
# Reference: SQLAlchemy ORM Tutorial (2025)

from collections import Counter
from datetime import datetime, timedelta
import json
import os
import requests
from typing import Optional, Dict, Any  # ✅ Python 3.9-compatible typing

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename  # (safe to keep even if unused)

# ✅ NEW: for eager loading (prevents N+1 queries in templates)
from sqlalchemy.orm import joinedload

# ================================
# ✅ CLOUDINARY (Production Image Storage)
# ================================
import cloudinary
import cloudinary.uploader
import cloudinary.api

CLOUDINARY_URL = (os.getenv("CLOUDINARY_URL") or "").strip()

if CLOUDINARY_URL:
    os.environ["CLOUDINARY_URL"] = CLOUDINARY_URL
    cloudinary.config(secure=True)
    CLOUDINARY_ENABLED = True
else:
    CLOUDINARY_ENABLED = False

print("Cloudinary configured:", CLOUDINARY_ENABLED)

# ================================
# FLASK APP SETUP
# ================================

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

# ================================
# DATABASE CONFIG (PostgreSQL)
# ================================

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    DB_USER = "postgres"
    DB_PASS = ""
    DB_HOST = "127.0.0.1"
    DB_PORT = "5432"
    DB_NAME = "swimsafe"
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
print("DB URI =", app.config["SQLALCHEMY_DATABASE_URI"])

db = SQLAlchemy(app)

# ================================
# STORMGLASS API
# ================================

STORMGLASS_API_KEY = os.getenv("STORMGLASS_API_KEY", "").strip()
print("Stormglass key loaded:", bool(STORMGLASS_API_KEY))

STORMGLASS_ENDPOINT = "https://api.stormglass.io/v2/weather/point"
STORMGLASS_TIDE_SEA_LEVEL_ENDPOINT = "https://api.stormglass.io/v2/tide/sea-level/point"
STORMGLASS_TIDE_EXTREMES_ENDPOINT = "https://api.stormglass.io/v2/tide/extremes/point"

# ================================
# UPLOADS
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
# SESSION PRESETS
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


# ================================
# MODELS
# ================================

class Beach(db.Model):
    __tablename__ = "beaches"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    county = db.Column(db.String(100))
    latitude = db.Column(db.Numeric(9, 6))
    longitude = db.Column(db.Numeric(9, 6))

    address_line1 = db.Column(db.String(160))
    address_line2 = db.Column(db.String(160))
    town = db.Column(db.String(120))
    postcode = db.Column(db.String(20))
    country = db.Column(db.String(60))

    parking_info = db.Column(db.Text)
    facilities = db.Column(db.Text)
    access_notes = db.Column(db.Text)
    safety_notes = db.Column(db.Text)
    emergency_access = db.Column(db.Text)

    maps_url = db.Column(db.String(500))
    website_url = db.Column(db.String(500))


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
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)


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


class SwimSessionPlan(db.Model):
    __tablename__ = "swim_session_plans"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)

    planned_for = db.Column(db.DateTime, nullable=False)

    goal = db.Column(db.String(80), nullable=False, default="Endurance")
    duration_min = db.Column(db.Integer)
    distance_m = db.Column(db.Integer)
    intensity = db.Column(db.String(30), default="Easy")
    skill_level = db.Column(db.String(30), default="Intermediate")

    notes = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User")
    beach = db.relationship("Beach")

    __table_args__ = (
        db.Index("ix_swim_session_user_time", "user_id", "planned_for"),
    )


class SwimSessionOutcome(db.Model):
    __tablename__ = "swim_session_outcomes"
    id = db.Column(db.Integer, primary_key=True)

    session_id = db.Column(db.Integer, db.ForeignKey("swim_session_plans.id"), nullable=False, unique=True)

    status = db.Column(db.String(20), nullable=False, default="planned")

    rpe = db.Column(db.Integer)
    actual_duration_min = db.Column(db.Integer)
    actual_distance_m = db.Column(db.Integer)
    outcome_notes = db.Column(db.String(255))

    completed_at = db.Column(db.DateTime)

    session = db.relationship("SwimSessionPlan")


class BeachPhoto(db.Model):
    __tablename__ = "beach_photos"
    id = db.Column(db.Integer, primary_key=True)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)

    image_url = db.Column(db.String(500), nullable=False)
    public_id = db.Column(db.String(255), nullable=True)

    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    uploaded_by = db.Column(db.String(100))

    beach = db.relationship("Beach")


# ================================
# NEW MODELS
# ================================

class Notification(db.Model):
    __tablename__ = "notifications"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    beach_id   = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)
    message    = db.Column(db.String(255), nullable=False)
    is_read    = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user  = db.relationship("User")
    beach = db.relationship("Beach")

    __table_args__ = (
        db.Index("ix_notif_user_read", "user_id", "is_read"),
    )


class BeachVideo(db.Model):
    __tablename__ = "beach_videos"
    id          = db.Column(db.Integer, primary_key=True)
    beach_id    = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=True)
    video_url   = db.Column(db.String(500), nullable=False)
    public_id   = db.Column(db.String(255), nullable=True)
    title       = db.Column(db.String(150), nullable=False, default="")
    video_type  = db.Column(db.String(20), nullable=False, default="beach")  # "beach" or "swimming"
    uploaded_by = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    beach = db.relationship("Beach", foreign_keys=[beach_id])

    __table_args__ = (
        db.Index("ix_beach_videos_beach", "beach_id"),
        db.Index("ix_beach_videos_type",  "video_type"),
    )


# ================================
# CONTEXT PROCESSOR — unread notification count
# ================================

@app.context_processor
def inject_unread_count():
    uid  = session.get("user_id")
    role = session.get("role")
    if uid and role == "swimmer":
        try:
            count = Notification.query.filter_by(user_id=uid, is_read=False).count()
            return {"unread_count": count}
        except Exception:
            return {"unread_count": 0}
    return {"unread_count": 0}


# ================================
# HELPERS
# ================================

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
    uid = session.get("user_id")
    if not uid:
        flash("Please log in again.", "error")
        return None
    return uid


def _clean_text(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    if len(v) > max_len:
        v = v[:max_len]
    return v


def _safe_http_url(value: Optional[str], max_len: int = 500) -> Optional[str]:
    v = _clean_text(value, max_len=max_len)
    if not v:
        return None
    if v.startswith("http://") or v.startswith("https://"):
        return v
    return None


def _safe_hour_value(hour: dict, key: str):
    try:
        data = hour.get(key)
        if not isinstance(data, dict):
            return None
        if "sg" in data:
            return data["sg"]
        return next(iter(data.values()), None)
    except Exception:
        return None


def _stormglass_headers():
    return {"Authorization": STORMGLASS_API_KEY}


def _utc_hour_str(dt: datetime) -> str:
    dt2 = dt.replace(minute=0, second=0, microsecond=0)
    return dt2.strftime("%Y-%m-%dT%H")


def _to_float(x):
    try:
        return float(x)
    except Exception:
        return None


def _notify_favourites_of_report(beach_id: int, flag_status: Optional[str], notes: Optional[str]):
    """Create in-app notifications for swimmers who have favourited this beach."""
    try:
        favs = FavoriteBeach.query.filter_by(beach_id=beach_id).all()
        if not favs:
            return

        beach = Beach.query.get(beach_id)
        beach_name = beach.name if beach else f"Beach #{beach_id}"

        flag_part = f" — Flag: {flag_status}" if flag_status else ""
        msg = f"New report for {beach_name}{flag_part}."
        if notes:
            short = notes[:80] + ("…" if len(notes) > 80 else "")
            msg += f" Notes: {short}"

        msg = msg[:255]

        for fav in favs:
            notif = Notification(
                user_id=fav.user_id,
                beach_id=beach_id,
                message=msg,
            )
            db.session.add(notif)

        db.session.commit()
    except Exception:
        db.session.rollback()


def get_marine_conditions(lat: float, lng: float):
    if not STORMGLASS_API_KEY:
        return None

    params = ",".join([
        "waveHeight", "waveDirection", "wavePeriod",
        "swellHeight", "swellDirection",
        "windSpeed", "windDirection",
        "waterTemperature", "currentSpeed", "currentDirection",
    ])

    now = datetime.utcnow()
    start = int(now.timestamp())
    end = int((now + timedelta(hours=1)).timestamp())

    try:
        r = requests.get(
            STORMGLASS_ENDPOINT,
            params={"lat": lat, "lng": lng, "params": params, "source": "noaa", "start": start, "end": end},
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
            "wave_height":     _safe_hour_value(hour0, "waveHeight"),
            "wave_direction":  _safe_hour_value(hour0, "waveDirection"),
            "wave_period":     _safe_hour_value(hour0, "wavePeriod"),
            "swell_height":    _safe_hour_value(hour0, "swellHeight"),
            "swell_direction": _safe_hour_value(hour0, "swellDirection"),
            "wind_speed":      _safe_hour_value(hour0, "windSpeed"),
            "wind_direction":  _safe_hour_value(hour0, "windDirection"),
            "water_temp":      _safe_hour_value(hour0, "waterTemperature"),
            "current_speed":   _safe_hour_value(hour0, "currentSpeed"),
            "current_direction": _safe_hour_value(hour0, "currentDirection"),
            "time": hour0.get("time"),
        }

    except Exception:
        return None


def get_marine_conditions_at(lat: float, lng: float, when_dt: datetime):
    if not STORMGLASS_API_KEY:
        return None

    params = ",".join([
        "waveHeight", "waveDirection", "wavePeriod",
        "swellHeight", "swellDirection",
        "windSpeed", "windDirection",
        "waterTemperature", "currentSpeed", "currentDirection",
    ])

    dt = when_dt.replace(minute=0, second=0, microsecond=0)
    start = int((dt - timedelta(hours=1)).timestamp())
    end = int((dt + timedelta(hours=1)).timestamp())

    try:
        r = requests.get(
            STORMGLASS_ENDPOINT,
            params={"lat": lat, "lng": lng, "params": params, "source": "noaa", "start": start, "end": end},
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
            "wave_height":     _safe_hour_value(best, "waveHeight"),
            "wave_direction":  _safe_hour_value(best, "waveDirection"),
            "wave_period":     _safe_hour_value(best, "wavePeriod"),
            "swell_height":    _safe_hour_value(best, "swellHeight"),
            "swell_direction": _safe_hour_value(best, "swellDirection"),
            "wind_speed":      _safe_hour_value(best, "windSpeed"),
            "wind_direction":  _safe_hour_value(best, "windDirection"),
            "water_temp":      _safe_hour_value(best, "waterTemperature"),
            "current_speed":   _safe_hour_value(best, "currentSpeed"),
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
            params={"lat": lat, "lng": lng, "start": _utc_hour_str(start_dt), "end": _utc_hour_str(end_dt), "datum": datum},
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
            params={"lat": lat, "lng": lng, "start": _utc_hour_str(start_dt), "end": _utc_hour_str(end_dt), "datum": datum},
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


def compute_tide_assist(lat: float, lng: float, marine_data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, str]]:
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
                    nearest = {"diff": diff, "type": (e.get("type") or "").lower(), "time": t_str, "height": e.get("height")}
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
        "tide_state":    tide_state or "",
        "tide_strength": tide_strength or "",
        "tide_basis":    tide_basis or "",
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

    unsafe_hit  = any("unsafe threshold" in r for r in reasons)
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
        "level":       level,
        "level_class": level_class,
        "reasons":     reasons if reasons else ["Conditions are within basic low-risk thresholds."]
    }


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


def _swimmer_context_tips(latest_report, advisory, tide):
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
        state    = (tide.get("tide_state") or "").strip().lower()
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


# ================================
# ROUTES — Auth
# ================================

ALLOWED_ROLES = {"swimmer", "lifeguard"}

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role     = request.form.get("role", "swimmer").strip().lower()

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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"]     = user.role
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


# ================================
# ROUTES — Pages
# ================================

@app.route("/", methods=["GET"])
def home():
    return render_template("home.html", role=current_user_role())


@app.route("/beaches", methods=["GET"])
def beaches():
    if not login_required():
        return redirect(url_for("login"))

    q      = request.args.get("q", "").strip()
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

    since = datetime.utcnow() - timedelta(days=7)
    week_reports = (
        SeaReport.query
        .filter(SeaReport.beach_id == beach_id, SeaReport.reported_at >= since)
        .order_by(SeaReport.reported_at.desc())
        .all()
    )

    trend = {
        "count_7d":   len(week_reports),
        "flag_green":  sum(1 for r in week_reports if (r.flag_status or "") == "Green"),
        "flag_yellow": sum(1 for r in week_reports if (r.flag_status or "") == "Yellow"),
        "flag_red":    sum(1 for r in week_reports if (r.flag_status or "") == "Red"),
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

    # NEW: beach videos
    videos = (
        BeachVideo.query.filter_by(beach_id=beach_id, video_type="beach")
        .order_by(BeachVideo.uploaded_at.desc())
        .all()
    )

    return render_template(
        "beach_detail.html",
        beach=beach,
        latest_report=latest_report,
        reports=recent_reports,
        issues=open_issues,
        photos=photos,
        videos=videos,
        trend=trend,
        role=current_user_role(),
        username=session.get("username")
    )


@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    if not login_required():
        return redirect(url_for("login"))
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ================================
# ROUTES — Photos
# ================================

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
        flash("Cloudinary is not configured (CLOUDINARY_URL missing).", "error")
        return redirect(url_for("beach_detail", beach_id=beach.id))

    try:
        res = cloudinary.uploader.upload(f, folder=f"swimsafe/beaches/{beach.id}", resource_type="image")

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


@app.post("/photos/<int:photo_id>/delete")
def delete_beach_photo(photo_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        photo = BeachPhoto.query.get(photo_id)
        if not photo:
            flash("Photo not found.", "error")
            return redirect(url_for("beaches"))

        beach_id = photo.beach_id

        if CLOUDINARY_ENABLED and photo.public_id:
            cloudinary.uploader.destroy(photo.public_id, resource_type="image")

        db.session.delete(photo)
        db.session.commit()
        flash("Photo deleted.", "success")

        return redirect(url_for("beach_detail", beach_id=beach_id))

    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting photo: {e}", "error")
        return redirect(url_for("beaches"))


@app.get("/admin/reset-beach-photos")
def admin_reset_beach_photos():
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        BeachPhoto.__table__.drop(db.engine, checkfirst=True)
        db.create_all()
        return "✅ beach_photos dropped + recreated"
    except Exception as e:
        return f"❌ error: {e}", 500


# ================================
# ROUTES — Videos (NEW)
# ================================

@app.post("/beach/<int:beach_id>/video")
def upload_beach_video(beach_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    beach = Beach.query.get_or_404(beach_id)
    f     = request.files.get("video")
    title = _clean_text(request.form.get("title"), 150) or "Beach video"

    if not f or not f.filename:
        flash("No file selected.", "error")
        return redirect(url_for("beach_detail", beach_id=beach.id))

    if not CLOUDINARY_ENABLED:
        flash("Cloudinary is not configured (CLOUDINARY_URL missing).", "error")
        return redirect(url_for("beach_detail", beach_id=beach.id))

    try:
        res = cloudinary.uploader.upload(f, folder=f"swimsafe/beaches/{beach.id}/videos", resource_type="video")

        v = BeachVideo(
            beach_id=beach.id,
            video_url=res.get("secure_url"),
            public_id=res.get("public_id"),
            title=title,
            video_type="beach",
            uploaded_by=session.get("username"),
        )
        db.session.add(v)
        db.session.commit()
        flash("Video uploaded.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error uploading video: {e}", "error")

    return redirect(url_for("beach_detail", beach_id=beach.id))


@app.post("/videos/<int:video_id>/delete")
def delete_beach_video(video_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        v = BeachVideo.query.get(video_id)
        if not v:
            flash("Video not found.", "error")
            return redirect(url_for("beaches"))

        redirect_to = url_for("beach_detail", beach_id=v.beach_id) if v.beach_id else url_for("swimming_videos")

        if CLOUDINARY_ENABLED and v.public_id:
            cloudinary.uploader.destroy(v.public_id, resource_type="video")

        db.session.delete(v)
        db.session.commit()
        flash("Video deleted.", "success")
        return redirect(redirect_to)

    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting video: {e}", "error")
        return redirect(url_for("beaches"))


@app.route("/videos", methods=["GET"])
def swimming_videos():
    if not login_required():
        return redirect(url_for("login"))

    videos = (
        BeachVideo.query
        .filter_by(video_type="swimming")
        .order_by(BeachVideo.uploaded_at.desc())
        .all()
    )

    return render_template(
        "swimming_videos.html",
        videos=videos,
        role=current_user_role(),
        username=session.get("username"),
    )


@app.post("/videos/upload-swimming")
def upload_swimming_video():
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    f     = request.files.get("video")
    title = _clean_text(request.form.get("title"), 150) or "Open water swimming video"

    if not f or not f.filename:
        flash("No file selected.", "error")
        return redirect(url_for("swimming_videos"))

    if not CLOUDINARY_ENABLED:
        flash("Cloudinary is not configured (CLOUDINARY_URL missing).", "error")
        return redirect(url_for("swimming_videos"))

    try:
        res = cloudinary.uploader.upload(f, folder="swimsafe/swimming_videos", resource_type="video")

        v = BeachVideo(
            beach_id=None,
            video_url=res.get("secure_url"),
            public_id=res.get("public_id"),
            title=title,
            video_type="swimming",
            uploaded_by=session.get("username"),
        )
        db.session.add(v)
        db.session.commit()
        flash("Swimming video uploaded.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error uploading video: {e}", "error")

    return redirect(url_for("swimming_videos"))


# ================================
# ROUTES — Notifications (NEW)
# ================================

@app.get("/notifications")
def notifications_page():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    notifs = (
        Notification.query
        .filter_by(user_id=uid)
        .order_by(Notification.created_at.desc())
        .limit(60)
        .all()
    )

    try:
        Notification.query.filter_by(user_id=uid, is_read=False).update({"is_read": True})
        db.session.commit()
    except Exception:
        db.session.rollback()

    return render_template(
        "notifications.html",
        notifications=notifs,
        role=current_user_role(),
        username=session.get("username"),
    )


@app.post("/notifications/<int:notif_id>/read")
def mark_notification_read(notif_id):
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        n = Notification.query.filter_by(id=notif_id, user_id=uid).first()
        if n:
            n.is_read = True
            db.session.commit()
    except Exception:
        db.session.rollback()

    return redirect(url_for("notifications_page"))


@app.post("/notifications/read-all")
def mark_all_notifications_read():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    try:
        Notification.query.filter_by(user_id=uid, is_read=False).update({"is_read": True})
        db.session.commit()
        flash("All notifications marked as read.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error: {e}", "error")

    return redirect(url_for("notifications_page"))


# ================================
# ROUTES — Trend Analysis (NEW)
# ================================

@app.route("/beach/<int:beach_id>/trends", methods=["GET"])
def beach_trends(beach_id):
    if not login_required():
        return redirect(url_for("login"))

    beach = Beach.query.get_or_404(beach_id)

    all_reports = (
        SeaReport.query
        .filter_by(beach_id=beach_id)
        .order_by(SeaReport.reported_at.asc())
        .all()
    )

    labels      = []
    temps       = []
    flags       = []
    flag_colors = []

    FLAG_MAP = {"green": 1, "yellow": 2, "amber": 2, "red": 3}
    FLAG_COLOR_MAP = {
        "green":  "rgba(34,197,94,0.85)",
        "yellow": "rgba(251,191,36,0.85)",
        "amber":  "rgba(251,191,36,0.85)",
        "red":    "rgba(239,68,68,0.85)",
    }

    for r in all_reports:
        labels.append(r.reported_at.strftime("%Y-%m-%d %H:%M"))
        temps.append(float(r.temp_c) if r.temp_c is not None else None)
        flag_lower = (r.flag_status or "").lower()
        flags.append(FLAG_MAP.get(flag_lower, 0))
        flag_colors.append(FLAG_COLOR_MAP.get(flag_lower, "rgba(148,163,184,0.6)"))

    total        = len(all_reports)
    green_count  = sum(1 for r in all_reports if (r.flag_status or "").lower() == "green")
    yellow_count = sum(1 for r in all_reports if (r.flag_status or "").lower() in {"yellow", "amber"})
    red_count    = sum(1 for r in all_reports if (r.flag_status or "").lower() == "red")

    valid_temps = [float(r.temp_c) for r in all_reports if r.temp_c is not None]
    avg_temp = round(sum(valid_temps) / len(valid_temps), 1) if valid_temps else None
    min_temp = round(min(valid_temps), 1) if valid_temps else None
    max_temp = round(max(valid_temps), 1) if valid_temps else None

    wave_labels  = []
    wave_heights = []
    for r in all_reports[-30:]:
        if r.notes and "Wave:" in r.notes:
            try:
                part = r.notes.split("Wave:")[1].split("m")[0].strip()
                wh = float(part)
                wave_labels.append(r.reported_at.strftime("%Y-%m-%d %H:%M"))
                wave_heights.append(wh)
            except Exception:
                pass

    chart_data = {
        "labels":       json.dumps(labels),
        "temps":        json.dumps(temps),
        "flags":        json.dumps(flags),
        "flag_colors":  json.dumps(flag_colors),
        "wave_labels":  json.dumps(wave_labels),
        "wave_heights": json.dumps(wave_heights),
    }

    return render_template(
        "beach_trends.html",
        beach=beach,
        all_reports=all_reports,
        total=total,
        green_count=green_count,
        yellow_count=yellow_count,
        red_count=red_count,
        avg_temp=avg_temp,
        min_temp=min_temp,
        max_temp=max_temp,
        chart_data=chart_data,
        role=current_user_role(),
        username=session.get("username"),
    )


# ================================
# ROUTES — Swimmer Stats (NEW)
# ================================

@app.route("/swimmer/stats", methods=["GET"])
def swimmer_stats():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    uid = _require_user_id()
    if uid is None:
        return redirect(url_for("login"))

    all_plans = (
        SwimSessionPlan.query
        .filter_by(user_id=uid)
        .order_by(SwimSessionPlan.planned_for.asc())
        .all()
    )

    plan_ids = [p.id for p in all_plans]

    outcomes = (
        SwimSessionOutcome.query
        .filter(SwimSessionOutcome.session_id.in_(plan_ids))
        .all()
        if plan_ids else []
    )
    outcome_map = {o.session_id: o for o in outcomes}

    total_planned   = len(all_plans)
    completed_count = sum(1 for o in outcomes if o.status == "completed")
    skipped_count   = sum(1 for o in outcomes if o.status == "skipped")

    total_distance = sum(
        (o.actual_distance_m or 0)
        for o in outcomes if o.status == "completed" and o.actual_distance_m
    )
    total_duration = sum(
        (o.actual_duration_min or 0)
        for o in outcomes if o.status == "completed" and o.actual_duration_min
    )

    rpe_values = [o.rpe for o in outcomes if o.status == "completed" and o.rpe]
    avg_rpe = round(sum(rpe_values) / len(rpe_values), 1) if rpe_values else None

    beach_counter     = Counter(p.beach_id for p in all_plans)
    fav_beach_id      = beach_counter.most_common(1)[0][0] if beach_counter else None
    fav_beach         = Beach.query.get(fav_beach_id) if fav_beach_id else None

    goal_counter      = dict(Counter(p.goal for p in all_plans))
    intensity_counter = dict(Counter(p.intensity for p in all_plans))

    completed_sessions = [
        (outcome_map[p.id], p)
        for p in all_plans
        if p.id in outcome_map and outcome_map[p.id].status == "completed"
    ]
    completed_sessions.sort(key=lambda x: x[1].planned_for)
    last_20 = completed_sessions[-20:]

    chart_labels   = json.dumps([p.planned_for.strftime("%Y-%m-%d") for _, p in last_20])
    chart_distance = json.dumps([o.actual_distance_m or 0 for o, _ in last_20])
    chart_duration = json.dumps([o.actual_duration_min or 0 for o, _ in last_20])
    chart_rpe      = json.dumps([o.rpe or 0 for o, _ in last_20])

    recent_completed = list(reversed(last_20[-10:]))

    return render_template(
        "swimmer_stats.html",
        role=current_user_role(),
        username=session.get("username"),
        total_planned=total_planned,
        completed_count=completed_count,
        skipped_count=skipped_count,
        total_distance=total_distance,
        total_duration=total_duration,
        avg_rpe=avg_rpe,
        fav_beach=fav_beach,
        goal_counter=goal_counter,
        intensity_counter=intensity_counter,
        chart_labels=chart_labels,
        chart_distance=chart_distance,
        chart_duration=chart_duration,
        chart_rpe=chart_rpe,
        recent_completed=recent_completed,
        outcome_map=outcome_map,
    )


# ================================
# ROUTES — Favourites
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
# ROUTES — Session Planner
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

    session_ids = [s.id for s in upcoming] + [s.id for s in recent]
    outcomes = (
        SwimSessionOutcome.query
        .filter(SwimSessionOutcome.session_id.in_(session_ids))
        .all()
        if session_ids else []
    )
    outcome_by_session = {o.session_id: o for o in outcomes}

    safety_by_session = {}
    cache = {}

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
            tide     = compute_tide_assist(lat, lng, marine_data=api_data)

            if tide:
                api_data["tide_state"]    = tide.get("tide_state", "")
                api_data["tide_strength"] = tide.get("tide_strength", "")
                api_data["tide_basis"]    = tide.get("tide_basis", "")

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
        beach_id_raw    = (request.form.get("beach_id") or "").strip()
        planned_for_str = (request.form.get("planned_for") or "").strip()

        if not beach_id_raw.isdigit() or not planned_for_str:
            flash("Please select a beach and date/time.", "error")
            return redirect(url_for("swimmer_sessions"))

        beach_id   = int(beach_id_raw)
        planned_for = datetime.strptime(planned_for_str, "%Y-%m-%dT%H:%M")

        goal        = (request.form.get("goal") or "Endurance").strip()
        intensity   = (request.form.get("intensity") or "Easy").strip()
        skill_level = (request.form.get("skill_level") or "Intermediate").strip()

        duration_min_raw = (request.form.get("duration_min") or "").strip()
        distance_m_raw   = (request.form.get("distance_m") or "").strip()
        notes            = (request.form.get("notes") or "").strip()

        duration_min = int(duration_min_raw) if duration_min_raw.isdigit() else None
        distance_m   = int(distance_m_raw)   if distance_m_raw.isdigit()   else None

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

        outcome.status       = "completed"
        outcome.completed_at = datetime.utcnow()

        rpe_raw  = (request.form.get("rpe") or "").strip()
        dur_raw  = (request.form.get("actual_duration_min") or "").strip()
        dist_raw = (request.form.get("actual_distance_m") or "").strip()
        notes    = (request.form.get("outcome_notes") or "").strip()

        outcome.rpe                = int(rpe_raw)  if rpe_raw.isdigit()  else None
        outcome.actual_duration_min = int(dur_raw)  if dur_raw.isdigit()  else None
        outcome.actual_distance_m   = int(dist_raw) if dist_raw.isdigit() else None
        outcome.outcome_notes       = notes if notes else None

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

        outcome.status        = "skipped"
        outcome.completed_at  = datetime.utcnow()
        outcome.outcome_notes = (request.form.get("outcome_notes") or "").strip() or None

        db.session.commit()
        flash("Session marked as skipped.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating session outcome: {e}", "error")

    return redirect(url_for("swimmer_sessions"))


# ================================
# ROUTES — Beach Info
# ================================

@app.route("/beach/<int:beach_id>/info", methods=["GET"])
def beach_info(beach_id):
    if not login_required():
        return redirect(url_for("login"))

    beach = Beach.query.get_or_404(beach_id)
    return render_template("beach_info.html", beach=beach, role=current_user_role())


@app.route("/lifeguard/beach/<int:beach_id>/edit-info", methods=["GET", "POST"])
def lifeguard_edit_beach_info(beach_id):
    if not login_required("lifeguard"):
        flash("Lifeguard access required.", "error")
        return redirect(url_for("login"))

    beach = Beach.query.get_or_404(beach_id)

    if request.method == "POST":
        beach.address_line1 = _clean_text(request.form.get("address_line1"), 160)
        beach.address_line2 = _clean_text(request.form.get("address_line2"), 160)
        beach.town          = _clean_text(request.form.get("town"), 120)
        beach.postcode      = _clean_text(request.form.get("postcode"), 20)
        beach.country       = _clean_text(request.form.get("country"), 60)

        beach.maps_url    = _safe_http_url(request.form.get("maps_url"), 500)
        beach.website_url = _safe_http_url(request.form.get("website_url"), 500)

        beach.parking_info     = _clean_text(request.form.get("parking_info"), 5000)
        beach.facilities       = _clean_text(request.form.get("facilities"), 5000)
        beach.access_notes     = _clean_text(request.form.get("access_notes"), 5000)
        beach.safety_notes     = _clean_text(request.form.get("safety_notes"), 5000)
        beach.emergency_access = _clean_text(request.form.get("emergency_access"), 5000)

        try:
            db.session.commit()
            flash("Beach info updated.", "success")
            return redirect(url_for("beach_info", beach_id=beach.id))
        except Exception as e:
            db.session.rollback()
            flash(f"Could not save changes: {e}", "error")

    return render_template("beach_info_edit.html", beach=beach, role=current_user_role())


# ================================
# ROUTES — Swimmer dashboard
# ================================

@app.route("/swimmer", methods=["GET"])
def swimmer():
    if not login_required(role="swimmer"):
        return redirect(url_for("login"))

    beaches_list = Beach.query.order_by(Beach.name.asc()).all()
    beach_id     = request.args.get("beach_id", "").strip()

    report_query = SeaReport.query.order_by(SeaReport.reported_at.desc())
    if beach_id.isdigit():
        report_query = report_query.filter(SeaReport.beach_id == int(beach_id))

    reports       = report_query.limit(20).all()
    latest_report = reports[0] if reports else None

    api_data     = None
    tide         = None
    advisory     = None
    swimmer_tips = []

    primary_beach = _pick_primary_beach_for_swimmer(beach_id, reports, beaches_list)

    if primary_beach and primary_beach.latitude is not None and primary_beach.longitude is not None:
        try:
            lat = float(primary_beach.latitude)
            lng = float(primary_beach.longitude)

            api_data = get_marine_conditions(lat, lng)
            tide     = compute_tide_assist(lat, lng, marine_data=api_data)

            if api_data is None:
                api_data = {}

            if tide:
                api_data["tide_state"]    = tide.get("tide_state", "")
                api_data["tide_strength"] = tide.get("tide_strength", "")
                api_data["tide_basis"]    = tide.get("tide_basis", "")

            advisory     = build_safety_advisory(api_data if api_data else None)
            swimmer_tips = _swimmer_context_tips(latest_report, advisory, tide)
        except Exception:
            api_data     = None
            tide         = None
            advisory     = None
            swimmer_tips = []

    kpis = {
        "report_count":       len(reports),
        "beach_count":        len(beaches_list),
        "latest_report_time": latest_report.reported_at.strftime("%Y-%m-%d %H:%M") if latest_report else "—",
    }

    uid = session.get("user_id")
    favourites         = []
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


# ================================
# ROUTES — Lifeguard dashboard
# ================================

@app.route("/lifeguard", methods=["GET"])
def lifeguard():
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    beaches_list = Beach.query.order_by(Beach.name.asc()).all()
    reports      = SeaReport.query.order_by(SeaReport.reported_at.desc()).limit(20).all()
    issues       = SwimmerIssue.query.filter_by(resolved=False).order_by(SwimmerIssue.submitted_at.desc()).all()

    api_data          = None
    selected_beach_id = request.args.get("beach_id", "").strip()
    advisory          = None

    if selected_beach_id.isdigit():
        b = Beach.query.get(int(selected_beach_id))
        if b and b.latitude is not None and b.longitude is not None:
            lat = float(b.latitude)
            lng = float(b.longitude)

            api_data = get_marine_conditions(lat, lng)
            tide     = compute_tide_assist(lat, lng, marine_data=api_data)

            if api_data is None:
                api_data = {}

            if tide:
                api_data["tide_state"]    = tide.get("tide_state", "")
                api_data["tide_strength"] = tide.get("tide_strength", "")
                api_data["tide_basis"]    = tide.get("tide_basis", "")

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


# ================================
# ROUTES — Reports
# ================================

@app.route("/report", methods=["POST"])
def create_report():
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    try:
        beach_id    = int(request.form.get("beach_id"))
        tide        = request.form.get("tide") or None
        temp_raw    = request.form.get("temp_c")
        temp_c      = float(temp_raw) if temp_raw else None
        flag_status = request.form.get("flag_status") or None
        notes       = request.form.get("notes") or None

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

        # Notify swimmers who have this beach favourited
        _notify_favourites_of_report(beach_id, flag_status, notes)

    except Exception as e:
        db.session.rollback()
        flash(f"Error saving report: {e}", "error")

    return redirect(url_for("lifeguard"))


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


@app.route("/report/<int:report_id>/edit", methods=["GET", "POST"])
def edit_report(report_id):
    if not login_required(role="lifeguard"):
        return redirect(url_for("login"))

    report       = SeaReport.query.get_or_404(report_id)
    beaches_list = Beach.query.order_by(Beach.name.asc()).all()

    if request.method == "POST":
        try:
            report.beach_id = int(request.form.get("beach_id"))
            report.tide     = request.form.get("tide") or None

            temp_raw    = request.form.get("temp_c")
            report.temp_c = float(temp_raw) if temp_raw else None

            report.flag_status = request.form.get("flag_status") or None
            report.notes       = request.form.get("notes") or None

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


# ================================
# ROUTES — Issues
# ================================

@app.post("/issue")
def create_issue():
    if not login_required():
        return redirect(url_for("login"))

    try:
        beach_id    = int(request.form.get("issue_beach_id"))
        issue_type  = request.form.get("issue_type") or None
        description = request.form.get("issue_desc") or None

        issue = SwimmerIssue(beach_id=beach_id, issue_type=issue_type, description=description)
        db.session.add(issue)
        db.session.commit()
        flash("Issue submitted for lifeguard review.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error submitting issue: {e}", "error")

    return redirect(url_for("swimmer"))


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


# ================================
# STARTUP
# ================================

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)