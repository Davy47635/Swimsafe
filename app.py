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


# ---- Beach Photos ----
class BeachPhoto(db.Model):
    __tablename__ = "beach_photos"
    id = db.Column(db.Integer, primary_key=True)
    beach_id = db.Column(db.Integer, db.ForeignKey("beaches.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
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

    # Added currents where available (plan/coverage dependent).
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


def get_tide_sea_level(lat: float, lng: float, start_dt: datetime, end_dt: datetime, datum: str = "MSL"):
    """
    Tide Sea Level endpoint: returns hourly sea level in meters.
    Stormglass expects start/end like YYYY-MM-DDTHH (UTC).
    """
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
    """
    Tide Extremes endpoint: returns times & heights for high/low tides.
    """
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
    """
    Returns:
      {
        "tide_state": "Rising/Falling/High/Low",
        "tide_strength": "Weak/Moderate/Strong",
        "tide_basis": "...",
      }
    Safe fallbacks: returns None if not enough data / no API key.
    """
    if not STORMGLASS_API_KEY:
        return None

    now = datetime.utcnow()

    # 1) Sea level for now & +1h (direction + fallback strength)
    sea = get_tide_sea_level(lat, lng, now, now + timedelta(hours=2))

    sea_now = None
    sea_next = None

    if sea and len(sea) >= 2:
        # Stormglass typically returns items like {"time":"...","sg":1.23}
        def extract_height(item: dict):
            if not isinstance(item, dict):
                return None
            if "sg" in item:
                return _to_float(item.get("sg"))
            # fallback keys (just in case)
            return _to_float(item.get("height") or item.get("value") or item.get("seaLevel"))

        sea_now = extract_height(sea[0])
        sea_next = extract_height(sea[1])

    delta_m = None
    if sea_now is not None and sea_next is not None:
        delta_m = sea_next - sea_now  # approx per hour

    # 2) Extremes: nearest extreme within 60 minutes → High/Low
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

    # Prefer currentSpeed if present
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
            rate = abs(delta_m)  # m/hr proxy
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
    """
    Rule-based advisory from API conditions.
    Returns dict: {level, level_class, reasons[]} or None if no API data.
    """
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

    try:
        original = secure_filename(f.filename)
        unique_name = f"{beach.id}_{int(datetime.utcnow().timestamp())}_{original}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        f.save(save_path)

        p = BeachPhoto(
            beach_id=beach.id,
            filename=unique_name,
            uploaded_by=session.get("username")
        )
        db.session.add(p)
        db.session.commit()
        flash("Photo uploaded.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error uploading photo: {e}", "error")

    return redirect(url_for("beach_detail", beach_id=beach.id))


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

    return render_template(
        "swimmer.html",
        beaches=beaches_list,
        reports=reports,
        role=current_user_role(),
        selected_beach_id=beach_id
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

