# Some of the route structure and wording were helped by ChatGPT.
# Final code decisions, testing, and database setup were done by me.
# Reference: Flask Documentation - Routing, Templates & Sessions (2025)
# Reference: SQLAlchemy ORM Tutorial (2025)

from datetime import datetime, timedelta
import os
import requests

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
STORMGLASS_ENDPOINT = "https://api.stormglass.io/v2/weather/point"

# ================================
# UPLOADS (Beach photos)
# ================================

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS






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


# ---- NEW: Beach Photos ----
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


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


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
    ])

    # IMPORTANT: give Stormglass a short time window, otherwise you may get empty hours
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
            headers={"Authorization": STORMGLASS_API_KEY},
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
            "time": hour0.get("time"),
        }

    except Exception:
        return None


def build_safety_advisory(api_data: dict):
    """
    Rule-based advisory from API conditions.
    Returns dict: {level, level_class, reasons[]} or None if no API data.
    """
    if not api_data:
        return None

    wave_h = api_data.get("wave_height")
    wind_s = api_data.get("wind_speed")
    wave_p = api_data.get("wave_period")

    # Convert to floats where possible
    def to_float(x):
        try:
            return float(x)
        except Exception:
            return None

    wave_h = to_float(wave_h)
    wind_s = to_float(wind_s)
    wave_p = to_float(wave_p)

    reasons = []
    level = "Low risk"
    level_class = "low"

    # --- RULES ---
    # Wave height
    if wave_h is not None:
        if wave_h > 2.5:
            reasons.append(f"Wave height {wave_h:.1f}m is above unsafe threshold (2.5m).")
        elif wave_h > 1.5:
            reasons.append(f"Wave height {wave_h:.1f}m is above caution threshold (1.5m).")

    # Wind speed (m/s)
    if wind_s is not None:
        if wind_s > 14:
            reasons.append(f"Wind speed {wind_s:.1f}m/s is above unsafe threshold (14m/s).")
        elif wind_s > 9:
            reasons.append(f"Wind speed {wind_s:.1f}m/s is above caution threshold (9m/s).")

    # Long-period swell (more powerful waves)
    if wave_p is not None and wave_h is not None:
        if wave_p > 14 and wave_h > 1.5:
            reasons.append(f"Long wave period {wave_p:.0f}s with wave height {wave_h:.1f}m suggests powerful swell.")
        elif wave_p > 12 and wave_h > 1.2:
            reasons.append(f"Wave period {wave_p:.0f}s with wave height {wave_h:.1f}m suggests stronger sets.")

    # Determine final level based on strongest trigger
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

    # If we literally got no usable numbers
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


# ---- NEW: Serve uploaded files (kept behind login) ----
@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    if not login_required():
        return redirect(url_for("login"))
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---- NEW: Lifeguard uploads a photo for a beach ----
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
        flash("Invalid file type. Use png/jpg/jpeg/gif/webp.", "error")
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
    if not login_required():
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

    # API: optional load by selected beach
    api_data = None
    selected_beach_id = request.args.get("beach_id", "").strip()

    # ✅ NEW: advisory output for option A
    advisory = None

    if selected_beach_id.isdigit():
        b = Beach.query.get(int(selected_beach_id))
        if b and b.latitude is not None and b.longitude is not None:
            api_data = get_marine_conditions(float(b.latitude), float(b.longitude))
            # ✅ NEW: build advisory from API data
            advisory = build_safety_advisory(api_data)
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
        # ✅ NEW: pass advisory to template
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

        # ✅ ADDED: get advisory level from hidden field
        advisory_level = request.form.get("advisory_level")

        # ✅ ADDED: append advisory into notes (does NOT overwrite existing notes)
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
