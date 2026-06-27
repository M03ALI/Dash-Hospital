"""
Hospital Weekly Dashboard
=========================

Two modes, one shared SQLite database:

  • DATA ENTRY (analysts, password protected) — pick a day from a weekly
    calendar strip and enter that day's data:
        Patients   : currently admitted, new admissions, discharges, ER visits,
                     ICU patients, surgeries, births, deaths, referrals out
        Capacity   : total beds, beds available, ICU beds available
        Staff      : doctors, nurses, support staff, specialists on call
        Ambulances : available, fleet total, calls responded, avg ER wait (mins)
        Supplies   : oxygen supply level (%), blood-bank units by blood type
        Departments / Medications / Tests (editable tables)

  • PUBLIC DASHBOARD (everyone, read-only) with two view types:
        - Day : each day has its own dashboard, chosen from a calendar.
        - Weekly     : Mon–Sun roll-up across the week.

Run:
    pip install -r requirements.txt
    streamlit run hospital_dashboard.py

Analyst password comes from env var HOSPITAL_ADMIN_PASSWORD (default "changeme").
"""

import os
from datetime import datetime, date, timedelta
import sqlite3
import hmac
import hashlib
import time
import base64
import struct
import secrets as pysecrets

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
DB_PATH = os.environ.get("HOSPITAL_DB_PATH", "hospital_dashboard.db")

# ── Authentication / security ──
SESSION_TIMEOUT = 30 * 60     # auto sign-out after 30 min in a session
MAX_FAILS = 5                 # failed attempts before a temporary lock
LOCK_SECONDS = 60            # lock duration after too many failures
PBKDF2_ITERS = 600_000       # OWASP-recommended work factor for PBKDF2-HMAC-SHA256
THROTTLE_BASE = 0.4          # seconds added per failed attempt (brute-force slow-down)


def _get_secret(name, default=None):
    """Prefer Streamlit secrets, then environment variables."""
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return os.environ.get(name, default)


def _pbkdf2(pw, salt, iters=PBKDF2_ITERS):
    return hashlib.pbkdf2_hmac("sha256", (pw or "").encode("utf-8"), salt, iters).hex()


def make_password_hash(pw, iters=PBKDF2_ITERS):
    """Create a salted PBKDF2 hash string to store instead of a plaintext password."""
    salt = pysecrets.token_bytes(16)
    return f"pbkdf2_sha256${iters}${salt.hex()}${_pbkdf2(pw, salt, iters)}"


ADMIN_HASH = _get_secret("HOSPITAL_ADMIN_PASSWORD_HASH")
ADMIN_PASSWORD = _get_secret("HOSPITAL_ADMIN_PASSWORD", "changeme")
TOTP_SECRET = _get_secret("HOSPITAL_ADMIN_TOTP_SECRET")   # optional 2FA (base32)


def verify_password(pw):
    """Constant-time check against a stored hash (preferred) or plaintext fallback."""
    if ADMIN_HASH:
        try:
            _scheme, iters, salt_hex, hash_hex = ADMIN_HASH.split("$")
            calc = _pbkdf2(pw, bytes.fromhex(salt_hex), int(iters))
            return hmac.compare_digest(calc, hash_hex)
        except Exception:
            return False
    return hmac.compare_digest(pw or "", ADMIN_PASSWORD)


def _b32_secret(nbytes=20):
    """A fresh base32 secret for setting up an authenticator app."""
    return base64.b32encode(pysecrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def _totp_at(secret_b32, when, step=30, digits=6):
    """RFC 6238 TOTP using only the standard library (no extra dependencies)."""
    s = (secret_b32 or "").strip().replace(" ", "").upper()
    s += "=" * ((8 - len(s) % 8) % 8)            # restore base32 padding
    key = base64.b32decode(s, casefold=True)
    counter = int(when // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret_b32, code, window=1):
    """Verify a 6-digit code with a ±1 step (±30s) tolerance, constant-time."""
    code = (code or "").strip()
    if not (secret_b32 and code.isdigit()):
        return False
    now = time.time()
    ok = False
    for w in range(-window, window + 1):
        try:
            if hmac.compare_digest(_totp_at(secret_b32, now + w * 30), code):
                ok = True
        except Exception:
            return False
    return ok


def two_factor_enabled():
    return bool(TOTP_SECRET)

DAILY_FIELDS = [
    ("current_inpatients", "Currently admitted (inpatients)", "Patients"),
    ("admitted", "New admissions today", "Patients"),
    ("discharged", "Discharged today", "Patients"),
    ("er_visits", "Emergency / ER visits", "Patients"),
    ("icu_patients", "ICU patients", "Patients"),
    ("surgeries", "Surgeries performed", "Patients"),
    ("births", "Births", "Patients"),
    ("deaths", "Deaths", "Patients"),
    ("referrals_out", "Referrals out", "Patients"),
    ("beds_total", "Total beds", "Capacity"),
    ("beds_available", "Beds available", "Capacity"),
    ("icu_beds_available", "ICU beds available", "Capacity"),
    ("doctors", "Doctors on duty", "Staff"),
    ("nurses", "Nurses on duty", "Staff"),
    ("support_staff", "Support staff on duty", "Staff"),
    ("specialists_on_call", "Specialists on call", "Staff"),
    ("ambulances_available", "Ambulances available", "Ambulances & Emergency"),
    ("ambulances_total", "Ambulances (fleet total)", "Ambulances & Emergency"),
    ("ambulance_calls", "Ambulance calls responded", "Ambulances & Emergency"),
    ("avg_er_wait_min", "Avg ER wait (minutes)", "Ambulances & Emergency"),
    ("oxygen_pct", "Oxygen supply level (%)", "Critical Supplies"),
]
FIELD_KEYS = [f[0] for f in DAILY_FIELDS]
FIELD_GROUPS = ["Patients", "Capacity", "Staff", "Ambulances & Emergency", "Critical Supplies"]

BLOOD_TYPES = ["O+", "O-", "A+", "A-", "B+", "B-", "AB+", "AB-"]
DEFAULT_DEPARTMENTS = ["Cardiology", "Emergency", "Delivery / Maternity", "Surgery",
                       "Pediatrics", "Radiology", "ICU", "Outpatient (OPD)"]
DEFAULT_MEDICATIONS = [("Paracetamol", "Available"), ("Amoxicillin", "Available"),
                       ("Insulin", "Available"), ("IV Fluids (Saline)", "Available"),
                       ("Adrenaline", "Available"), ("ORS Sachets", "Available")]
DEFAULT_TESTS = ["Full Blood Count", "Malaria RDT", "Blood Glucose", "X-Ray",
                 "Ultrasound", "COVID-19 PCR", "Urinalysis", "HIV Test", "ECG"]
DEPT_STATUSES = ["Operational", "Limited", "Closed"]
MED_STATUSES = ["Available", "Limited availability", "Not available"]

PRIMARY, TEAL2, ACCENT, INK = "#006868", "#02A6A6", "#60D8F8", "#06343A"
LIGHT_BG, GRID, WARN, DANGER, OK_GREEN = "#F0FAFA", "#CFE6E6", "#F4A340", "#F85050", "#2E9E5B"
STATUS_COLOR = {"Operational": OK_GREEN, "Limited": WARN, "Closed": DANGER}
STATUS_SCORE = {"Operational": 2, "Limited": 1, "Closed": 0}
MED_STATUS_COLOR = {"Available": OK_GREEN, "Limited availability": WARN, "Not available": DANGER}
MED_STATUS_SCORE = {"Available": 2, "Limited availability": 1, "Not available": 0}

HDM_LOGO_B64 = "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"

import base64 as _b64, io as _io
try:
    from PIL import Image as _PILImage
    _PAGE_ICON = _PILImage.open(_io.BytesIO(_b64.b64decode(HDM_LOGO_B64)))
except Exception:
    _PAGE_ICON = None

st.set_page_config(page_title="Hospital Dashboard", layout="wide",
                   page_icon=_PAGE_ICON if _PAGE_ICON is not None else None)

# ── Theme (light default; runtime toggle lives in the sidebar) ──
DARK = bool(st.session_state.get("ui_dark", False))
if DARK:
    APP_BG, SIDE_BG, SIDE_BORDER = "#0E1A1A", "#0B1515", "#1E3636"
    BODY_FG, MUTED_FG, SECT_BORDER = "#E6F2F2", "#9FBABA", "#1B3433"
    CARD_BG, METRIC_BG, METRIC_LABEL = "#13201F", "#13201F", "#9FBABA"
else:
    APP_BG, SIDE_BG, SIDE_BORDER = "#FFFFFF", LIGHT_BG, GRID
    BODY_FG, MUTED_FG, SECT_BORDER = "#0E2A2A", "#5E7373", LIGHT_BG
    CARD_BG, METRIC_BG, METRIC_LABEL = "#FFFFFF", LIGHT_BG, "#5E7373"

_DARK_OVERRIDES = (f"""
    .stApp, .stApp p, .stApp li, .stApp label,
    [data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] p,
    [data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p,
    [data-testid="stCaptionContainer"], .stRadio label, .stCheckbox label,
    [data-testid="stExpander"] summary, [data-testid="stExpander"] p {{
        color:{BODY_FG}; }}
    [data-testid="stSidebar"] * {{ color:{BODY_FG}; }}
    /* keep card internals readable on their light/dark surfaces */
    .chart-card-title {{ color:{PRIMARY} !important; }}
    [data-testid="stMetricValue"] {{ color:{TEAL2} !important; }}
    [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] * {{ color:{METRIC_LABEL} !important; }}
    [data-testid="stExpander"] {{ border:1px solid {SIDE_BORDER}; border-radius:10px; }}
""" if DARK else "")

st.markdown(f"""
<style>
    .stApp {{ background:{APP_BG}; color:{BODY_FG}; }}
    [data-testid="stSidebar"] {{ background:{SIDE_BG}; border-right:1px solid {SIDE_BORDER}; }}
    .big-title {{ font-size:clamp(1.6rem,4.5vw,2.4rem); font-weight:800;
        background:linear-gradient(90deg,{PRIMARY},{TEAL2});
        -webkit-background-clip:text; -webkit-text-fill-color:transparent;
        background-clip:text; margin-bottom:.1rem; }}
    .sub {{ color:{MUTED_FG}; font-size:.95rem; margin-bottom:1rem; }}
    .section {{ font-size:1.15rem; font-weight:700; color:{PRIMARY};
        border-bottom:2px solid {SECT_BORDER}; padding-bottom:.3rem; margin:1.4rem 0 .8rem 0; }}
    [data-testid="stMetric"] {{ background:{METRIC_BG}; border:1px solid {SIDE_BORDER};
        border-radius:12px; padding:14px 16px; }}
    [data-testid="stMetricValue"] {{ color:{PRIMARY}; }}
    .stButton>button[kind="primary"], .stDownloadButton>button {{
        background:{PRIMARY}; border:1px solid {PRIMARY}; color:#FFF; font-weight:600; border-radius:8px; }}
    .pill {{ display:inline-block; padding:4px 12px; border-radius:999px;
        color:#FFF; font-weight:700; font-size:.85rem; margin:2px; }}
    [data-testid="stPlotlyChart"], [data-testid="stDataFrame"] {{ max-width:100% !important; }}
    /* unified chart cards: title sits in a header inside the same bordered card as
       the chart, so a title can never look detached or stacked over the content */
    [data-testid="stVerticalBlockBorderWrapper"] {{ border-radius:16px !important;
        border-color:{SIDE_BORDER} !important; box-shadow:0 2px 10px rgba(6,52,58,.05);
        background:{CARD_BG}; padding:6px 14px 4px 14px !important; margin-bottom:.7rem; }}
    .chart-card-title {{ font-size:1.06rem; font-weight:700; color:{PRIMARY};
        margin:.1rem 0 .15rem 0; line-height:1.2; }}
    .chart-card-sub {{ font-size:.82rem; color:{MUTED_FG}; margin:-.05rem 0 .2rem 0; }}
    {_DARK_OVERRIDES}
    /* phones & tablets: wrap columns two-up so cards, inputs and buttons stay
       readable. Charts render full-width (outside columns), so they're unaffected. */
    @media (max-width: 980px) {{
        [data-testid="stHorizontalBlock"] {{ flex-wrap:wrap !important; gap:0.55rem !important; }}
        [data-testid="stColumn"], [data-testid="column"] {{
            min-width:47% !important; flex:1 1 47% !important; }}
    }}
    /* small phones: a touch more compact */
    @media (max-width: 460px) {{
        .block-container {{ padding-left:0.6rem !important; padding-right:0.6rem !important; }}
        [data-testid="stMetric"] {{ padding:10px 12px; }}
        [data-testid="stMetricValue"] {{ font-size:1.15rem !important; }}
    }}
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────
@st.cache_resource
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    c = get_conn()
    cols = ", ".join(f"{k} INTEGER DEFAULT 0" for k in FIELD_KEYS)
    c.executescript(f"""
    CREATE TABLE IF NOT EXISTS daily (
        entry_date TEXT PRIMARY KEY, {cols}, notes TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS departments (
        entry_date TEXT, name TEXT, status TEXT, PRIMARY KEY (entry_date, name));
    CREATE TABLE IF NOT EXISTS medications (
        entry_date TEXT, name TEXT, stock INTEGER, unit TEXT, status TEXT,
        PRIMARY KEY (entry_date, name));
    CREATE TABLE IF NOT EXISTS tests (
        entry_date TEXT, name TEXT, available INTEGER, PRIMARY KEY (entry_date, name));
    CREATE TABLE IF NOT EXISTS blood_bank (
        entry_date TEXT, blood_type TEXT, units INTEGER, PRIMARY KEY (entry_date, blood_type));
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
    """)
    c.commit()
    migrate()


def migrate():
    c = get_conn()
    existing = {r[1] for r in c.execute("PRAGMA table_info(daily)").fetchall()}
    for k in FIELD_KEYS:
        if k not in existing:
            c.execute(f"ALTER TABLE daily ADD COLUMN {k} INTEGER DEFAULT 0")
    med_cols = {r[1] for r in c.execute("PRAGMA table_info(medications)").fetchall()}
    if "status" not in med_cols:
        c.execute("ALTER TABLE medications ADD COLUMN status TEXT")
    c.commit()


def get_setting(key, default=""):
    row = get_conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(key, value):
    c = get_conn()
    c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    c.commit()


def dates_with_data(start, end):
    """Set of YYYY-MM-DD strings in [start,end] that already have any data."""
    c = get_conn()
    p = (start.isoformat(), end.isoformat())
    s = set()
    for tbl in ("daily", "departments", "medications", "tests", "blood_bank"):
        for r in c.execute(f"SELECT DISTINCT entry_date FROM {tbl} "
                           f"WHERE entry_date BETWEEN ? AND ?", p).fetchall():
            s.add(r[0])
    return s


def save_day(d, numeric, notes, dept_df, med_df, test_df, blood_df):
    ds = d.isoformat()
    c = get_conn()
    cols = FIELD_KEYS + ["notes", "updated_at"]
    placeholders = ", ".join("?" for _ in cols) + ", ?"
    updates = ", ".join(f"{k}=excluded.{k}" for k in cols)
    vals = [int(numeric.get(k, 0)) for k in FIELD_KEYS] + \
           [notes, datetime.now().isoformat(timespec="seconds"), ds]
    c.execute(f"INSERT INTO daily({', '.join(cols)}, entry_date) VALUES({placeholders}) "
              f"ON CONFLICT(entry_date) DO UPDATE SET {updates}", vals)
    for tbl in ("departments", "medications", "tests", "blood_bank"):
        c.execute(f"DELETE FROM {tbl} WHERE entry_date=?", (ds,))
    for _, r in dept_df.iterrows():
        n = str(r.get("Department", "")).strip()
        if n:
            c.execute("INSERT OR REPLACE INTO departments VALUES(?,?,?)",
                      (ds, n, str(r.get("Status", "Operational"))))
    for _, r in med_df.iterrows():
        n = str(r.get("Medication", "")).strip()
        if n:
            status = str(r.get("Status", "Available")).strip() or "Available"
            c.execute("INSERT OR REPLACE INTO medications(entry_date, name, status) "
                      "VALUES(?,?,?)", (ds, n, status))
    for _, r in test_df.iterrows():
        n = str(r.get("Test", "")).strip()
        if n:
            c.execute("INSERT OR REPLACE INTO tests VALUES(?,?,?)",
                      (ds, n, 1 if r.get("Available", False) else 0))
    for _, r in blood_df.iterrows():
        bt = str(r.get("Blood Type", "")).strip()
        if bt:
            c.execute("INSERT OR REPLACE INTO blood_bank VALUES(?,?,?)",
                      (ds, bt, int(r.get("Units", 0) or 0)))
    c.commit()


def load_day(d):
    ds = d.isoformat()
    c = get_conn()
    cur = c.execute("SELECT * FROM daily WHERE entry_date=?", (ds,))
    row = cur.fetchone()
    scalars = dict(zip([x[0] for x in cur.description], row)) if row else None
    depts = pd.read_sql_query("SELECT name AS Department, status AS Status FROM departments "
                              "WHERE entry_date=?", c, params=(ds,))
    meds = pd.read_sql_query(
        "SELECT name AS Medication, COALESCE(status, "
        "CASE WHEN stock IS NULL THEN 'Available' WHEN stock<=0 THEN 'Not available' "
        "WHEN stock<=10 THEN 'Limited availability' ELSE 'Available' END) AS Status "
        "FROM medications WHERE entry_date=?", c, params=(ds,))
    tests = pd.read_sql_query("SELECT name AS Test, available FROM tests WHERE entry_date=?",
                              c, params=(ds,))
    if not tests.empty:
        tests["Available"] = tests["available"].astype(bool)
        tests = tests[["Test", "Available"]]
    blood = pd.read_sql_query("SELECT blood_type AS 'Blood Type', units AS Units FROM blood_bank "
                              "WHERE entry_date=?", c, params=(ds,))
    return scalars, depts, meds, tests, blood


def load_range(start, end):
    c = get_conn()
    p = (start.isoformat(), end.isoformat())
    return (pd.read_sql_query("SELECT * FROM daily WHERE entry_date BETWEEN ? AND ? ORDER BY entry_date", c, params=p),
            pd.read_sql_query("SELECT * FROM departments WHERE entry_date BETWEEN ? AND ?", c, params=p),
            pd.read_sql_query(
                "SELECT entry_date, name, COALESCE(status, "
                "CASE WHEN stock IS NULL THEN 'Available' WHEN stock<=0 THEN 'Not available' "
                "WHEN stock<=10 THEN 'Limited availability' ELSE 'Available' END) AS status "
                "FROM medications WHERE entry_date BETWEEN ? AND ?", c, params=p),
            pd.read_sql_query("SELECT * FROM tests WHERE entry_date BETWEEN ? AND ?", c, params=p),
            pd.read_sql_query("SELECT * FROM blood_bank WHERE entry_date BETWEEN ? AND ?", c, params=p))


init_db()
HOSPITAL_NAME = get_setting("hospital_name", "General Hospital")


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def week_bounds(any_day):
    monday = any_day - timedelta(days=any_day.weekday())
    return monday, monday + timedelta(days=6)


def month_bounds(any_day):
    first = any_day.replace(day=1)
    nxt = first.replace(year=first.year + 1, month=1) if first.month == 12 \
        else first.replace(month=first.month + 1)
    return first, nxt - timedelta(days=1)


def day_label(dstr):
    return datetime.fromisoformat(dstr).strftime("%a %d")


def style_fig(fig, h=380, hide_axis_titles=True):
    """Clean styling: black plot border, no gridlines, and bar values shown inside
    the bar when they fit, otherwise on top of the bar (never hidden)."""
    for tr in fig.data:
        if tr.type == "bar":
            horizontal = getattr(tr, "orientation", None) == "h"
            tr.text = tr.x if horizontal else tr.y
            tr.texttemplate = "%{x:,.0f}" if horizontal else "%{y:,.0f}"
            tr.textposition = "auto"            # inside if it fits, else on top of the bar
            tr.insidetextanchor = "middle"
            tr.textangle = 0
            tr.cliponaxis = False               # don't clip labels drawn above bars
            tr.insidetextfont = dict(color="#FFFFFF", size=16)
            tr.outsidetextfont = dict(color=INK, size=16)
        elif tr.type == "scatter":
            # also print the value at each point on line charts (skip when too dense)
            horizontal = getattr(tr, "orientation", None) == "h"
            seq = getattr(tr, "x", None) if horizontal else getattr(tr, "y", None)
            try:
                n = len(seq) if seq is not None else 0
            except TypeError:
                n = 0
            if 0 < n <= 16:
                mode = getattr(tr, "mode", None) or "lines+markers"
                if "text" not in mode:
                    tr.mode = mode + "+text"
                tr.texttemplate = "%{x:,.0f}" if horizontal else "%{y:,.0f}"
                tr.textposition = "top center"
                tr.cliponaxis = False
                tr.textfont = dict(size=14, color=INK)
    fig.update_layout(
        paper_bgcolor="#FFFFFF", plot_bgcolor="#FFFFFF",
        font=dict(color=INK, size=13), height=h,
        margin=dict(l=14, r=18, t=70, b=60),
        title=dict(x=0.01, xanchor="left", y=0.98, yanchor="top",
                   font=dict(size=16, color=PRIMARY)),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=1, xanchor="right",
                    font=dict(size=12)),
        bargap=0.30, bargroupgap=0.12, autosize=True,
    )
    fig.update_xaxes(showline=True, linecolor="#000000", linewidth=1.4, mirror=True,
                     showgrid=False, zeroline=False, automargin=True,
                     tickfont=dict(size=12), title_text=("" if hide_axis_titles else None))
    fig.update_yaxes(showline=True, linecolor="#000000", linewidth=1.4, mirror=True,
                     showgrid=False, zeroline=False, automargin=True,
                     tickfont=dict(size=12), title_text=("" if hide_axis_titles else None))
    return fig


# CSS for big-screen presentation mode: hides app chrome and compacts spacing so
# the dashboard fills a TV / large display. It never hides overflow, so content can
# never be clipped or overlap — at worst it grows slightly, it never covers a title.
TV_CSS = """
<style>
    [data-testid="stSidebar"], [data-testid="collapsedControl"] { display:none !important; }
    header[data-testid="stHeader"], [data-testid="stToolbar"] { display:none !important; }
    .block-container { max-width:100% !important; min-height:100vh !important;
        padding:0.5rem 1.2rem 0.8rem 1.2rem !important; animation: tvfade .5s ease both; }
    @keyframes tvfade { from { opacity:0; } to { opacity:1; } }
    .big-title { font-size:clamp(1.4rem, 2.1vw, 3rem) !important; margin:0 !important; }
    .sub { display:none !important; }
    /* professional presentation header bar (full-width, branded, underlined) */
    .tvhead { display:flex; align-items:center; gap:clamp(10px,1.4vw,20px); width:100%;
        padding:2px 2px 12px 2px; border-bottom:2px solid #CFE6E6; margin:.1rem 0 .55rem 0; }
    .tvlogo { height:clamp(36px,4.6vw,70px); width:auto; border-radius:10px; flex:0 0 auto;
        box-shadow:0 1px 6px rgba(6,52,58,.16); }
    .tvname { font-weight:800; color:#006868; line-height:1.05;
        font-size:clamp(1.35rem,2.8vw,2.8rem);
        background:linear-gradient(90deg,#006868,#02A6A6);
        -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;
        white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .tvhead-meta { margin-left:auto; text-align:right; flex:0 0 auto; line-height:1.25;
        font-weight:700; color:#06343A; font-size:clamp(0.82rem,1.15vw,1.4rem); }
    .tvhead-upd { display:block; font-weight:600; color:#5E7373;
        font-size:clamp(0.7rem,0.9vw,1.05rem); }
    .tvinfo { font-size:clamp(0.82rem, 1.05vw, 1.3rem); font-weight:600; color:#5E7373;
        margin-top:3px; }
    /* compact, understated Exit button, right-aligned above the header */
    [data-testid="stColumn"]:last-child .stButton>button {
        background:#FFFFFF !important; color:#06343A !important;
        border:1px solid #CFE6E6 !important; border-radius:10px !important;
        font-weight:700 !important; padding:2px 10px !important; }
    [data-testid="stColumn"]:last-child .stButton>button:hover {
        border-color:#02A6A6 !important; color:#006868 !important; }
    .section { font-size:clamp(0.9rem, 1.2vw, 1.5rem) !important; font-weight:700 !important;
        margin:0.2rem 0 0.15rem 0 !important; padding-bottom:0.1rem !important; }
    [data-testid="stMetric"] { padding:8px 12px !important; text-align:center; }
    [data-testid="stMetricValue"] { font-size:clamp(1.15rem, 1.8vw, 2.8rem) !important; }
    [data-testid="stMetricLabel"] p { font-size:clamp(0.68rem, 0.9vw, 1.1rem) !important; }
    .pill { font-size:clamp(0.72rem, 0.95vw, 1.15rem) !important;
        padding:3px 12px !important; margin:1px !important; }
    [data-testid="stHorizontalBlock"] { gap:0.6rem !important; }
    @media (min-width: 1000px) {
        [data-testid="stColumn"], [data-testid="column"] {
            min-width:0 !important; flex:1 1 0 !important; }
    }
    /* each panel is a self-contained card: title sits above its own chart, with a
       border separating panels so a title can never look like it overlaps a chart */
    .tvcard { border:1px solid #CFE6E6; border-radius:12px; padding:6px 8px 2px 8px;
        background:#FFFFFF; margin-bottom:0.4rem; }
    [data-testid="stPlotlyChart"] { border:1px solid #E3F1F1; border-radius:10px;
        padding:4px 4px 0 4px; background:#FFFFFF; }
    .tvchart-title { font-size:clamp(0.85rem, 1.2vw, 1.5rem); font-weight:700;
        color:#006868; text-align:center; line-height:1.15; margin:0.1rem 0 0.15rem 0; }
    /* slideshow footer (normal flow, so it can never cover a chart) */
    .tvfoot { display:flex; align-items:center; gap:16px; padding:6px 4px 2px 4px;
        margin-top:0.3rem; border-top:1px solid #CFE6E6; }
    .tvprogress { flex:1; height:7px; background:#E3F1F1; border-radius:999px; overflow:hidden; }
    .tvbar { height:100%; width:0; border-radius:999px;
        background:linear-gradient(90deg,#006868,#02A6A6);
        animation-name: tvgrow; animation-timing-function:linear; animation-fill-mode:forwards; }
    @keyframes tvgrow { from { width:0; } to { width:100%; } }
    .tvdots { display:flex; gap:7px; }
    .tvdot { width:10px; height:10px; border-radius:50%; background:#CFE6E6; }
    .tvdot.on { background:#006868; transform:scale(1.18); }
    .tvmeta { font-size:clamp(0.7rem, 0.85vw, 1rem); color:#5E7373; white-space:nowrap; }
</style>
"""


def _tv_kpi_per_row(vw):
    return 6 if vw >= 1500 else 4 if vw >= 1000 else 3


def render_kpis(items, tv):
    """KPI cards. On the big screen the cards-per-row adapt to the viewport width;
    in normal mode they wrap responsively via CSS."""
    if tv:
        vw, _vh = _tv_viewport()
        per_row = _tv_kpi_per_row(vw)
    else:
        per_row = 4
    for i in range(0, len(items), per_row):
        cols = st.columns(per_row)
        for col, (label, value) in zip(cols, items[i:i + per_row]):
            col.metric(label, value)


def dept_status_fig(pairs):
    """One full-width bar per department, coloured by status with the status named
    inside it. Bar length is constant so a Closed or Limited department is shown
    just as clearly as an Operational one — the colour and label carry the meaning."""
    if not pairs:
        return None
    names = [p[0] for p in pairs]
    colors = [STATUS_COLOR.get(p[1], "#777") for p in pairs]
    fig = go.Figure(go.Bar(
        x=[1] * len(names), y=names, orientation="h", marker_color=colors,
        text=[p[1] for p in pairs], textposition="inside", insidetextanchor="middle",
        textfont=dict(color="#FFFFFF"), cliponaxis=False,
        hovertext=[f"{n}: {s}" for n, s in pairs], hoverinfo="text"))
    fig.update_layout(title="Department status", paper_bgcolor="#FFFFFF",
                      plot_bgcolor="#FFFFFF", font=dict(color=INK), showlegend=False,
                      margin=dict(l=12, r=14, t=48, b=24), title_font=dict(color=PRIMARY),
                      bargap=0.24)
    fig.update_xaxes(range=[0, 1], showticklabels=False, showgrid=False, zeroline=False,
                     showline=True, linecolor="#000000", linewidth=1.4, mirror=True)
    fig.update_yaxes(autorange="reversed", automargin=True, showgrid=False,
                     showline=True, linecolor="#000000", linewidth=1.4, mirror=True)
    return fig


def med_status_fig(pairs):
    """Compact availability grid: one small coloured circle per medication
    (green = Available, amber = Limited availability, red = Not available) laid
    out side by side to save space, with the name under each circle and a colour
    key. Scales to many medications by wrapping into rows."""
    if not pairs:
        return None
    import math
    n = len(pairs)
    cols = max(1, min(n, 6))
    rows = math.ceil(n / cols)
    xs, ys, names, cols_color, hov = [], [], [], [], []
    for i, (name, status) in enumerate(pairs):
        s = status if status in MED_STATUS_COLOR else "Not available"
        xs.append(i % cols)
        ys.append(-(i // cols))
        names.append(str(name))
        cols_color.append(MED_STATUS_COLOR[s])
        hov.append(f"{name}: {s}")
    fig = go.Figure()
    # the medication circles
    fig.add_scatter(
        x=xs, y=ys, mode="markers+text", text=names,
        textposition="bottom center", textfont=dict(size=11, color=INK),
        marker=dict(size=30, color=cols_color, line=dict(color="#FFFFFF", width=2)),
        hovertext=hov, hoverinfo="text", showlegend=False, cliponaxis=False)
    # colour key (always shows all three) via legend-only points
    for s in MED_STATUSES:
        fig.add_scatter(x=[None], y=[None], mode="markers", name=s,
                        marker=dict(size=13, color=MED_STATUS_COLOR[s]),
                        showlegend=True, hoverinfo="skip")
    fig.update_layout(
        title="Medication availability", paper_bgcolor="#FFFFFF", plot_bgcolor="#FFFFFF",
        font=dict(color=INK), title_font=dict(color=PRIMARY),
        margin=dict(l=8, r=8, t=54, b=48),
        legend=dict(orientation="h", yanchor="top", y=-0.02, x=0.5, xanchor="center",
                    font=dict(size=12)),
        height=max(180, rows * 104 + 96))
    pad = 0.6
    fig.update_xaxes(visible=False, showgrid=False, zeroline=False,
                     range=[-pad, (cols - 1) + pad])
    fig.update_yaxes(visible=False, showgrid=False, zeroline=False,
                     range=[-(rows - 1) - 0.78, 0.78])
    return fig


def tests_fig(avail, unavail):
    """One coloured bar per test — green available, red not available."""
    names = list(avail) + list(unavail)
    if not names:
        return None
    colors = [OK_GREEN] * len(avail) + [DANGER] * len(unavail)
    marks = ["✓ " + n for n in avail] + ["✕ " + n for n in unavail]
    fig = go.Figure(go.Bar(x=[1] * len(names), y=names, orientation="h", marker_color=colors,
                           text=marks, textposition="inside", insidetextanchor="start",
                           textfont=dict(color="#FFFFFF")))
    fig.update_layout(title="Tests available (green) / not available (red)",
                      paper_bgcolor="#FFFFFF", plot_bgcolor="#FFFFFF", font=dict(color=INK),
                      showlegend=False, margin=dict(l=12, r=14, t=48, b=24),
                      title_font=dict(color=PRIMARY))
    fig.update_xaxes(range=[0, 1], showticklabels=False, showgrid=False, zeroline=False,
                     showline=True, linecolor="#000000", linewidth=1.4, mirror=True)
    fig.update_yaxes(showticklabels=False, autorange="reversed", showgrid=False,
                     showline=True, linecolor="#000000", linewidth=1.4, mirror=True)
    return fig


# ── PERFORMANCE / HOSPITAL CONDITION ────────────────────────────────
# A field counts as RED (out / closed), YELLOW (limited / low) or GREEN
# (available / operational). The weighted average of these decides whether the
# hospital is operating at a Critical, Medium or Stable condition.
LOW_BLOOD = 5        # blood units: 1..below this = limited (yellow)


def health_summary(statuses, tests_avail, tests_unavail, med_statuses, blood_units, oxygen):
    """Classify every status field red/yellow/green and derive the overall
    operating condition. Returns counts, a 0–100 health score, the condition
    label/colour, and a per-category breakdown."""
    def tally(items, fn):
        r = y = g = 0
        for it in items:
            c = fn(it)
            r += c == "r"; y += c == "y"; g += c == "g"
        return r, y, g

    dr, dy, dg = tally(statuses, lambda s: "g" if s == "Operational"
                       else "y" if s == "Limited" else "r")
    tr, ty, tg = int(tests_unavail), 0, int(tests_avail)       # tests: avail=green, not=red
    mr, my, mg = tally(med_statuses, lambda s: "g" if s == "Available"
                       else "y" if s == "Limited availability" else "r")
    br, by, bg = tally(blood_units, lambda u: "r" if u <= 0
                       else "y" if u < LOW_BLOOD else "g")
    o_r, o_y, o_g = (1, 0, 0) if oxygen < 25 else (0, 1, 0) if oxygen < 50 else (0, 0, 1)

    cats = [("Departments", dr, dy, dg), ("Tests", tr, ty, tg),
            ("Medications", mr, my, mg), ("Blood bank", br, by, bg),
            ("Oxygen", o_r, o_y, o_g)]
    red = dr + tr + mr + br + o_r
    yellow = dy + ty + my + by + o_y
    green = dg + tg + mg + bg + o_g
    total = red + yellow + green
    score = round((green * 2 + yellow) / (2 * total) * 100) if total else 0
    if total == 0:
        condition, color = "No data", "#777777"
    elif score >= 75:
        condition, color = "Stable", OK_GREEN
    elif score >= 50:
        condition, color = "Medium", WARN
    else:
        condition, color = "Critical", DANGER
    return dict(red=red, yellow=yellow, green=green, total=total, score=score,
                condition=condition, color=color, cats=cats)


def performance_figs(summary):
    """The performance dashboard panels: an operational-health gauge and a
    red/yellow/green breakdown by category."""
    color, score = summary["color"], summary["score"]
    gz = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number={"suffix": "%"},
        title={"text": "Operational health"},
        gauge={"axis": {"range": [0, 100]}, "bar": {"color": color},
               "steps": [{"range": [0, 50], "color": "#fde2e2"},
                         {"range": [50, 75], "color": "#fdf0db"},
                         {"range": [75, 100], "color": "#e3f5ea"}],
               "threshold": {"line": {"color": INK, "width": 3},
                             "thickness": 0.75, "value": score}}))
    gz.update_layout(paper_bgcolor="#FFFFFF", plot_bgcolor="#FFFFFF",
                     font=dict(color=INK), margin=dict(l=22, r=22, t=58, b=12),
                     title=dict(text="Operational health", x=0.5, xanchor="center",
                                font=dict(color=PRIMARY)))

    cats = summary["cats"]
    names = [c[0] for c in cats]
    fb = go.Figure()
    fb.add_bar(y=names, x=[c[3] for c in cats], name="Available / OK",
               orientation="h", marker_color=OK_GREEN)
    fb.add_bar(y=names, x=[c[2] for c in cats], name="Limited / low",
               orientation="h", marker_color=WARN)
    fb.add_bar(y=names, x=[c[1] for c in cats], name="Out / closed",
               orientation="h", marker_color=DANGER)
    fb.update_layout(barmode="stack",
                     title="Field status by category (green = ok, amber = limited, red = critical)")
    fb.update_yaxes(autorange="reversed")
    return [(f"Hospital Status — {summary['condition']}", gz),
            ("Status Breakdown", style_fig(fb, h=360))]


def perf_inputs_single(s, depts, meds, tests, blood):
    statuses = list(depts["Status"]) if not depts.empty else []
    ta = int(tests["Available"].sum()) if not tests.empty else 0
    tu = int((~tests["Available"]).sum()) if not tests.empty else 0
    med_statuses = list(meds["Status"]) if not meds.empty else []
    blood_units = [int(x) for x in blood["Units"]] if not blood.empty else []
    return statuses, ta, tu, med_statuses, blood_units, int(s.get("oxygen_pct", 0))


def perf_inputs_range(latest, depts, meds, tests, blood):
    statuses = []
    if not depts.empty:
        last_d = sorted(depts["entry_date"].unique())[-1]
        statuses = list(depts[depts["entry_date"] == last_d]["status"])
    ta = tu = 0
    if not tests.empty:
        last_t = tests["entry_date"].max()
        tt = tests[tests["entry_date"] == last_t]
        ta = int((tt["available"] == 1).sum()); tu = int((tt["available"] == 0).sum())
    med_statuses = []
    if not meds.empty:
        last_m = meds["entry_date"].max()
        med_statuses = list(meds[meds["entry_date"] == last_m]["status"])
    blood_units = []
    if not blood.empty:
        last_b = blood["entry_date"].max()
        blood_units = [int(x) for x in blood[blood["entry_date"] == last_b]["units"]]
    oxygen = int(latest["oxygen_pct"]) if latest is not None else 0
    return statuses, ta, tu, med_statuses, blood_units, oxygen


def render_performance_normal(summary, figs):
    """Top-of-page performance dashboard for the scrolling (non-presentation) view."""
    st.markdown('<div class="section">Hospital Performance</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div style="background:{summary["color"]};color:#fff;border-radius:14px;'
        f'padding:14px 18px;text-align:center;margin-bottom:.6rem;font-weight:800;'
        f'font-size:clamp(1.1rem,2.4vw,1.9rem);box-shadow:0 2px 10px rgba(6,52,58,.12);">'
        f'Hospital condition: {summary["condition"]}'
        f'<span style="font-weight:600;font-size:.62em;">'
        f' &nbsp;·&nbsp; operational health {summary["score"]}%</span></div>',
        unsafe_allow_html=True)
    render_kpis([("🟥 Critical (out / closed)", summary["red"]),
                 ("🟨 Limited / low", summary["yellow"]),
                 ("🟩 Stable (available)", summary["green"]),
                 ("❤️ Operational health", f'{summary["score"]}%')], False)
    for title, fig in figs:
        _render_chart_card(title, fig)


TV_SLIDESHOW_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  * { box-sizing:border-box; }
  html,body { margin:0; padding:0; background:transparent;
    font-family:'Source Sans Pro',system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  #wrap { position:relative; width:100%; height:100vh; display:flex; flex-direction:column; }
  #stage { position:relative; flex:1 1 auto; min-height:0; }
  .slide { position:absolute; inset:0; opacity:0; transition:opacity .65s ease;
    display:grid; gap:12px; padding:2px; pointer-events:none; }
  .slide.active { opacity:1; pointer-events:auto; }
  .cell { display:flex; flex-direction:column; min-height:0; min-width:0; background:#FFFFFF;
    border:1px solid #CFE6E6; border-radius:14px; padding:8px 8px 2px 8px;
    box-shadow:0 2px 10px rgba(6,52,58,.05); }
  .ctitle { font-weight:700; color:#006868; text-align:center; line-height:1.12; margin:0 0 3px 0; }
  .plot { flex:1 1 auto; min-height:0; width:100%; }
  #foot { display:flex; align-items:center; gap:16px; padding:8px 8px 4px 8px;
    border-top:1px solid #CFE6E6; flex:0 0 auto; }
  #bar { flex:1; height:8px; background:#E3F1F1; border-radius:999px; overflow:hidden; }
  #barfill { height:100%; width:0; border-radius:999px;
    background:linear-gradient(90deg,#006868,#02A6A6); }
  #dots { display:flex; gap:8px; }
  .dot { width:11px; height:11px; border-radius:50%; background:#CFE6E6; transition:transform .3s,background .3s; }
  .dot.on { background:#006868; transform:scale(1.25); }
  #meta { color:#5E7373; white-space:nowrap; }
  /* floating fullscreen control (auto-hides like PowerPoint) */
  #fsbtn { position:fixed; top:10px; right:12px; z-index:50; border:none; cursor:pointer;
    background:rgba(0,104,104,.92); color:#fff; font-size:18px; line-height:1;
    width:42px; height:42px; border-radius:10px; box-shadow:0 2px 8px rgba(6,52,58,.25);
    opacity:0; transition:opacity .3s; }
  #fsbtn.show { opacity:1; }
  /* start-presentation splash */
  #splash { position:fixed; inset:0; z-index:60; display:flex; flex-direction:column;
    align-items:center; justify-content:center; gap:14px; text-align:center;
    background:linear-gradient(135deg,#F0FAFA,#FFFFFF); }
  #splash h2 { margin:0; color:#006868; font-size:clamp(1.2rem,2.4vw,2rem); font-weight:800; }
  #splash p { margin:0; color:#5E7373; font-size:clamp(.85rem,1.3vw,1.1rem); }
  #startbtn { margin-top:6px; border:none; cursor:pointer; color:#fff; font-weight:700;
    font-size:clamp(1rem,1.6vw,1.3rem); padding:14px 26px; border-radius:12px;
    background:linear-gradient(90deg,#006868,#02A6A6); box-shadow:0 6px 18px rgba(0,104,104,.3); }
</style></head><body>
<button id="fsbtn" title="Full screen (Esc to exit)">&#x26F6;</button>
<div id="splash">
  <h2>Ready to present</h2>
  <p>Show only the dashboards on the whole screen.</p>
  <button id="startbtn">&#9654;&nbsp; Start full-screen presentation</button>
  <p style="opacity:.8;">Press <b>Esc</b> any time to exit.</p>
</div>
<div id="wrap">
  <div id="stage"></div>
  <div id="foot"><div id="bar"><div id="barfill"></div></div>
    <div id="dots"></div><div id="meta"></div></div>
</div>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<script>
(function(){
  var D = __DATA__;
  var seconds = D.seconds || 30, panels = D.panels || [];
  var stage = document.getElementById('stage'),
      dotsEl = document.getElementById('dots'),
      metaEl = document.getElementById('meta'),
      barfill = document.getElementById('barfill'),
      fsbtn = document.getElementById('fsbtn'),
      splash = document.getElementById('splash'),
      startbtn = document.getElementById('startbtn');
  var st = {cols:0, per:0, pages:1, idx:0, slides:[], timer:null};

  // ---- make the iframe fill from its top to the bottom of the viewport ----
  function fit(){
    try{
      var fe = window.frameElement;
      if(fe){
        var top = fe.getBoundingClientRect().top;
        var avail = Math.max(260, window.parent.innerHeight - top - 6);
        fe.style.height = avail + 'px'; fe.height = avail;
      }
    }catch(e){}
  }
  function dims(){
    return { w: document.documentElement.clientWidth || window.innerWidth,
             h: document.documentElement.clientHeight || window.innerHeight };
  }
  function calc(){
    var d = dims();
    var cols = d.w < 760 ? 1 : 2;
    var stageH = Math.max(200, d.h - 54);
    var rowsFit = Math.max(1, Math.floor(stageH / 300));
    var per = Math.max(1, Math.min(6, cols * rowsFit));
    var fs = Math.min(2.2, Math.max(1.0, d.h / 1000));
    return {cols:cols, per:per, fs:fs};
  }
  function startBar(){
    barfill.style.transition='none'; barfill.style.width='0%';
    void barfill.offsetWidth;
    barfill.style.transition='width '+seconds+'s linear'; barfill.style.width='100%';
  }
  function show(i){
    for(var s=0;s<st.slides.length;s++) st.slides[s].classList.toggle('active', s===i);
    var dl=dotsEl.children;
    for(var d=0;d<dl.length;d++) dl[d].classList.toggle('on', d===i);
    var s0=i*st.per+1, s1=Math.min(panels.length,(i+1)*st.per);
    metaEl.textContent='Showing '+s0+'\\u2013'+s1+' of '+panels.length+
      ' \\u00b7 slide '+(i+1)+'/'+st.pages+' \\u00b7 every '+seconds+'s';
    startBar();
    var pl=st.slides[i].querySelectorAll('.plot');
    for(var q=0;q<pl.length;q++){ try{Plotly.Plots.resize(pl[q]);}catch(e){} }
  }
  function timer(){ clearInterval(st.timer); if(st.pages>1) st.timer=setInterval(function(){ st.idx=(st.idx+1)%st.pages; show(st.idx); }, seconds*1000); }
  function build(){
    var c=calc(); st.cols=c.cols; st.per=c.per;
    var titlePx=Math.round(15*c.fs);
    stage.innerHTML=''; dotsEl.innerHTML=''; st.slides=[];
    st.pages=Math.max(1, Math.ceil(panels.length/c.per));
    if(st.idx>=st.pages) st.idx=0;
    for(var p=0;p<st.pages;p++){
      var slide=document.createElement('div'); slide.className='slide';
      var count=Math.min(c.per, panels.length-p*c.per);
      var rows=Math.max(1, Math.ceil(count/c.cols));
      slide.style.gridTemplateColumns='repeat('+c.cols+', 1fr)';
      slide.style.gridTemplateRows='repeat('+rows+', 1fr)';
      for(var k=p*c.per;k<Math.min(panels.length,(p+1)*c.per);k++){
        var cell=document.createElement('div'); cell.className='cell';
        var t=document.createElement('div'); t.className='ctitle';
        t.style.fontSize=titlePx+'px'; t.textContent=panels[k].title;
        var pd=document.createElement('div'); pd.className='plot';
        cell.appendChild(t); cell.appendChild(pd); slide.appendChild(cell);
        var lay=Object.assign({}, panels[k].fig.layout);
        lay.font=Object.assign({}, lay.font||{}, {size:Math.round(13*c.fs)});
        var data=(panels[k].fig.data||[]).map(function(tr){
          var t=Object.assign({}, tr);
          if(t.type==='bar'){
            t.insidetextfont=Object.assign({}, t.insidetextfont||{}, {size:Math.round(18*c.fs)});
            t.outsidetextfont=Object.assign({}, t.outsidetextfont||{}, {size:Math.round(18*c.fs)});
          } else if(t.type==='scatter' && (t.text || (t.texttemplate && String(t.mode||'').indexOf('text')>=0))){
            t.textfont=Object.assign({}, t.textfont||{}, {size:Math.round(15*c.fs)});
          }
          return t;
        });
        try{ Plotly.newPlot(pd, data, lay, {responsive:true, displayModeBar:false}); }catch(e){}
      }
      stage.appendChild(slide); st.slides.push(slide);
      var dot=document.createElement('div'); dot.className='dot'; dotsEl.appendChild(dot);
    }
    show(st.idx); timer();
  }
  function onResize(){
    fit(); var c=calc();
    if(c.cols!==st.cols || c.per!==st.per){ build(); }
    else { var all=document.querySelectorAll('.plot');
      for(var r=0;r<all.length;r++){ try{Plotly.Plots.resize(all[r]);}catch(e){} } }
  }

  // ---- fullscreen (true PowerPoint-style presentation) ----
  function isFs(){ try{ return !!(window.parent.document.fullscreenElement||window.parent.document.webkitFullscreenElement); }catch(e){ return false; } }
  function enterFs(){
    try{ var el=window.parent.document.documentElement;
      (el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el); }catch(e){}
  }
  function exitFsApi(){
    try{ var doc=window.parent.document;
      (doc.exitFullscreen||doc.webkitExitFullscreen||function(){}).call(doc); }catch(e){}
  }
  function exitPresentation(){
    try{ var u=new URL(window.parent.location.href);
      ['tv','v','d','t0','vw','vh'].forEach(function(k){ u.searchParams.delete(k); });
      window.parent.location.replace(u.toString());
    }catch(e){}
  }
  var wasFs=false;
  function onFsChange(){
    var f=isFs();
    fsbtn.innerHTML = f ? '&#x2715;' : '&#x26F6;';
    fsbtn.title = f ? 'Exit full screen (Esc)' : 'Full screen';
    if(f){ wasFs=true; splash.style.display='none'; }
    if(!f && wasFs){ exitPresentation(); return; }   // Esc / exit -> leave presentation
    setTimeout(onResize, 60);
  }
  startbtn.addEventListener('click', enterFs);
  fsbtn.addEventListener('click', function(){ isFs() ? exitFsApi() : enterFs(); });
  if(isFs()){ splash.style.display='none'; wasFs=true; }

  // auto-hide the floating control, reveal on mouse move
  var hideT;
  function poke(){ fsbtn.classList.add('show'); clearTimeout(hideT);
    hideT=setTimeout(function(){ fsbtn.classList.remove('show'); }, 2500); }
  ['mousemove','click','keydown'].forEach(function(ev){ document.addEventListener(ev, poke); });
  try{ ['mousemove','click','keydown'].forEach(function(ev){ window.parent.document.addEventListener(ev, poke); }); }catch(e){}
  poke();

  fit(); build();
  var rzT;
  function deb(){ clearTimeout(rzT); rzT=setTimeout(onResize, 150); }
  window.addEventListener('resize', deb);
  try{ window.parent.addEventListener('resize', deb); }catch(e){}
  document.addEventListener('fullscreenchange', onFsChange);
  try{
    window.parent.document.addEventListener('fullscreenchange', onFsChange);
    window.parent.document.addEventListener('webkitfullscreenchange', onFsChange);
  }catch(e){}
})();
</script></body></html>"""


def _plain_arrays(obj):
    """Plotly serialises numeric arrays as base64 'typed arrays'
    ({'bdata': ..., 'dtype': ..., 'shape': ...}). The plotly.js loaded for the
    presentation slideshow can mis-read those, which made the big-screen charts
    show wrong/empty values. Decode them back into plain number lists so the
    presented data is exactly what was entered, on any plotly.js version."""
    if isinstance(obj, dict):
        if "bdata" in obj and "dtype" in obj:
            try:
                import base64
                import numpy as np
                raw = base64.b64decode(obj["bdata"])
                arr = np.frombuffer(raw, dtype=np.dtype(obj["dtype"]))
                shape = obj.get("shape")
                if shape:
                    if isinstance(shape, str):
                        shape = tuple(int(s) for s in shape.split(",") if s.strip())
                    arr = arr.reshape(shape)
                return arr.tolist()
            except Exception:
                return obj
        return {k: _plain_arrays(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_plain_arrays(v) for v in obj]
    return obj


def _clear_fig_titles(fig, top=48):
    """Remove a figure's own title (and any gauge/Indicator title) so the single
    styled header above the chart is the only title — never two titles stacked.
    Also tightens the top margin so no empty band is left where the title was."""
    try:
        fig.update_layout(title_text="", margin=dict(t=top))
    except Exception:
        pass
    try:
        for tr in getattr(fig, "data", []):
            if getattr(tr, "type", "") == "indicator":
                tr.title = {"text": ""}
    except Exception:
        pass
    return fig


def _render_chart_card(title, fig):
    """One chart as a self-contained bordered card: the title is the card header and
    the chart sits directly beneath it inside the same border — never detached."""
    with st.container(border=True):
        if title:
            st.markdown(f'<div class="chart-card-title">{title}</div>', unsafe_allow_html=True)
        st.plotly_chart(_clear_fig_titles(fig, top=28), use_container_width=True,
                        theme=None, config={"displayModeBar": False})


def render_tv_slideshow(blocks, seconds=30):
    """Render the whole rotating dashboard as one self-contained component.

    Every chart is drawn once with Plotly.js inside a single iframe; the slides
    then cross-fade in the browser on a timer. Because nothing on the Streamlit
    page re-runs to advance a slide, the screen never blanks or reloads."""
    blocks = [b for b in blocks if b is not None and b[1] is not None]
    if not blocks:
        return

    vw, vh = _tv_viewport()
    cols_n = 1 if vw < 760 else 2
    kpi_pr = _tv_kpi_per_row(vw)
    kpi_rows = (12 + kpi_pr - 1) // kpi_pr
    reserve_outside = 120 + kpi_rows * 64               # header + info line + KPI band
    total_iframe = max(320, vh - reserve_outside)
    stage_h = total_iframe - 48                         # leave room for the footer
    rows_fit = max(1, int(stage_h // 300))              # ~300px-tall charts
    per_page = max(1, min(6, cols_n * rows_fit))        # panels per slide — device adaptive
    fs = min(2.0, max(1.0, vh / 1000.0))                # scale text with screen

    import json
    panels = []
    for title, fig in blocks:
        try:
            _clear_fig_titles(fig, top=24)        # also clears gauge/Indicator titles
            fig.update_layout(
                autosize=True,
                margin=dict(l=16, r=14, t=24, b=44),
                font=dict(size=int(13 * fs)),
                legend=dict(orientation="h", yanchor="bottom", y=1.0, x=1,
                            xanchor="right", font=dict(size=int(10 * fs))))
            fig.update_xaxes(tickfont=dict(size=int(12 * fs)), automargin=True)
            fig.update_yaxes(tickfont=dict(size=int(12 * fs)), automargin=True)
            fig.update_traces(insidetextfont=dict(color="#FFFFFF", size=int(17 * fs)),
                              outsidetextfont=dict(color=INK, size=int(17 * fs)),
                              selector=dict(type="bar"))
            fig.update_traces(textfont=dict(color=INK, size=int(15 * fs)),
                              selector=dict(type="scatter"))
            try:
                fig.layout.height = None
            except Exception:
                pass
            panels.append({"title": title,
                           "fig": _plain_arrays(json.loads(fig.to_json()))})
        except Exception:
            pass

    if not panels:
        # Graceful fallback (e.g. Plotly serialization unavailable): show the first
        # slide's charts statically — still no reload.
        for title, fig in blocks[:per_page]:
            if title:
                st.markdown(f'<div class="tvchart-title">{title}</div>',
                            unsafe_allow_html=True)
            st.plotly_chart(fig, use_container_width=True, theme=None,
                            config={"displayModeBar": False})
        return

    payload = json.dumps({"panels": panels, "seconds": seconds})
    html = TV_SLIDESHOW_HTML.replace("__DATA__", payload)
    try:
        from streamlit.components.v1 import html as _html
        # initial height; the component then self-fits to fill the screen (incl. fullscreen)
        _html(html, height=total_iframe, scrolling=False)
    except Exception:
        for title, fig in blocks[:per_page]:
            st.plotly_chart(fig, use_container_width=True, theme=None,
                            config={"displayModeBar": False})


def show_charts(blocks, tv, seconds=30, per_page=4):
    """Normal mode: one chart per row under its section header.
    Big-screen mode: an auto-rotating slideshow — `per_page` panels at a time,
    advancing every `seconds` and looping, sized to fill the screen cleanly."""
    blocks = [b for b in blocks if b is not None and b[1] is not None]
    if not tv:
        for title, fig in blocks:
            _render_chart_card(title, fig)
        return

    # Seamless slideshow: every chart is drawn once inside a single self-contained
    # component and the slides cross-fade in the browser — no page reload, no blank.
    render_tv_slideshow(blocks, seconds)


def render_tests_block(avail, unavail, suffix=""):
    """Available / not-available test pills, stacked (safe inside columns)."""
    st.markdown(f"**Available ({len(avail)}){suffix}**")
    if avail:
        st.markdown(" ".join(f'<span class="pill" style="background:{OK_GREEN}">✓ {n}</span>'
                             for n in avail), unsafe_allow_html=True)
    else:
        st.caption("None reported.")
    st.markdown(f"**Not available ({len(unavail)})**")
    if unavail:
        st.markdown(" ".join(f'<span class="pill" style="background:{DANGER}">✕ {n}</span>'
                             for n in unavail), unsafe_allow_html=True)
    else:
        st.caption("None.")


def _qp_date(key):
    """Read a YYYY-MM-DD value from the URL query params, defaulting to today."""
    try:
        return date.fromisoformat(st.query_params.get(key, ""))
    except Exception:
        return date.today()


def enter_tv():
    """Enter big-screen slideshow mode. State is stored in the URL so it survives
    the periodic auto-refresh that drives the slideshow."""
    view_sel = st.session_state.get("pub_view", "Day")
    if view_sel.startswith("Week"):
        code, key = "w", "wk_ref"
    elif view_sel.startswith("Month"):
        code, key = "m", "mo_ref"
    else:
        code, key = "s", "dash_day"
    sel = st.session_state.get(key, date.today())
    st.query_params["tv"] = "1"
    st.query_params["v"] = code
    try:
        st.query_params["d"] = sel.isoformat()
    except Exception:
        st.query_params["d"] = date.today().isoformat()
    st.query_params["t0"] = str(int(time.time()))   # slideshow start time
    st.rerun()


def exit_tv():
    for k in ("tv", "v", "d", "t0", "vw", "vh"):
        try:
            del st.query_params[k]
        except Exception:
            pass
    st.session_state.pop("tv_mode", None)
    st.rerun()


def _tv_viewport():
    """Actual browser viewport (px) reported by the client, with safe defaults."""
    def _int(key, default):
        try:
            return int(st.query_params.get(key, "0") or 0) or default
        except Exception:
            return default
    return _int("vw", 1280), _int("vh", 800)


def inject_tv_autosize():
    """Measure the real viewport on the client and store it in the URL, so the
    server can size the slideshow to whatever screen it's displayed on. Re-runs
    on window resize / entering fullscreen, then reloads to re-fit."""
    try:
        from streamlit.components.v1 import html as _html
        _html("""
        <script>
        (function(){
          function sync(){
            try{
              if (window.parent.document.fullscreenElement) return;  // never reload in fullscreen
              var w = window.parent.innerWidth, h = window.parent.innerHeight;
              var u = new URL(window.parent.location.href);
              var sw = parseInt(u.searchParams.get('vw')||'0');
              var sh = parseInt(u.searchParams.get('vh')||'0');
              if (Math.abs(sw-w) > 40 || Math.abs(sh-h) > 40) {
                u.searchParams.set('vw', w);
                u.searchParams.set('vh', h);
                window.parent.location.replace(u.toString());
              }
            } catch(e) {}
          }
          sync();
          if (!window.parent.__tvResize) {
            window.parent.__tvResize = 1;
            window.parent.addEventListener('resize', function(){
              clearTimeout(window.parent.__rz);
              window.parent.__rz = setTimeout(sync, 400);
            });
          }
        })();
        </script>
        """, height=0)
    except Exception:
        pass


def day_picker(state_key, title):
    """Calendar date picker + a Mon–Sun button strip (✓ marks days with data).
    Returns (selected_date, monday, sunday, set_of_dates_with_data)."""
    if state_key not in st.session_state:
        st.session_state[state_key] = date.today()
    picked = st.date_input(title, value=st.session_state[state_key])
    if picked != st.session_state[state_key]:
        st.session_state[state_key] = picked
        st.rerun()
    day = st.session_state[state_key]
    mon, sun = week_bounds(day)
    have = dates_with_data(mon, sun)
    st.caption(f"Week of {mon:%d %b} – {sun:%d %b %Y}  ·  ✓ = data saved for that day")
    cols = st.columns(7)
    for i in range(7):
        dy = mon + timedelta(days=i)
        mark = " ✓" if dy.isoformat() in have else ""
        selected = (dy == day)
        if cols[i].button(f"{dy:%a} {dy:%d}{mark}", key=f"{state_key}_b{i}",
                          type="primary" if selected else "secondary",
                          use_container_width=True):
            st.session_state[state_key] = dy
            st.rerun()
    return st.session_state[state_key], mon, sun, have


def dept_pills(pairs):
    st.markdown(" ".join(
        f'<span class="pill" style="background:{STATUS_COLOR.get(s,"#777")}">{n}: {s}</span>'
        for n, s in pairs), unsafe_allow_html=True)


def day_dataframe(day, scalars, depts, meds, tests, blood):
    """Flatten one day's full record into a tidy CSV-ready table:
    Date, Section, Item, Value, Detail."""
    ds = day.isoformat()
    s = scalars or {}
    label_map = {k: lbl for k, lbl, _ in DAILY_FIELDS}
    group_map = {k: grp for k, lbl, grp in DAILY_FIELDS}
    rows = []
    for k in FIELD_KEYS:
        rows.append({"Date": ds, "Section": group_map[k], "Item": label_map[k],
                     "Value": int(s.get(k, 0) or 0), "Detail": ""})
    if s.get("beds_total"):
        occ = (s["beds_total"] - s["beds_available"]) / s["beds_total"] * 100
        rows.append({"Date": ds, "Section": "Capacity", "Item": "Bed occupancy (%)",
                     "Value": round(occ, 1), "Detail": ""})
    for _, r in depts.iterrows():
        rows.append({"Date": ds, "Section": "Department", "Item": r["Department"],
                     "Value": r["Status"], "Detail": ""})
    for _, r in meds.iterrows():
        rows.append({"Date": ds, "Section": "Medication", "Item": r["Medication"],
                     "Value": str(r.get("Status", "") or ""), "Detail": ""})
    for _, r in tests.iterrows():
        rows.append({"Date": ds, "Section": "Test", "Item": r["Test"],
                     "Value": "Available" if r["Available"] else "Not available", "Detail": ""})
    for _, r in blood.iterrows():
        rows.append({"Date": ds, "Section": "Blood Bank", "Item": r["Blood Type"],
                     "Value": int(r["Units"] or 0), "Detail": "units"})
    if s.get("notes"):
        rows.append({"Date": ds, "Section": "Notes", "Item": "Notes",
                     "Value": s.get("notes"), "Detail": ""})
    return pd.DataFrame(rows, columns=["Date", "Section", "Item", "Value", "Detail"])


def day_csv_bytes(day, scalars, depts, meds, tests, blood):
    return day_dataframe(day, scalars, depts, meds, tests, blood).to_csv(index=False).encode("utf-8")


def _draw_icon(ax, key, cx, cy, s, color):
    """Draw a simple vector icon centered at (cx,cy), spanning ~s, for the PDF
    'At a Glance' tiles (font-independent so it always renders)."""
    import matplotlib.patches as mp
    WHITE = "#FFFFFF"

    def P(u, v):
        return (cx + u * s, cy + v * s)

    def circle(u, v, r, fill=True, col=None):
        col = col or color
        ax.add_patch(mp.Circle(P(u, v), r * s, facecolor=(col if fill else "none"),
                               edgecolor=col, linewidth=1.3, zorder=5))

    def rect(u, v, w, h, fill=True, rounded=0.0, col=None):
        col = col or color
        fc = col if fill else "none"
        if rounded > 0:
            ax.add_patch(mp.FancyBboxPatch((cx + u * s, cy + v * s), w * s, h * s,
                         boxstyle=f"round,pad=0,rounding_size={rounded*s}",
                         facecolor=fc, edgecolor=col, linewidth=1.3, zorder=5))
        else:
            ax.add_patch(mp.Rectangle((cx + u * s, cy + v * s), w * s, h * s,
                         facecolor=fc, edgecolor=col, linewidth=1.3, zorder=5))

    def line(u1, v1, u2, v2, w=1.8, col=None):
        col = col or color
        ax.plot([cx + u1 * s, cx + u2 * s], [cy + v1 * s, cy + v2 * s],
                color=col, linewidth=w, solid_capstyle="round", zorder=6)

    def poly(pts, fill=True, col=None):
        col = col or color
        ax.add_patch(mp.Polygon([P(u, v) for u, v in pts], closed=True,
                     facecolor=(col if fill else "none"), edgecolor=col, linewidth=1.3, zorder=5))

    def wedge(u, v, r, t1, t2, col=None):
        col = col or color
        ax.add_patch(mp.Wedge(P(u, v), r * s, t1, t2, facecolor=col, edgecolor=col, zorder=5))

    def plus(u, v, hw, hh, col):
        rect(u - hw, v - hh * 0.32, hw * 2, hh * 0.64, col=col)
        rect(u - hw * 0.32, v - hh, hw * 0.64, hh * 2, col=col)

    if key == "patient":
        circle(0, 0.28, 0.16)
        poly([(-0.28, -0.34), (0.28, -0.34), (0.18, 0.06), (-0.18, 0.06)])
    elif key == "bed":
        rect(-0.34, -0.16, 0.68, 0.16, rounded=0.04)
        rect(-0.40, -0.16, 0.06, 0.34)
        rect(-0.30, 0.00, 0.16, 0.09, rounded=0.03, col=WHITE)
        line(-0.36, -0.16, -0.36, -0.30); line(0.30, -0.16, 0.30, -0.30)
    elif key == "admit":
        line(0, 0.34, 0, -0.04, w=2.4)
        poly([(-0.12, -0.02), (0.12, -0.02), (0, -0.20)])
        line(-0.28, -0.28, 0.28, -0.28, w=2.4)
    elif key == "discharge":
        line(0, -0.30, 0, 0.12, w=2.4)
        poly([(-0.12, 0.12), (0.12, 0.12), (0, 0.30)])
        line(-0.28, -0.30, 0.28, -0.30, w=2.4)
    elif key == "er":
        plus(0, 0, 0.34, 0.34, color)
    elif key == "surgery":
        line(-0.30, -0.28, 0.10, 0.12, w=3.2)
        poly([(0.10, 0.12), (0.32, 0.32), (0.30, 0.12)])
    elif key == "birth":
        circle(0, 0.20, 0.15)
        poly([(-0.22, -0.34), (0.22, -0.34), (0.15, 0.04), (-0.15, 0.04)])
        circle(0, 0.20, 0.05, col=WHITE)
    elif key == "death":
        rect(-0.24, -0.34, 0.48, 0.42)
        wedge(0, 0.08, 0.24, 0, 180)
        plus(0, 0.04, 0.10, 0.14, WHITE)
    elif key == "doctor":
        circle(0, 0.28, 0.15)
        poly([(-0.28, -0.34), (0.28, -0.34), (0.18, 0.05), (-0.18, 0.05)])
        plus(0, -0.14, 0.09, 0.11, WHITE)
    elif key == "nurse":
        plus(0, 0.40, 0.06, 0.07, color)
        circle(0, 0.22, 0.15)
        poly([(-0.28, -0.34), (0.28, -0.34), (0.18, 0.00), (-0.18, 0.00)])
    elif key == "ambulance":
        rect(-0.40, -0.18, 0.58, 0.34, rounded=0.04)
        poly([(0.18, -0.18), (0.40, -0.18), (0.40, 0.04), (0.18, 0.12)])
        rect(0.20, -0.04, 0.14, 0.10, col=WHITE)
        plus(-0.18, 0.02, 0.10, 0.10, WHITE)
        circle(-0.20, -0.22, 0.08); circle(0.18, -0.22, 0.08)
    elif key == "oxygen":
        rect(-0.16, -0.34, 0.32, 0.58, rounded=0.10)
        rect(-0.06, 0.22, 0.12, 0.10)
        rect(-0.16, -0.12, 0.32, 0.10, col=WHITE)
    elif key == "calendar":
        rect(-0.32, -0.30, 0.64, 0.56, fill=False, rounded=0.04)
        rect(-0.32, 0.12, 0.64, 0.14)
        line(-0.18, 0.20, -0.18, 0.34, w=2.4); line(0.18, 0.20, 0.18, 0.34, w=2.4)
    else:
        circle(0, 0, 0.22, fill=False)


def build_glance_image(items, color=PRIMARY, ncol=4):
    """Render an 'At a Glance' grid of KPI tiles (icon + value + label) as a PNG.
    Returns (BytesIO, aspect_ratio)."""
    import io
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mp

    nrow = (len(items) + ncol - 1) // ncol
    fw = 7.4
    fh = 1.5 * nrow
    fig, ax = plt.subplots(figsize=(fw, fh))
    ax.set_xlim(0, ncol); ax.set_ylim(0, nrow); ax.axis("off")
    for i, (key, label, value) in enumerate(items):
        c = i % ncol
        r = i // ncol
        x = c
        y = nrow - 1 - r
        ax.add_patch(mp.FancyBboxPatch((x + 0.05, y + 0.05), 0.90, 0.90,
                     boxstyle="round,pad=0,rounding_size=0.10",
                     facecolor="#F0FAFA", edgecolor="#CFE6E6", linewidth=1.1))
        _draw_icon(ax, key, x + 0.5, y + 0.68, 0.28, color)
        ax.text(x + 0.5, y + 0.40, str(value), ha="center", va="center",
                fontsize=15, fontweight="bold", color=color)
        ax.text(x + 0.5, y + 0.16, label, ha="center", va="center",
                fontsize=7.3, color="#5E7373")
    fig.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    b = io.BytesIO()
    fig.savefig(b, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    b.seek(0)
    return (b, fh / fw)


def build_day_pdf(day, scalars, depts, meds, tests, blood, hospital_name):
    """A themed one-page-plus PDF report for a single day."""
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable, Image as RLImage)
    s = scalars or {}

    # ── optional charts (matplotlib → PNG) ──
    charts = {}
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        def _bar(pairs, title, horizontal=False, color=PRIMARY):
            labels = [p[0] for p in pairs]
            vals = [p[1] for p in pairs]
            fw, fh = (6.6, max(2.4, 0.45 * len(labels) + 1)) if horizontal else (6.6, 3.0)
            fig, ax = plt.subplots(figsize=(fw, fh))
            if horizontal:
                bars = ax.barh(labels, vals, color=color); ax.invert_yaxis()
            else:
                bars = ax.bar(labels, vals, color=color)
            ax.bar_label(bars, padding=3, fontsize=8)
            ax.set_title(title, fontsize=11, fontweight="bold", color=PRIMARY)
            ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
            ax.tick_params(labelsize=8)
            fig.tight_layout()
            b = io.BytesIO(); fig.savefig(b, format="png", dpi=150, bbox_inches="tight")
            plt.close(fig); b.seek(0)
            return (b, fh / fw)

        charts["patients"] = _bar(
            [("Admissions", int(s.get("admitted", 0))), ("Discharges", int(s.get("discharged", 0))),
             ("ER visits", int(s.get("er_visits", 0))), ("ICU", int(s.get("icu_patients", 0))),
             ("Surgeries", int(s.get("surgeries", 0))), ("Births", int(s.get("births", 0))),
             ("Deaths", int(s.get("deaths", 0))), ("Referrals out", int(s.get("referrals_out", 0)))],
            "Patient activity", horizontal=True, color=PRIMARY)
        charts["staff"] = _bar(
            [("Doctors", int(s.get("doctors", 0))), ("Nurses", int(s.get("nurses", 0))),
             ("Support", int(s.get("support_staff", 0))), ("Specialists", int(s.get("specialists_on_call", 0)))],
            "Staff on duty", color=TEAL2)
        if not blood.empty and blood["Units"].sum() > 0:
            charts["blood"] = _bar([(r["Blood Type"], int(r["Units"])) for _, r in blood.iterrows()],
                                   "Blood bank units by type", color=DANGER)
    except Exception:
        charts = {}

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=14 * mm,
                            title=f"Daily Report {day.isoformat()}")
    base = getSampleStyleSheet()
    title_style = ParagraphStyle("t", parent=base["Title"], fontSize=20,
                                 textColor=colors.HexColor(INK), spaceAfter=2, alignment=TA_CENTER)
    sub_style = ParagraphStyle("s", parent=base["Normal"], fontSize=10.5, textColor=colors.grey,
                               alignment=TA_CENTER, spaceAfter=10)
    h_style = ParagraphStyle("h", parent=base["Heading2"], fontSize=12.5,
                             textColor=colors.HexColor(PRIMARY), spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13)
    small = ParagraphStyle("sm", parent=base["Normal"], fontSize=8.5, textColor=colors.grey)

    def hr():
        return HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#BFE0E0"),
                          spaceBefore=2, spaceAfter=8)

    def section(t):
        return [Paragraph(t, h_style), hr()]

    def kv_table(rows, widths=(95 * mm, 65 * mm)):
        data = [[Paragraph(f"<b>{k}</b>", body), Paragraph(str(v), body)] for k, v in rows]
        t = Table(data, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#D8F0F0")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BFE0E0")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor(LIGHT_BG)]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    def img(item, width=170 * mm):
        b, ar = item
        return RLImage(b, width=width, height=width * ar)

    def grp_rows(group):
        return [(lbl, int(s.get(k, 0))) for k, lbl, g in DAILY_FIELDS if g == group]

    story = []
    story.append(Paragraph(f"{hospital_name}", title_style))
    story.append(Paragraph(f"Daily Report &nbsp;•&nbsp; {day:%A, %d %B %Y}", sub_style))
    story.append(Paragraph(f"Generated {datetime.now():%d %b %Y %H:%M}", small))
    story.append(Spacer(1, 6))

    # ── At a Glance (KPI tiles with icons) ──
    occ_txt = "—"
    if s.get("beds_total"):
        occ_txt = f"{(s['beds_total'] - s['beds_available']) / s['beds_total'] * 100:.0f}%"
    ox = int(s.get("oxygen_pct", 0))
    avail = int(s.get("ambulances_available", 0))
    total = int(s.get("ambulances_total", 0))
    glance_items = [
        ("patient", "Patients in hospital", int(s.get("current_inpatients", 0))),
        ("admit", "New admissions", int(s.get("admitted", 0))),
        ("discharge", "Discharged", int(s.get("discharged", 0))),
        ("er", "ER visits", int(s.get("er_visits", 0))),
        ("surgery", "Surgeries", int(s.get("surgeries", 0))),
        ("birth", "Births", int(s.get("births", 0))),
        ("death", "Deaths", int(s.get("deaths", 0))),
        ("bed", "Bed occupancy", occ_txt),
        ("doctor", "Doctors on duty", int(s.get("doctors", 0))),
        ("nurse", "Nurses on duty", int(s.get("nurses", 0))),
        ("ambulance", "Ambulances", f"{avail}/{total}"),
        ("oxygen", "Oxygen supply", f"{ox}%"),
    ]
    try:
        story += section("At a Glance")
        story.append(img(build_glance_image(glance_items)))
    except Exception:
        pass

    # Patients + occupancy
    story += section("Patients")
    story.append(kv_table(grp_rows("Patients")))
    if charts.get("patients"):
        story.append(Spacer(1, 6)); story.append(img(charts["patients"]))

    # Capacity (with occupancy)
    story += section("Capacity")
    cap = grp_rows("Capacity")
    if s.get("beds_total"):
        occ = (s["beds_total"] - s["beds_available"]) / s["beds_total"] * 100
        cap = cap + [("Bed occupancy (%)", f"{occ:.0f}%")]
    story.append(kv_table(cap))

    # Staff
    story += section("Staff on Duty")
    story.append(kv_table(grp_rows("Staff")))
    if charts.get("staff"):
        story.append(Spacer(1, 6)); story.append(img(charts["staff"]))

    # Ambulances + supplies
    story += section("Ambulances & Emergency")
    story.append(kv_table(grp_rows("Ambulances & Emergency")))
    story += section("Critical Supplies")
    story.append(kv_table(grp_rows("Critical Supplies")))

    # Blood bank
    if not blood.empty:
        story += section("Blood Bank")
        bt = [["Blood Type", "Units"]] + [[r["Blood Type"], str(int(r["Units"]))]
                                          for _, r in blood.iterrows()]
        t = Table(bt, colWidths=(80 * mm, 80 * mm))
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(PRIMARY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BFE0E0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT_BG)]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(t)
        if charts.get("blood"):
            story.append(Spacer(1, 6)); story.append(img(charts["blood"]))

    # Departments (status colour-coded)
    if not depts.empty:
        story += section("Department Status")
        rows = [["Department", "Status"]] + [[r["Department"], r["Status"]]
                                             for _, r in depts.iterrows()]
        t = Table(rows, colWidths=(110 * mm, 50 * mm))
        ts = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(PRIMARY)),
              ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
              ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
              ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BFE0E0")),
              ("FONTSIZE", (0, 0), (-1, -1), 9)]
        for i, (_, r) in enumerate(depts.iterrows(), start=1):
            col = STATUS_COLOR.get(r["Status"], "#777777")
            ts.append(("BACKGROUND", (1, i), (1, i), colors.HexColor(col)))
            ts.append(("TEXTCOLOR", (1, i), (1, i), colors.white))
        t.setStyle(TableStyle(ts))
        story.append(t)

    # Medications
    if not meds.empty:
        story += section("Medication Availability")
        rows = [["Medication", "Availability"]] + [
            [r["Medication"], str(r.get("Status", "") or "")]
            for _, r in meds.iterrows()]
        t = Table(rows, colWidths=(110 * mm, 50 * mm))
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(PRIMARY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BFE0E0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT_BG)]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(t)

    # Tests
    if not tests.empty:
        story += section("Medical Tests")
        rows = [["Test", "Available"]] + [
            [r["Test"], "Yes" if r["Available"] else "No"] for _, r in tests.iterrows()]
        t = Table(rows, colWidths=(120 * mm, 40 * mm))
        ts = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(PRIMARY)),
              ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
              ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
              ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BFE0E0")),
              ("FONTSIZE", (0, 0), (-1, -1), 9)]
        for i, (_, r) in enumerate(tests.iterrows(), start=1):
            col = OK_GREEN if r["Available"] else DANGER
            ts.append(("BACKGROUND", (1, i), (1, i), colors.HexColor(col)))
            ts.append(("TEXTCOLOR", (1, i), (1, i), colors.white))
        t.setStyle(TableStyle(ts))
        story.append(t)

    # Notes
    if s.get("notes"):
        story += section("Notes")
        story.append(Paragraph(str(s["notes"]).replace("\n", "<br/>"), body))

    story.append(Spacer(1, 10))
    story.append(hr())
    story.append(Paragraph(
        "Automatically generated by the Hospital Dashboard. Figures as entered by the analyst for this day.",
        small))

    doc.build(story)
    return buf.getvalue()


# ══════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════
st.sidebar.markdown(
    f'<div style="text-align:center;background:#FFFFFF;border:1px solid {GRID};'
    f'border-radius:12px;padding:10px 8px;margin-bottom:8px;">'
    f'<img src="data:image/jpeg;base64,{HDM_LOGO_B64}" style="width:150px;max-width:92%;"/>'
    f'</div>', unsafe_allow_html=True)
st.sidebar.markdown(f"#### {HOSPITAL_NAME}")
mode = st.sidebar.radio("View", ["Public Dashboard", "Data Entry (Analyst)"])
st.sidebar.toggle("🌙 Dark mode", key="ui_dark",
                  help="Switch between light and dark display. Light is the default.")
st.sidebar.divider()

# auto sign-out on inactivity + manual logout
if st.session_state.get("authed"):
    if time.time() - st.session_state.get("auth_time", 0) > SESSION_TIMEOUT:
        st.session_state.pop("authed", None)
        st.session_state.pop("auth_time", None)
    elif st.sidebar.button("🔒 Log out", use_container_width=True):
        for _k in ("authed", "auth_time", "fails", "lock_until"):
            st.session_state.pop(_k, None)
        st.rerun()

st.sidebar.caption("Public view is read-only. Data entry needs the analyst password.")
if not ADMIN_HASH and ADMIN_PASSWORD == "changeme":
    st.sidebar.warning("Default analyst password in use. Set HOSPITAL_ADMIN_PASSWORD — or better, a "
                       "hashed HOSPITAL_ADMIN_PASSWORD_HASH — before deploying publicly.")

# Big-screen / TV slideshow toggle (Public Dashboard only)
if mode == "Public Dashboard":
    st.sidebar.divider()
    if st.query_params.get("tv") == "1":
        if st.sidebar.button("✕ Exit big-screen mode", use_container_width=True):
            exit_tv()
    else:
        if st.sidebar.button("📺 Display on TV / big screen", use_container_width=True):
            enter_tv()


# ══════════════════════════════════════════════
# DATA ENTRY MODE
# ══════════════════════════════════════════════
if mode == "Data Entry (Analyst)":
    st.markdown('<div class="big-title">Daily Data Entry</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub">Pick a day from the calendar, fill in that day\'s figures, '
                'and save. Each saved day powers its own dashboard.</div>', unsafe_allow_html=True)

    if not st.session_state.get("authed"):
        now = time.time()
        lock_until = st.session_state.get("lock_until", 0)
        if now < lock_until:
            st.error(f"Too many attempts. Try again in {int(lock_until - now)} seconds.")
            st.stop()
        pw = st.text_input("Analyst password", type="password")
        code = ""
        if two_factor_enabled():
            code = st.text_input("Authenticator code (6 digits)", max_chars=6,
                                 help="From your authenticator app (Google Authenticator, "
                                      "Authy, 1Password, etc.).")
        if st.button("Unlock", type="primary"):
            pw_ok = verify_password(pw)
            otp_ok = (not two_factor_enabled()) or totp_verify(TOTP_SECRET, code)
            if pw_ok and otp_ok:
                st.session_state.authed = True
                st.session_state.auth_time = time.time()
                st.session_state.fails = 0
                st.session_state.pop("lock_until", None)
                try:
                    set_setting("last_login", datetime.now().isoformat(timespec="seconds"))
                except Exception:
                    pass
                st.rerun()
            else:
                # throttle every failed attempt to slow brute-force/guessing
                fails = st.session_state.get("fails", 0) + 1
                st.session_state.fails = fails
                time.sleep(min(3.0, THROTTLE_BASE * fails))
                if fails >= MAX_FAILS:
                    st.session_state.lock_until = time.time() + LOCK_SECONDS
                    st.session_state.fails = 0
                    st.error(f"Too many failed attempts. Locked for {LOCK_SECONDS} seconds.")
                else:
                    left = MAX_FAILS - fails
                    msg = "Incorrect credentials." if two_factor_enabled() else "Incorrect password."
                    st.error(f"{msg} {left} attempt(s) left before a temporary lock.")
        st.stop()

    with st.expander("⚙️ Settings"):
        new_name = st.text_input("Hospital name (shown publicly)", value=HOSPITAL_NAME)
        if st.button("Save name"):
            set_setting("hospital_name", new_name.strip() or "General Hospital")
            st.success("Saved. Reload to update it everywhere.")

        st.divider()
        st.markdown("**Account & security**")
        _last = get_setting("last_login", "")
        st.caption(("🔐 Two-factor authentication is **on**." if two_factor_enabled()
                    else "🔓 Two-factor authentication is off (optional).")
                   + (f"  •  Last sign-in: {_last}." if _last else ""))
        if not ADMIN_HASH:
            st.caption("⚠️ Using a plaintext password. Generate a salted hash below and store it "
                       "as `HOSPITAL_ADMIN_PASSWORD_HASH` for much stronger protection.")

        st.markdown("**Create a hashed password**")
        st.caption("Generate a salted PBKDF2 hash, then set it as the "
                   "`HOSPITAL_ADMIN_PASSWORD_HASH` secret (or env var) and restart. "
                   "The plaintext is never stored. Use 12+ characters.")
        npw = st.text_input("New analyst password", type="password", key="newpw")
        if st.button("Generate hash"):
            if len(npw) < 8:
                st.warning("Use at least 8 characters (12+ recommended).")
            else:
                if len(npw) < 12:
                    st.caption("Tip: 12+ characters is recommended.")
                st.code(make_password_hash(npw), language="text")

        st.markdown("**Set up two-factor authentication (optional)**")
        st.caption("Generate a secret, store it as `HOSPITAL_ADMIN_TOTP_SECRET`, then add it to "
                   "an authenticator app using the key (or otpauth link) below, and restart.")
        if st.button("Generate 2FA secret"):
            _sec = _b32_secret()
            _label = (HOSPITAL_NAME or "Hospital").replace(" ", "%20")
            st.code(_sec, language="text")
            st.caption("otpauth link (add to your authenticator app):")
            st.code(f"otpauth://totp/{_label}:analyst?secret={_sec}&issuer={_label}",
                    language="text")

    st.markdown('<div class="section">Select the day</div>', unsafe_allow_html=True)
    entry_date, _, _, _ = day_picker("entry_day", "Pick a day (calendar)")
    st.info(f"Entering data for **{entry_date:%A, %d %b %Y}**")

    scalars, depts, meds, tests, blood = load_day(entry_date)
    if scalars:
        st.caption(f"An entry already exists (updated {scalars.get('updated_at','—')}). "
                   "Saving overwrites it.")

    def num_val(key):
        return int(scalars[key]) if scalars and scalars.get(key) is not None else 0

    numeric = {}
    for group in FIELD_GROUPS:
        st.markdown(f'<div class="section">{group}</div>', unsafe_allow_html=True)
        fields = [f for f in DAILY_FIELDS if f[2] == group]
        for i in range(0, len(fields), 3):
            cols = st.columns(3)
            for col, (key, label, _) in zip(cols, fields[i:i+3]):
                maxv = 100 if key == "oxygen_pct" else 1_000_000
                numeric[key] = col.number_input(label, 0, maxv, num_val(key), key=f"in_{key}")

    if numeric.get("beds_total", 0) > 0:
        occ = numeric["beds_total"] - numeric["beds_available"]
        st.caption(f"➡️ Calculated bed occupancy: **{occ:,} / {numeric['beds_total']:,} "
                   f"({occ / numeric['beds_total'] * 100:.0f}%)**")

    # gentle, non-blocking sanity checks so obvious typos are caught before saving
    _warnings = []
    if numeric.get("beds_available", 0) > numeric.get("beds_total", 0):
        _warnings.append("Beds available is greater than total beds.")
    if numeric.get("icu_beds_available", 0) > numeric.get("beds_total", 0):
        _warnings.append("ICU beds available is greater than total beds.")
    if numeric.get("ambulances_available", 0) > numeric.get("ambulances_total", 0):
        _warnings.append("Ambulances available is greater than the fleet total.")
    if numeric.get("icu_patients", 0) > numeric.get("current_inpatients", 0):
        _warnings.append("ICU patients is greater than total inpatients.")
    if _warnings:
        st.warning("Please double-check: " + "  ".join("• " + w for w in _warnings)
                   + "  (You can still save — these are just reminders.)")

    st.markdown('<div class="section">Blood Bank (units by type)</div>', unsafe_allow_html=True)
    if blood.empty:
        blood = pd.DataFrame({"Blood Type": BLOOD_TYPES, "Units": [0] * len(BLOOD_TYPES)})
    blood_edit = st.data_editor(
        blood, num_rows="dynamic", use_container_width=True, key="blood_ed",
        column_config={"Blood Type": st.column_config.SelectboxColumn("Blood Type", options=BLOOD_TYPES, required=True),
                       "Units": st.column_config.NumberColumn("Units", min_value=0, step=1)})

    st.markdown('<div class="section">Operational Departments</div>', unsafe_allow_html=True)
    if depts.empty:
        depts = pd.DataFrame({"Department": DEFAULT_DEPARTMENTS,
                              "Status": ["Operational"] * len(DEFAULT_DEPARTMENTS)})
    dept_edit = st.data_editor(
        depts, num_rows="dynamic", use_container_width=True, key="dept_ed",
        column_config={"Department": st.column_config.TextColumn("Department", required=True),
                       "Status": st.column_config.SelectboxColumn("Status", options=DEPT_STATUSES, required=True)})

    st.markdown('<div class="section">Medication Availability</div>', unsafe_allow_html=True)
    st.caption("Set each medication's availability. Add or remove rows as needed.")
    if meds.empty:
        meds = pd.DataFrame(DEFAULT_MEDICATIONS, columns=["Medication", "Status"])
    med_edit = st.data_editor(
        meds, num_rows="dynamic", use_container_width=True, key="med_ed",
        column_config={"Medication": st.column_config.TextColumn("Medication", required=True),
                       "Status": st.column_config.SelectboxColumn("Status", options=MED_STATUSES,
                                                                  required=True)})

    st.markdown('<div class="section">Medical Tests Available Today</div>', unsafe_allow_html=True)
    if tests.empty:
        tests = pd.DataFrame({"Test": DEFAULT_TESTS, "Available": [True] * len(DEFAULT_TESTS)})
    test_edit = st.data_editor(
        tests, num_rows="dynamic", use_container_width=True, key="test_ed",
        column_config={"Test": st.column_config.TextColumn("Test", required=True),
                       "Available": st.column_config.CheckboxColumn("Available")})

    notes = st.text_area("Notes (optional)", value=scalars["notes"] if scalars else "")

    if st.button("💾 Save this day", type="primary", use_container_width=True):
        save_day(entry_date, numeric, notes, dept_edit, med_edit, test_edit, blood_edit)
        st.session_state.auth_time = time.time()   # keep the session alive on activity
        st.success(f"Saved entry for {entry_date:%A, %d %b %Y}.")
        st.balloons()

    # download the saved data for the selected day (reloaded fresh from the database)
    _s, _dp, _md, _ts, _bl = load_day(entry_date)
    if _s or not _dp.empty or not _md.empty or not _ts.empty or not _bl.empty:
        dl = st.columns(2)
        dl[0].download_button(
            "⬇️ Download this day's saved data (CSV)",
            day_csv_bytes(entry_date, _s, _dp, _md, _ts, _bl),
            file_name=f"hospital_{entry_date:%Y%m%d}.csv", mime="text/csv",
            use_container_width=True)
        dl[1].download_button(
            "📄 Download this day's report (PDF)",
            build_day_pdf(entry_date, _s, _dp, _md, _ts, _bl, HOSPITAL_NAME),
            file_name=f"hospital_report_{entry_date:%Y%m%d}.pdf", mime="application/pdf",
            use_container_width=True)


# ══════════════════════════════════════════════
# PUBLIC DASHBOARD MODE
# ══════════════════════════════════════════════
else:
    tv = st.query_params.get("tv") == "1"
    if tv:
        st.markdown(TV_CSS, unsafe_allow_html=True)
        inject_tv_autosize()

    if tv:
        # ---- professional presentation header ----
        _v = st.query_params.get("v")
        view = {"w": "Week", "m": "Month"}.get(_v, "Day")
        _sel = _qp_date("d")
        if view.startswith("Week"):
            _ws, _we = week_bounds(_sel)
            _info = f"Week · {_ws:%d %b} – {_we:%d %b %Y}"
        elif view.startswith("Month"):
            _ms, _me = month_bounds(_sel)
            _info = f"Month · {_ms:%B %Y}"
        else:
            _info = f"Day · {_sel:%A, %d %b %Y}"
        # compact exit affordance, then a full-width branded header bar
        ec = st.columns([8.6, 1.4])
        with ec[1]:
            if st.button("✕ Exit", use_container_width=True):
                exit_tv()
        st.markdown(
            '<div class="tvhead">'
            f'<img class="tvlogo" src="data:image/jpeg;base64,{HDM_LOGO_B64}"/>'
            f'<div class="tvname">{HOSPITAL_NAME}</div>'
            f'<div class="tvhead-meta">{_info}'
            f'<span class="tvhead-upd">updated {datetime.now():%H:%M}</span></div>'
            '</div>', unsafe_allow_html=True)
    else:
        head = st.columns([7, 2])
        with head[0]:
            st.markdown(
                '<div class="big-title">'
                f'<img src="data:image/jpeg;base64,{HDM_LOGO_B64}" '
                'style="height:1.15em;width:auto;vertical-align:middle;'
                'margin-right:.45em;border-radius:5px;"/>'
                f'{HOSPITAL_NAME} — Dashboard</div>',
                unsafe_allow_html=True)
        with head[1]:
            if st.button("📺 Present on big screen", use_container_width=True):
                enter_tv()
        view = st.radio("View", ["Day", "Week", "Month"],
                        horizontal=True, key="pub_view")

    # ──────────────────────────────────────────
    # SINGLE-DAY DASHBOARD
    # ──────────────────────────────────────────
    if view == "Day":
        if tv:
            day = _qp_date("d")
        else:
            day, _, _, _ = day_picker("dash_day", "Choose a day (calendar)")
            st.markdown(f'<div class="sub">Showing <b>{day:%A, %d %b %Y}</b> &nbsp;•&nbsp; '
                        f'updated {datetime.now():%H:%M}</div>', unsafe_allow_html=True)

        scalars, depts, meds, tests, blood = load_day(day)
        if not scalars and depts.empty and meds.empty and tests.empty and blood.empty:
            st.info(f"No data recorded for {day:%A, %d %b %Y}. An analyst can add it in "
                    "the **Data Entry** view.")
            st.stop()
        s = scalars or {k: 0 for k in FIELD_KEYS}

        # download everything entered for this specific day (hidden in presentation mode)
        if not tv:
            dl = st.columns(2)
            dl[0].download_button(
                "⬇️ Download this day's data (CSV)",
                day_csv_bytes(day, scalars, depts, meds, tests, blood),
                file_name=f"hospital_{day:%Y%m%d}.csv", mime="text/csv",
                use_container_width=True)
            dl[1].download_button(
                "📄 Download this day's report (PDF)",
                build_day_pdf(day, scalars, depts, meds, tests, blood, HOSPITAL_NAME),
                file_name=f"hospital_report_{day:%Y%m%d}.pdf", mime="application/pdf",
                use_container_width=True)

        # ── Performance dashboard (always shown first) ──
        perf_summary = health_summary(*perf_inputs_single(s, depts, meds, tests, blood))
        perf_figs_list = performance_figs(perf_summary)
        if tv:
            perf_blocks = perf_figs_list
        else:
            render_performance_normal(perf_summary, perf_figs_list)
            perf_blocks = []

        # KPI cards
        st.markdown('<div class="section">At a Glance</div>', unsafe_allow_html=True)
        occ_txt = "—"
        if s.get("beds_total"):
            occ_txt = f"{(s['beds_total'] - s['beds_available']) / s['beds_total'] * 100:.0f}%"
        kpis = [
            ("🤒 Patients in hospital", int(s.get("current_inpatients", 0))),
            ("📥 New admissions", int(s.get("admitted", 0))),
            ("📤 Discharged", int(s.get("discharged", 0))),
            ("🚨 ER visits", int(s.get("er_visits", 0))),
            ("🔪 Surgeries", int(s.get("surgeries", 0))),
            ("👶 Births", int(s.get("births", 0))),
            ("⚰️ Deaths", int(s.get("deaths", 0))),
            ("🛏️ Bed occupancy", occ_txt),
            ("🧑‍⚕️ Doctors on duty", int(s.get("doctors", 0))),
            ("👩‍⚕️ Nurses on duty", int(s.get("nurses", 0))),
            ("🚑 Ambulances",
             f"{int(s.get('ambulances_available', 0))}/{int(s.get('ambulances_total', 0))}"),
            ("🫁 Oxygen supply", f"{int(s.get('oxygen_pct', 0))}%"),
        ]
        render_kpis(kpis, tv)

        day_blocks = []

        # Patient activity (horizontal bars — labels inside)
        cats = [("Admissions", "admitted"), ("Discharges", "discharged"),
                ("ER visits", "er_visits"), ("ICU patients", "icu_patients"),
                ("Surgeries", "surgeries"), ("Births", "births"),
                ("Deaths", "deaths"), ("Referrals out", "referrals_out")]
        pdf = pd.DataFrame({"Metric": [c[0] for c in cats],
                            "Count": [int(s.get(c[1], 0)) for c in cats]})
        figp = px.bar(pdf, x="Count", y="Metric", orientation="h",
                      title="Patients today", color_discrete_sequence=[PRIMARY])
        figp.update_layout(showlegend=False, yaxis=dict(autorange="reversed"))
        day_blocks.append(("Patient Activity", style_fig(figp, h=420)))

        # Staff
        sdf = pd.DataFrame({"Role": ["Doctors", "Nurses", "Support", "Specialists"],
                            "Count": [int(s.get("doctors", 0)), int(s.get("nurses", 0)),
                                      int(s.get("support_staff", 0)),
                                      int(s.get("specialists_on_call", 0))]})
        figs = px.bar(sdf, x="Role", y="Count", title="Staff today",
                      color_discrete_sequence=[TEAL2])
        figs.update_layout(showlegend=False)
        day_blocks.append(("Staff on Duty", style_fig(figs, h=340)))

        # Oxygen gauge
        ox = int(s.get("oxygen_pct", 0))
        ox_color = OK_GREEN if ox >= 50 else WARN if ox >= 25 else DANGER
        figo = go.Figure(go.Indicator(
            mode="gauge+number", value=ox, number={"suffix": "%"},
            title={"text": "Oxygen supply level"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": ox_color},
                   "steps": [{"range": [0, 25], "color": "#fde2e2"},
                             {"range": [25, 50], "color": "#fdf0db"},
                             {"range": [50, 100], "color": "#e3f5ea"}]}))
        figo.update_layout(paper_bgcolor="#FFFFFF", height=300,
                           margin=dict(l=20, r=20, t=60, b=10))
        day_blocks.append(("Critical Supplies", figo))

        # Blood bank
        if not blood.empty and blood["Units"].sum() > 0:
            b = blood.copy()
            b["low"] = b["Units"] < 5
            figb = px.bar(b, x="Blood Type", y="Units", color="low",
                          color_discrete_map={True: DANGER, False: PRIMARY},
                          title="Blood bank units by type (red = low, <5)")
            figb.update_layout(showlegend=False)
            day_blocks.append(("Blood Bank", style_fig(figb, h=340)))

        # Medications (availability status)
        if not meds.empty:
            day_blocks.append(("Medication Availability",
                               med_status_fig(list(zip(meds["Medication"], meds["Status"])))))

        if tv:
            if not depts.empty:
                day_blocks.append(("Department Status",
                                   dept_status_fig(list(zip(depts["Department"],
                                                            depts["Status"])))))
            if not tests.empty:
                day_blocks.append(("Tests",
                                   tests_fig(tests[tests["Available"]]["Test"].tolist(),
                                             tests[~tests["Available"]]["Test"].tolist())))

        show_charts(perf_blocks + day_blocks, tv)

        if not tv:
            if not depts.empty:
                st.markdown('<div class="section">Department Status</div>',
                            unsafe_allow_html=True)
                dept_pills(list(zip(depts["Department"], depts["Status"])))
            if not tests.empty:
                st.markdown('<div class="section">Medical Tests Available</div>',
                            unsafe_allow_html=True)
                render_tests_block(tests[tests["Available"]]["Test"].tolist(),
                                   tests[~tests["Available"]]["Test"].tolist())

    # ──────────────────────────────────────────
    # WEEKLY ROLL-UP DASHBOARD
    # ──────────────────────────────────────────
    elif view.startswith("Week"):
        if tv:
            ref_day = _qp_date("d")
        else:
            ref_day = st.date_input("Show week containing", value=date.today(), key="wk_ref")
        start, end = week_bounds(ref_day)
        if not tv:
            st.markdown(f'<div class="sub">Week of <b>{start:%d %b}</b> – <b>{end:%d %b %Y}</b> '
                        f'&nbsp;•&nbsp; updated {datetime.now():%H:%M}</div>',
                        unsafe_allow_html=True)

        daily, depts, meds, tests, blood = load_range(start, end)
        if all(x.empty for x in (daily, depts, meds, tests, blood)):
            st.info("No data recorded for this week yet.")
            st.stop()

        d = daily.copy()
        if not d.empty:
            d["Day"] = d["entry_date"].map(day_label)
        latest = d.iloc[-1] if not d.empty else None

        # ── Performance dashboard (always shown first) ──
        perf_summary = health_summary(*perf_inputs_range(latest, depts, meds, tests, blood))
        perf_figs_list = performance_figs(perf_summary)
        if tv:
            perf_blocks = perf_figs_list
        else:
            render_performance_normal(perf_summary, perf_figs_list)
            perf_blocks = []

        st.markdown('<div class="section">This Week at a Glance</div>', unsafe_allow_html=True)
        g = lambda col: int(d[col].sum()) if not d.empty else 0
        avg = lambda col: round(d[col].mean(), 1) if not d.empty else 0
        occ_txt = "—"
        if latest is not None and latest["beds_total"]:
            occ_txt = f"{(latest['beds_total']-latest['beds_available'])/latest['beds_total']*100:.0f}%"
        kpis = [
            ("🤒 Patients in hospital",
             int(latest["current_inpatients"]) if latest is not None else 0),
            ("📥 Admissions (wk)", f"{g('admitted'):,}"),
            ("📤 Discharged (wk)", f"{g('discharged'):,}"),
            ("🚨 ER visits (wk)", f"{g('er_visits'):,}"),
            ("🔪 Surgeries (wk)", f"{g('surgeries'):,}"),
            ("👶 Births (wk)", f"{g('births'):,}"),
            ("⚰️ Deaths (wk)", f"{g('deaths'):,}"),
            ("🛏️ Bed occupancy", occ_txt),
            ("🧑‍⚕️ Avg doctors/day", avg("doctors")),
            ("👩‍⚕️ Avg nurses/day", avg("nurses")),
            ("🚑 Avg ambulances", avg("ambulances_available")),
            ("📅 Days reported", f"{d['entry_date'].nunique() if not d.empty else 0}/7"),
        ]
        render_kpis(kpis, tv)

        wk_blocks = []
        if not d.empty:
            fig_p = go.Figure()
            fig_p.add_bar(x=d["Day"], y=d["admitted"], name="Admissions", marker_color=PRIMARY)
            fig_p.add_bar(x=d["Day"], y=d["discharged"], name="Discharges", marker_color=TEAL2)
            fig_p.update_layout(title="Admissions vs Discharges", barmode="group")
            wk_blocks.append(("Patient Flow", style_fig(fig_p)))

            fig_act = go.Figure()
            for col, name, color in [("er_visits", "ER visits", DANGER),
                                     ("surgeries", "Surgeries", PRIMARY),
                                     ("icu_patients", "ICU patients", WARN)]:
                fig_act.add_scatter(x=d["Day"], y=d[col], name=name, mode="lines+markers",
                                    line=dict(color=color))
            fig_act.update_layout(title="ER / Surgeries / ICU")
            wk_blocks.append(("ER / Surgeries / ICU", style_fig(fig_act)))

            fig_bed = go.Figure()
            fig_bed.add_bar(x=d["Day"], y=d["beds_available"], name="Beds available",
                            marker_color=TEAL2)
            fig_bed.add_scatter(x=d["Day"], y=d["beds_total"], name="Total beds",
                                mode="lines+markers", line=dict(color=INK, dash="dot"))
            fig_bed.update_layout(title="Beds Available vs Total")
            wk_blocks.append(("Beds & Occupancy", style_fig(fig_bed)))

            fig_s = go.Figure()
            fig_s.add_bar(x=d["Day"], y=d["doctors"], name="Doctors", marker_color=PRIMARY)
            fig_s.add_bar(x=d["Day"], y=d["nurses"], name="Nurses", marker_color=WARN)
            fig_s.add_bar(x=d["Day"], y=d["support_staff"], name="Support", marker_color=OK_GREEN)
            fig_s.update_layout(title="Staff on Duty", barmode="group")
            wk_blocks.append(("Staffing", style_fig(fig_s)))

            fig_a = go.Figure()
            fig_a.add_bar(x=d["Day"], y=d["ambulances_available"], name="Available",
                          marker_color=OK_GREEN)
            fig_a.add_scatter(x=d["Day"], y=d["ambulances_total"], name="Fleet total",
                              mode="lines+markers", line=dict(color=DANGER, dash="dot"))
            fig_a.update_layout(title="Ambulances Available vs Fleet")
            wk_blocks.append(("Ambulances", style_fig(fig_a)))

        if not blood.empty:
            latest_b = blood["entry_date"].max()
            b = blood[blood["entry_date"] == latest_b].copy()
            b["low"] = b["units"] < 5
            fig_bb = px.bar(b, x="blood_type", y="units", color="low",
                            color_discrete_map={True: DANGER, False: PRIMARY},
                            title=f"Units by type — {day_label(latest_b)} (red = low, <5)")
            fig_bb.update_layout(showlegend=False)
            wk_blocks.append((f"Blood Bank — as of {day_label(latest_b)}", style_fig(fig_bb)))

        latest_dept_status = None
        if not depts.empty:
            depts["Day"] = depts["entry_date"].map(day_label)
            depts["score"] = depts["status"].map(STATUS_SCORE).fillna(0)
            order = sorted(depts["entry_date"].unique())
            day_order = [day_label(x) for x in order]
            pivot = depts.pivot_table(index="name", columns="Day", values="score",
                                      aggfunc="last").reindex(columns=day_order)
            z = pivot.values
            _lbl = {2: "OK", 1: "Ltd", 0: "Closed"}
            txt = [["" if pd.isna(v) else _lbl[int(v)] for v in row] for row in z]
            fig_h = go.Figure(go.Heatmap(
                z=z, x=list(pivot.columns), y=list(pivot.index), text=txt, texttemplate="%{text}",
                colorscale=[[0, DANGER], [0.5, WARN], [1, OK_GREEN]],
                zmin=0, zmax=2, showscale=False, xgap=3, ygap=3))
            fig_h.update_layout(title="Operational status by day "
                                "(green = Operational, amber = Limited, red = Closed)")
            wk_blocks.append(("Department Status", style_fig(fig_h, h=max(300, 42 * pivot.shape[0]))))
            latest_d = depts[depts["entry_date"] == order[-1]]
            latest_dept_status = (day_label(order[-1]), list(zip(latest_d["name"], latest_d["status"])))

        if not meds.empty:
            latest_m = meds["entry_date"].max()
            m = meds[meds["entry_date"] == latest_m]
            wk_blocks.append((f"Medication Availability — as of {day_label(latest_m)}",
                              med_status_fig(list(zip(m["name"], m["status"])))))

        if tv and not tests.empty:
            latest_t = tests["entry_date"].max()
            t = tests[tests["entry_date"] == latest_t]
            wk_blocks.append(("Tests",
                              tests_fig(t[t["available"] == 1]["name"].tolist(),
                                        t[t["available"] == 0]["name"].tolist())))

        show_charts(perf_blocks + wk_blocks, tv)

        if not tv:
            if latest_dept_status is not None:
                st.caption(f"Latest department status — {latest_dept_status[0]}:")
                dept_pills(latest_dept_status[1])
            if not tests.empty:
                st.markdown('<div class="section">Medical Tests Available</div>',
                            unsafe_allow_html=True)
                latest_t = tests["entry_date"].max()
                t = tests[tests["entry_date"] == latest_t]
                render_tests_block(t[t["available"] == 1]["name"].tolist(),
                                   t[t["available"] == 0]["name"].tolist(),
                                   suffix=f" — {day_label(latest_t)}")
            st.divider()
            if not daily.empty:
                st.download_button("⬇️ Download this week's daily summary (CSV)",
                                   daily.to_csv(index=False).encode("utf-8"),
                                   file_name=f"weekly_summary_{start:%Y%m%d}.csv", mime="text/csv")

    # ──────────────────────────────────────────
    # MONTHLY ROLL-UP DASHBOARD
    # ──────────────────────────────────────────
    else:
        if tv:
            ref_day = _qp_date("d")
        else:
            ref_day = st.date_input("Show month containing", value=date.today(), key="mo_ref")
        start, end = month_bounds(ref_day)
        if not tv:
            st.markdown(f'<div class="sub">Month of <b>{start:%B %Y}</b> '
                        f'&nbsp;•&nbsp; updated {datetime.now():%H:%M}</div>',
                        unsafe_allow_html=True)

        daily, depts, meds, tests, blood = load_range(start, end)
        if all(x.empty for x in (daily, depts, meds, tests, blood)):
            st.info("No data recorded for this month yet.")
            st.stop()

        mlabel = lambda s: datetime.fromisoformat(s).strftime("%d")
        d = daily.copy()
        if not d.empty:
            d["Day"] = d["entry_date"].map(mlabel)
        latest = d.iloc[-1] if not d.empty else None

        # ── Performance dashboard (always shown first) ──
        perf_summary = health_summary(*perf_inputs_range(latest, depts, meds, tests, blood))
        perf_figs_list = performance_figs(perf_summary)
        if tv:
            perf_blocks = perf_figs_list
        else:
            render_performance_normal(perf_summary, perf_figs_list)
            perf_blocks = []

        st.markdown('<div class="section">This Month at a Glance</div>', unsafe_allow_html=True)
        g = lambda col: int(d[col].sum()) if not d.empty else 0
        avg = lambda col: round(d[col].mean(), 1) if not d.empty else 0
        occ_txt = "—"
        if latest is not None and latest["beds_total"]:
            occ_txt = f"{(latest['beds_total']-latest['beds_available'])/latest['beds_total']*100:.0f}%"
        days_in_month = (end - start).days + 1
        kpis = [
            ("🤒 Patients in hospital",
             int(latest["current_inpatients"]) if latest is not None else 0),
            ("📥 Admissions (mo)", f"{g('admitted'):,}"),
            ("📤 Discharged (mo)", f"{g('discharged'):,}"),
            ("🚨 ER visits (mo)", f"{g('er_visits'):,}"),
            ("🔪 Surgeries (mo)", f"{g('surgeries'):,}"),
            ("👶 Births (mo)", f"{g('births'):,}"),
            ("⚰️ Deaths (mo)", f"{g('deaths'):,}"),
            ("🛏️ Bed occupancy", occ_txt),
            ("🧑‍⚕️ Avg doctors/day", avg("doctors")),
            ("👩‍⚕️ Avg nurses/day", avg("nurses")),
            ("🚑 Avg ambulances", avg("ambulances_available")),
            ("📅 Days reported",
             f"{d['entry_date'].nunique() if not d.empty else 0}/{days_in_month}"),
        ]
        render_kpis(kpis, tv)

        mo_blocks = []
        if not d.empty:
            fig_p = go.Figure()
            fig_p.add_bar(x=d["Day"], y=d["admitted"], name="Admissions", marker_color=PRIMARY)
            fig_p.add_bar(x=d["Day"], y=d["discharged"], name="Discharges", marker_color=TEAL2)
            fig_p.update_layout(title="Admissions vs Discharges", barmode="group")
            mo_blocks.append(("Patient Flow", style_fig(fig_p)))

            fig_act = go.Figure()
            for col, name, color in [("er_visits", "ER visits", DANGER),
                                     ("surgeries", "Surgeries", PRIMARY),
                                     ("icu_patients", "ICU patients", WARN)]:
                fig_act.add_scatter(x=d["Day"], y=d[col], name=name, mode="lines+markers",
                                    line=dict(color=color))
            fig_act.update_layout(title="ER / Surgeries / ICU")
            mo_blocks.append(("ER / Surgeries / ICU", style_fig(fig_act)))

            fig_bed = go.Figure()
            fig_bed.add_bar(x=d["Day"], y=d["beds_available"], name="Beds available",
                            marker_color=TEAL2)
            fig_bed.add_scatter(x=d["Day"], y=d["beds_total"], name="Total beds",
                                mode="lines+markers", line=dict(color=INK, dash="dot"))
            fig_bed.update_layout(title="Beds Available vs Total")
            mo_blocks.append(("Beds & Occupancy", style_fig(fig_bed)))

            fig_s = go.Figure()
            fig_s.add_bar(x=d["Day"], y=d["doctors"], name="Doctors", marker_color=PRIMARY)
            fig_s.add_bar(x=d["Day"], y=d["nurses"], name="Nurses", marker_color=WARN)
            fig_s.add_bar(x=d["Day"], y=d["support_staff"], name="Support", marker_color=OK_GREEN)
            fig_s.update_layout(title="Staff on Duty", barmode="group")
            mo_blocks.append(("Staffing", style_fig(fig_s)))

            fig_a = go.Figure()
            fig_a.add_bar(x=d["Day"], y=d["ambulances_available"], name="Available",
                          marker_color=OK_GREEN)
            fig_a.add_scatter(x=d["Day"], y=d["ambulances_total"], name="Fleet total",
                              mode="lines+markers", line=dict(color=DANGER, dash="dot"))
            fig_a.update_layout(title="Ambulances Available vs Fleet")
            mo_blocks.append(("Ambulances", style_fig(fig_a)))

        if not blood.empty:
            latest_b = blood["entry_date"].max()
            b = blood[blood["entry_date"] == latest_b].copy()
            b["low"] = b["units"] < 5
            fig_bb = px.bar(b, x="blood_type", y="units", color="low",
                            color_discrete_map={True: DANGER, False: PRIMARY},
                            title=f"Units by type — {day_label(latest_b)} (red = low, <5)")
            fig_bb.update_layout(showlegend=False)
            mo_blocks.append((f"Blood Bank — as of {day_label(latest_b)}", style_fig(fig_bb)))

        latest_dept_status = None
        if not depts.empty:
            depts["Day"] = depts["entry_date"].map(mlabel)
            depts["score"] = depts["status"].map(STATUS_SCORE).fillna(0)
            order = sorted(depts["entry_date"].unique())
            day_order = [mlabel(x) for x in order]
            pivot = depts.pivot_table(index="name", columns="Day", values="score",
                                      aggfunc="last").reindex(columns=day_order)
            z = pivot.values
            _lbl = {2: "OK", 1: "Ltd", 0: "Closed"}
            txt = [["" if pd.isna(v) else _lbl[int(v)] for v in row] for row in z]
            fig_h = go.Figure(go.Heatmap(
                z=z, x=list(pivot.columns), y=list(pivot.index), text=txt, texttemplate="%{text}",
                colorscale=[[0, DANGER], [0.5, WARN], [1, OK_GREEN]],
                zmin=0, zmax=2, showscale=False, xgap=2, ygap=3))
            fig_h.update_layout(title="Operational status by day of month "
                                "(green = Operational, amber = Limited, red = Closed)")
            mo_blocks.append(("Department Status",
                              style_fig(fig_h, h=max(300, 42 * pivot.shape[0]))))
            latest_d = depts[depts["entry_date"] == order[-1]]
            latest_dept_status = (day_label(order[-1]),
                                  list(zip(latest_d["name"], latest_d["status"])))

        if not meds.empty:
            latest_m = meds["entry_date"].max()
            m = meds[meds["entry_date"] == latest_m]
            mo_blocks.append((f"Medication Availability — as of {day_label(latest_m)}",
                              med_status_fig(list(zip(m["name"], m["status"])))))

        if tv and not tests.empty:
            latest_t = tests["entry_date"].max()
            t = tests[tests["entry_date"] == latest_t]
            mo_blocks.append(("Tests",
                              tests_fig(t[t["available"] == 1]["name"].tolist(),
                                        t[t["available"] == 0]["name"].tolist())))

        show_charts(perf_blocks + mo_blocks, tv)

        if not tv:
            if latest_dept_status is not None:
                st.caption(f"Latest department status — {latest_dept_status[0]}:")
                dept_pills(latest_dept_status[1])
            if not tests.empty:
                st.markdown('<div class="section">Medical Tests Available</div>',
                            unsafe_allow_html=True)
                latest_t = tests["entry_date"].max()
                t = tests[tests["entry_date"] == latest_t]
                render_tests_block(t[t["available"] == 1]["name"].tolist(),
                                   t[t["available"] == 0]["name"].tolist(),
                                   suffix=f" — {day_label(latest_t)}")
            st.divider()
            if not daily.empty:
                st.download_button("⬇️ Download this month's daily summary (CSV)",
                                   daily.to_csv(index=False).encode("utf-8"),
                                   file_name=f"monthly_summary_{start:%Y%m}.csv", mime="text/csv")
