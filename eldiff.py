from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, Response
import sqlite3
from sqlite3 import OperationalError
from apscheduler.schedulers.background import BackgroundScheduler
import os
import threading
import xmltodict
from datetime import datetime
from bs4 import BeautifulSoup
import gzip
from typing import Union, Tuple, List, Dict
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from DiffManager import DiffManager
import logging
from logging.handlers import RotatingFileHandler
from config import POPULAR_BINARIES, DATABASE_FILE, X64_DIR, get_delta_patch_path, get_phase123_path, get_phase4_path, get_ida_path, get_patch_extract_path, get_product_id
from DatabaseManger import DatabaseManager

# Function type flags
DEFINED = 0
ADDED   = 1
DELETED = 2
IMPORTED = 4 # we will use bitwise OR to mark imported added or imported deleted funcs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('eldiff.log', maxBytes=1_000_000, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

db_path = str(DATABASE_FILE)
product_id = get_product_id()
process_lock = threading.Lock()

# CUTOFF_DATE = datetime(2024, 12, 3).date()

app = Flask(__name__)
app.secret_key = "eldiffsecrets"

# We need to import it after the main module logger itinialization to properly get log messages
# from this modules
from UpdFetcherManager import MicrosoftUpdateFetcher
from PatchExtractorManager import PatchExtractorManager

def to_u64_hex(val: Union[int,str]) -> str:
    raw = int(val, 16) if isinstance(val, str) and val.lower().startswith("0x") else int(val)
    u64 = raw & 0xFFFFFFFFFFFFFFFF
    return f"0x{u64:016x}"

def convrt_to_date_obj(date: str):
    return datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").date()

# Main pipeline code
# TODO: write a lock for a wizard and scheduler runs
def process_updates():
    if not process_lock.acquire(blocking=False):
        logger.warning("process_updates is already running")
        return

    fetcher = MicrosoftUpdateFetcher()
    db_manager = DatabaseManager(DATABASE_FILE)
    db_manager.initialize()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    db_entries = fetcher.get_existing_updates(conn)

    cur.execute("SELECT MIN(InitialReleaseDate) FROM updates")
    row = cur.fetchone()
    if row and row[0]:
        #parse it into a date for comparison
        earliest = convrt_to_date_obj(row[0])
        logger.info("Earliest processed bulletin: %s", earliest)
    else:
        earliest = None # Nothing processed yet

    new_upd = [] # new updates with new ID
    upd_upd = [] #NOTE: new udpates within same ID and looks like it's not used anymore, lol
    CUTOFF_DATE = datetime(2025, 6, 10).date()

    api_upd = fetcher.get_security_updates()

    for entry in api_upd:
        entry_id = entry["ID"]
        initial_date = convrt_to_date_obj(entry["InitialReleaseDate"])
        # Skip anything older than earliest processed
        if earliest and initial_date < earliest:
            logger.info("Skipping %s (initial %s < %s)", entry_id, initial_date, earliest)
            continue

        current_date = entry["CurrentReleaseDate"]

        if entry_id not in db_entries:
            new_upd.append(entry)
        else:
            db_initial, db_current = db_entries[entry_id]
            if current_date > db_current:
                upd_upd.append(entry)

    #TODO: combine new_upd and upd_upd in a single sorted list to process in a single loop
    all_updates = sorted(new_upd + upd_upd, key=lambda entry: entry["InitialReleaseDate"])

    # Process all updates
    # TODO: probe the kb, download and fill the db 
    for upd in all_updates:
        try:
            cvrf_url = upd.get("CvrfUrl")
            data = fetcher.fetch_cvrf_xml(cvrf_url)
            if data:
            # req = requests.get(cvrf_url)
            # if req.status_code == 200:
                # data = xmltodict.parse(req.content)
                # cves = MicrosoftUpdateFetcher.get_cve_by_product_id("12243", data)
                cves = fetcher.get_cve_by_product_id(product_id, data)

                if cves:
                    #TODO: rethink this check, cause vuln:URL might be empty in
                    # the first record but appear somewhere further
                    # f = MicrosoftUpdateFetcher.get_fixes(cves[0], "12243", data)
                    f = fetcher.get_fixes(cves[0], product_id, data)
                    url = f.get("vuln:URL")
                    if not url:
                        continue

                    kb = fetcher.extract_kb_from_url(url)
                    try:
                        # id = MicrosoftUpdateFetcher.get_update_id_by_kb(kb, "12243", data)
                        update_id = fetcher.get_update_id_by_kb(kb, product_id, data)
                        kb_link = fetcher.get_kb_link(update_id)
                        prod_name = fetcher.get_prod_name_by_id(product_id, data)
                        last_updated = fetcher.get_kb_date_from_page(url, update_id, prod_name)

                        if not last_updated:
                            logger.error("Skipping %s - Could not retrieve last_updated date", kb)
                            continue

                        formatted_kb_date = fetcher.format_catalog_date(last_updated)

                        #BUG: added additional check for the kb   
                        bulletin_date = datetime.strptime(upd["InitialReleaseDate"], "%Y-%m-%dT%H:%M:%SZ").date()

                        # Make a date object to properly compare with bulletin_date
                        kb_date = datetime.strptime(formatted_kb_date, "%Y-%m-%d").date()

                        if kb_date > bulletin_date:
                            logger.warning("Skipping processing %s (%s) for bulletin %s", kb, formatted_kb_date, upd['ID'])
                            continue

                        # Check if KbData exist in database and skip further processing
                        if fetcher.kb_date_exists(db_path, formatted_kb_date):
                            logger.warning("Skipping already processed %s", formatted_kb_date)
                            continue

                        #TODO: Write the initialization of the updates folder creation
                        upd_dir = os.path.join("updates", formatted_kb_date)
                        os.makedirs(upd_dir, exist_ok=True)
                        xml_path = os.path.join(upd_dir, f"{formatted_kb_date}.xml")
                        with open(xml_path, 'w', encoding='utf-8') as f:
                            xmltodict.unparse(data, f, pretty=True)

                        #TODO: process vulnerability info from data
                        fetcher.insert_vuln_for_all_upd_new(formatted_kb_date,
                                                            product_id,
                                                            db_path,
                                                            data)

                        cur.execute('''INSERT INTO updates (ID, InitialReleaseDate, CurrentReleaseDate, CvrfUrl, KbDate)
                        VALUES (?, ?, ?, ?, ?)''', (upd['ID'],
                                                    upd['InitialReleaseDate'],
                                                    upd['CurrentReleaseDate'],
                                                    cvrf_url,
                                                    formatted_kb_date))

                        conn.commit()

                        #TODO: Download MSU if update date is > CUTOFF_DATE
                        # kb_date = datetime.strptime(formatted_kb_date, "%Y-%m-%d").date()
                        if kb_date <= CUTOFF_DATE:
                            logger.warning("Skipping %s older than CUTOFF_DATE", formatted_kb_date)
                            continue

                        # if not MicrosoftUpdateFetcher.is_msu_exist(upd_dir): 
                        #     kb_path = MicrosoftUpdateFetcher.download_msu_file(kb_link, upd_dir)

                        kb_path = fetcher.download_msu_file(kb_link, upd_dir)
                        x64_bin_path = os.path.join(upd_dir, X64_DIR)
                        if not os.path.exists(x64_bin_path):
                            PatchExtractorManager.run_patch_extract(get_patch_extract_path(), kb_path, upd_dir)

                        tags = PatchExtractorManager.fetch_tags(db_path, formatted_kb_date)
                        comp_map = PatchExtractorManager.fetch_component_mapping(db_path)
                        candidates = PatchExtractorManager.get_candidate_binaries(tags, comp_map, POPULAR_BINARIES)

                        threshold = PatchExtractorManager.fetch_global_threshold(db_path, formatted_kb_date)

                        scanned = PatchExtractorManager.find_new_patched_files(x64_bin_path, threshold)

                        to_process = [ f for f in scanned if f['name'] in candidates ]

                        if to_process:
                            paths = [f['path'] for f in to_process]
                            PatchExtractorManager.populate_binaries_table(db_path, formatted_kb_date, paths)
                            
                        # patched_binaries = PatchExtractorManager.find_patched_binaries(x64_bin_path)
                        # #TODO: Apply delta_patch and populate binaries table
                        # if patched_binaries:
                        #     PatchExtractorManager.populate_binaries_table(x64_bin_path, db_path, formatted_kb_date, patched_binaries)

                            #TODO: apply patch to the forward_delta and update binaries table
                            PatchExtractorManager.process_and_update_binaries(db_path,
                                                                              upd_dir,
                                                                              get_delta_patch_path(),
                                                                              formatted_kb_date)
                            #Generate ida, binexport, bindiff databases 
                            binaries = PatchExtractorManager.get_binaries_for_kbdate(db_path, formatted_kb_date)
                            DiffManager.update_binary_hashes(db_path, formatted_kb_date)
                            for binary_name, binary_version, binary_path in binaries:
                                #TODO: check this solution for robustness
                                if not binary_path:
                                    continue
                                DiffManager.run_ida_batch(binary_path, db_path)

                            DiffManager.generate_binexport_for_kbdate(upd_dir, formatted_kb_date)
                            DiffManager.generate_bindiff(formatted_kb_date, db_path, upd_dir)

                            for binary_name, binary_version, binary_path in binaries:
                                """
                                Phase 1: Preload patched functions rows
                                Phase 2: Decompile, compress, update patched
                                functions table
                                Phase 3: Preload, decompile, compress added
                                functions, update added/deleted functions table,
                                preload deleted function with empty BLOB
                                """
                                DiffManager.analyze_funcs(db_path,
                                                          get_ida_path(),
                                                          get_phase123_path(),
                                                          binary_name,
                                                          binary_version)

                                # Looks like I got error above cause no diff function were made 
                                DiffManager.make_diff(db_path, binary_name, binary_version)

                                # Phase 4: Decompile, compress, update BLOB for
                                # deleted functions
                                DiffManager.process_added_deleted_functions(db_path,
                                                                            get_ida_path(), # ida64.exe
                                                                            get_phase4_path(),
                                                                            binary_name,
                                                                            binary_version)
                    except Exception as e:
                        logger.error("Failed to process %s: %s", kb, str(e))
                        continue

        except Exception as e:
            logger.exception("Failed to process update %s", upd.get('ID'))
            continue

    conn.close()
    process_lock.release()

login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        row = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return User(row["id"], row["username"]) if row else None

    @staticmethod
    def validate_login(username, password):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        
        logger = logging.getLogger(__name__)
        
        if row:
            try:
                logger.debug(f"User found: ID={row[0]}, Username={row[1]}")
                logger.debug(f"Stored hash type: {type(row[2])}, value: {row[2]}")
                
                stored_hash = row[2]
                result = check_password_hash(stored_hash, password)
                logger.debug(f"Password check result: {result}")
                
                if result:
                    return User(row[0], row[1])
            except Exception as e:
                logger.exception("Error during password validation")
        else:
            logger.warning(f"User not found: {username}")
            
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# WTForms Login Form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Validate credentials from the SQLite database
        user = User.validate_login(form.username.data, form.password.data)
        if user:
            login_user(user)
            flash("Logged in successfully.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/get_updates")
@login_required
def get_updates():
    with get_db_connection() as conn:
        updates = conn.execute("SELECT * FROM updates ORDER BY KbDate DESC LIMIT 10").fetchall()
    return jsonify([dict(update) for update in updates])

@app.route("/get_latest_update")
@login_required
def get_latest_update():
    with get_db_connection() as conn:
        latest_update = conn.execute(
            "SELECT KbDate FROM updates ORDER BY CurrentReleaseDate DESC LIMIT 1"
        ).fetchone()
    if latest_update:
        return jsonify({"latest_update_id": latest_update["KbDate"]})
    else:
        return jsonify({"error": "No updates found"}), 404

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/get_vulnerabilities/<kb_date>")
@login_required
def get_vulnerabilities(kb_date):
    with get_db_connection() as conn:
        vulnerabilities = conn.execute("""
            SELECT CVE, CWE, Impact, Severity, Tag AS Component, FAQ, URL AS FixURL, FixedBuild, Exploit_Status
            FROM Vulnerabilities
            WHERE KbDate = ?
        """, (kb_date,)).fetchall()

    parsed_vulnerabilities = []
    for vuln in vulnerabilities:
        exploit_status_dict = {}
        if vuln["Exploit_Status"]:
            for item in vuln["Exploit_Status"].split(";"):
                if ":" in item:
                    k, v = item.split(":", 1)
                    exploit_status_dict[k.strip()] = v.strip()

        parsed_vulnerabilities.append({
            "CVE": vuln["CVE"],
            "CWE": vuln["CWE"],
            "Impact": vuln["Impact"],
            "Severity": vuln["Severity"],
            "Component": vuln["Component"],
            "FAQ": vuln["FAQ"] or "—",
            "FixURL": vuln["FixURL"] or "—",
            "FixedBuild": vuln["FixedBuild"] or "—",
            "Exploit_Status": {
                "Publicly Disclosed": exploit_status_dict.get("Publicly Disclosed", "N/A"),
                "Exploited": exploit_status_dict.get("Exploited", "N/A")
            }
        })

    return jsonify(parsed_vulnerabilities)

@app.route('/search')
def global_search_page():
    with get_db_connection() as conn:
        kbdates = [row[0] for row in conn.execute(
            "SELECT DISTINCT KbDate FROM binaries ORDER BY KbDate DESC").fetchall()]
    return render_template('search.html', kbdates=kbdates)

@app.route('/global_search')
def global_search_api():
    conn = get_db_connection()

    # 1) Read filter parameters
    q               = request.args.get('q', '').strip()
    severity        = request.args.get('severity', '').strip()
    impact          = request.args.get('impact', '').strip()
    kbdate          = request.args.get('kbdate', '').strip()
    exploited_flag  = request.args.get('exploited','')            == '1'
    pd_flag         = request.args.get('publicly_disclosed','')   == '1'
    ml_flag         = request.args.get('more_likely','')          == '1'
    fuzzy           = request.args.get('fuzzy','')                == '1'

    # 2) Build WHERE clause pieces
    where_clauses = []
    params = []

    # 2.1) Keyword search over func_name, binary_name, component, CVEs
    if q:
        pattern = f"%{q}%"
        clause = []
        for col in ('func_name', 'binary_name', 'component', 'CVEs'):
            clause.append(f"{col} LIKE ? COLLATE NOCASE")
            params.append(pattern)
        where_clauses.append("(" + " OR ".join(clause) + ")")

    # 2.2) Severity, Impact, KbDate
    if severity:
        where_clauses.append("Severities = ?")
        params.append(severity)
    if impact:
        where_clauses.append("Impacts LIKE ? COLLATE NOCASE")
        params.append(f"%{impact}%")
    if kbdate:
        where_clauses.append("KbDate = ?")
        params.append(kbdate)

    # 2.3) Exploit-status flags
    if exploited_flag:
        where_clauses.append("Exploit_Statuses LIKE '%Exploited:Yes;%' COLLATE NOCASE")
    if pd_flag:
        where_clauses.append("Exploit_Statuses LIKE '%Publicly Disclosed:Yes;%' COLLATE NOCASE")
    if ml_flag:
        where_clauses.append("Exploit_Statuses LIKE '%Exploitation More Likely%' COLLATE NOCASE")

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # 3) Full SQL with GROUP_CONCAT and orphan vulnerabilities
    full_query = f"""
    WITH raw_changes AS (
      -- added/deleted/imported functions
      SELECT
        b.binary_name,
        b.binary_version,
        CASE
          WHEN (adf.function_type & 1)!=0 THEN 'added'
          WHEN (adf.function_type & 2)!=0 THEN 'deleted'
          WHEN (adf.function_type & 4)!=0 THEN 'imported'
          ELSE 'unknown'
        END AS func_type,
        adf.name    AS func_name,
        adf.address AS func_addr,
        cm.component,
        v.CVE,
        v.CWE,
        v.Impact,
        v.Severity,
        v.Exploit_Status,
        b.KbDate
      FROM binaries b
      JOIN added_deleted_funcs adf
        ON adf.binary_name = b.binary_name
       AND adf.binary_version = b.binary_version
      LEFT JOIN component_mapping cm
        ON cm.binary_name = b.binary_name
      LEFT JOIN Vulnerabilities v
        ON v.Tag = cm.component
       AND v.KbDate = b.KbDate

      UNION ALL

      -- patched functions
      SELECT
        b.binary_name,
        b.binary_version,
        'patched'      AS func_type,
        f.name2        AS func_name,
        f.address2     AS func_addr,
        cm.component,
        v.CVE,
        v.CWE,
        v.Impact,
        v.Severity,
        v.Exploit_Status,
        b.KbDate
      FROM binaries b
      JOIN functions f
        ON f.binary_name = b.binary_name
       AND f.binary_version = b.binary_version
      LEFT JOIN component_mapping cm
        ON cm.binary_name = b.binary_name
      LEFT JOIN Vulnerabilities v
        ON v.Tag = cm.component
       AND v.KbDate = b.KbDate

      UNION ALL

      -- orphan vulnerabilities (no component mapping)
      SELECT
        NULL           AS binary_name,
        NULL           AS binary_version,
        'vulnerability' AS func_type,
        NULL           AS func_name,
        NULL           AS func_addr,
        v.Tag          AS component,
        v.CVE,
        v.CWE,
        v.Impact,
        v.Severity,
        v.Exploit_Status,
        v.KbDate
      FROM Vulnerabilities v
      LEFT JOIN component_mapping cm
        ON cm.component = v.Tag
      WHERE cm.component IS NULL
    ),

    all_changes AS (
      SELECT
        binary_name,
        binary_version,
        func_type,
        func_name,
        func_addr,
        component,
        GROUP_CONCAT(DISTINCT CVE)               AS CVEs,
        GROUP_CONCAT(DISTINCT CWE)               AS CWEs,
        GROUP_CONCAT(DISTINCT Impact)            AS Impacts,
        GROUP_CONCAT(DISTINCT Severity)          AS Severities,
        GROUP_CONCAT(DISTINCT Exploit_Status)    AS Exploit_Statuses,
        KbDate
      FROM raw_changes
      GROUP BY
        binary_name, binary_version,
        func_type, func_name, func_addr,
        component, KbDate
    )

    SELECT *
    FROM all_changes
    {where_sql}
    ORDER BY KbDate DESC, binary_name, func_name
    """

    # app.logger.debug("GS QUERY:\n%s\nPARAMS: %s", full_query, params)

    try:
        cur = conn.execute(full_query, params)
        rows = [dict(r) for r in cur.fetchall()]
    except OperationalError as e:
        app.logger.error("SQL error in global_search: %s", e)
        rows = []
    finally:
        conn.close()

    return jsonify(rows)

@app.route("/binaries")
@login_required
def binaries():
    return render_template("binaries.html")

@app.route("/get_binaries")
@login_required
def get_binaries():
    kb_date = request.args.get('kb_date')
    conn = get_db_connection() 
    cur = conn.cursor()
    cur.execute("""
    SELECT DISTINCT
        b.binary_name,
        b.binary_version   AS new_version,
        b.KB,
        b.binary_hash,
        b.status,
        (
        SELECT binary_version
            FROM binaries b2
        WHERE b2.binary_name = b.binary_name
            AND DATE(b2.KbDate) < DATE(?)
        ORDER BY DATE(b2.KbDate) DESC
        LIMIT 1
        ) AS old_version 
    FROM binaries b
    WHERE DATE(b.KbDate) = DATE(?) AND b.status = 1
    """, (kb_date, kb_date))

    rows = cur.fetchall()
    conn.close()

    result = []
    for name, new_ver, kb, hsh, status, old_version in rows:
        result.append({
            "binary_name":    name,
            "binary_version": new_ver,
            "old_version":   old_version,   # <— might be None 
            "KB":              kb,
            "binary_hash":    hsh,
            "status":         status
        })
    return jsonify(result)

@app.route("/functions")
@login_required
def functions():
    return render_template("functions.html")

@app.route("/get_functions")
@login_required
def get_functions():
    binary_name    = request.args.get("binary_name")
    binary_version = request.args.get("binary_version")
    if not binary_name or not binary_version:
        return jsonify({"error": "binary_name and binary_version are required"}), 400

    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT ID, name1, address1, name2, address2, similarity
            FROM functions
            WHERE binary_name = ? AND binary_version = ?
            ORDER BY similarity DESC
            """,
            (binary_name, binary_version)).fetchall()

    out = []
    for r in rows:
        out.append({
            "ID":         r["ID"],
            "name1":      r["name1"],
            "address1":   to_u64_hex(r["address1"]),
            "name2":      r["name2"],
            "address2":   to_u64_hex(r["address2"]),
            "similarity": r["similarity"],
        })
    return jsonify(out)

@app.route("/get_all_functions")
@login_required
def get_all_functions():
    binary_name    = request.args.get("binary_name")
    binary_version = request.args.get("binary_version")
    if not binary_name or not binary_version:
        return jsonify({"error": "Missing required parameters"}), 400

    with get_db_connection() as conn:

        # 1) Patched
        patched_rows = conn.execute("""
        SELECT ID, name1, address1, name2, address2, similarity
            FROM functions
        WHERE binary_name    = ?
            AND binary_version = ?
        ORDER BY similarity DESC
        """, (binary_name, binary_version)).fetchall()

        # 2) ADDED  (bit 1 set: 1 or 1|4=5)
        added_rows = conn.execute("""
        SELECT id, name, address
            FROM added_deleted_funcs
        WHERE binary_name    = ?
            AND binary_version = ?
            AND (function_type & 1) != 0
        """, (binary_name, binary_version)).fetchall()

        # 3) DELETED (bit 2 set: 2 or 2|4=6)
        deleted_rows = conn.execute("""
        SELECT id, name, address
            FROM added_deleted_funcs
        WHERE binary_name    = ?
            AND binary_version = ?
            AND (function_type & 2) != 0
        """, (binary_name, binary_version)).fetchall()

    funcs = []

    # patched
    for r in patched_rows:
        funcs.append({
          "ID":         r["ID"],
          "type":       "patched",
          "name1":      r["name1"],
          "address1":   to_u64_hex(r["address1"]),
          "name2":      r["name2"],
          "address2":   to_u64_hex(r["address2"]),
          "similarity": r["similarity"]
        })

    # added
    for r in added_rows:
        funcs.append({
          "ID":         r["id"],
          "type":       "added",
          "name1":      "",
          "address1":   None,
          "name2":      r["name"],
          "address2":   to_u64_hex(r["address"]),
          "similarity": None
        })

    # deleted
    for r in deleted_rows:
        funcs.append({
          "ID":         r["id"],
          "type":       "deleted",
          "name1":      r["name"],
          "address1":   to_u64_hex(r["address"]),
          "name2":      "",
          "address2":   None,
          "similarity": None
        })

    return jsonify({
      "patched": len(patched_rows),
      "added":   len(added_rows),
      "deleted": len(deleted_rows),
      "functions": funcs
    })

@app.route("/get_diff/<int:function_id>")
@login_required
def get_diff(function_id):
    with get_db_connection() as conn:
        row = conn.execute("SELECT diff FROM functions WHERE ID = ?", (function_id,)).fetchone()

    if row and row["diff"]:
        try:
            # Decompress the diff blob
            decompressed_diff = gzip.decompress(row["diff"]).decode()
            return jsonify({"success": True, "diff": decompressed_diff})
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to decompress diff: {str(e)}"})
    
    return jsonify({"success": False, "error": "Diff not available"})


#TODO: Create an endpoint for the decompressed added/deleted BLOB
@app.route("/get_func_blob/<int:func_id>")
@login_required
def get_func_blob(func_id):
    with get_db_connection() as conn:
        row = conn.execute("""
        SELECT func_blob
            FROM added_deleted_funcs
        WHERE id = ?
        """, (func_id,)).fetchone()

    if not row or row["func_blob"] is None:
        return jsonify({"success": False, "error": "No code available"}), 404

    try:
        code = gzip.decompress(row["func_blob"]).decode()
        return jsonify({"success": True, "code": code})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to decompress code: {e}"})

@app.route("/get_component_mappings")
@login_required
def get_component_mappings():
    """
    Returns JSON array of { component, binary_name } from component_mapping table.
    """
    try:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT component, binary_name FROM component_mapping").fetchall()
        return jsonify([{"component": r["component"], "binary_name": r["binary_name"]} for r in rows])
    except Exception as e:
        logger.error("Error fetching component mappings: %s", e)
        return jsonify({"error": "Database error"}), 500

@app.route("/get_binary_by_component")
@login_required
def get_binary_by_component():
    component = request.args.get("component")
    kb_date   = request.args.get("kb_date")
    if not component or not kb_date:
        return jsonify({"error": "Missing parameters"}), 400
    try:
        with get_db_connection() as conn:
            mapping_row = conn.execute(
                "SELECT binary_name FROM component_mapping WHERE component = ?",
                (component,)).fetchone()
        if not mapping_row:
            return jsonify({"error": "Mapping not found"}), 404

        binary_name = mapping_row["binary_name"]
        binary_row = conn.execute(
            "SELECT binary_version FROM binaries WHERE binary_name = ? AND KbDate = ?",
            (binary_name, kb_date)).fetchone()

        if binary_row:
            return jsonify({
                "binary_name":    binary_name,
                "binary_version": binary_row["binary_version"]
            })
        return jsonify({"error": "Binary not found for this update"}), 404

    except Exception as e:
        logger.error("Error retrieving binary by component: %s", e)
        return jsonify({"error": "Database error"}), 500

@app.route("/get_binaries_for_component")
@login_required
def get_binaries_for_component():
    component = request.args.get("component")
    kb_date   = request.args.get("kb_date")
    if not component or not kb_date:
        return jsonify({"error": "Missing parameters"}), 400

    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT b.binary_name, b.binary_version
            FROM component_mapping cm
            JOIN binaries b 
                ON cm.binary_name = b.binary_name
            WHERE cm.component = ?
            AND b.KbDate    = ?
            ORDER BY b.binary_name
        """, (component, kb_date)).fetchall()

    return jsonify([
        {"binary_name": r["binary_name"],
         "binary_version": r["binary_version"]}
        for r in rows
    ])


def fetch_component_binary_cves(kb_date: str):
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT
                cm.component,
                cm.binary_name,
                GROUP_CONCAT(v.CVE, ', ') AS cves
            FROM Vulnerabilities v
            JOIN component_mapping cm
                ON v.Tag = cm.component
            JOIN binaries b
                ON cm.binary_name    = b.binary_name
            AND b.KbDate          = v.KbDate
            WHERE v.KbDate = ?
            GROUP BY cm.component, cm.binary_name
            ORDER BY cm.component, cm.binary_name
            """, (kb_date,)).fetchall()

    return [dict(r) for r in rows]

def fetch_high_risk_vulns(kb_date: str) -> List[Dict[str, str]]:
    """
    Fetch high-risk vulnerabilities for a given KB date.

    A vulnerability is considered high-risk if:
      - Severity is 'Critical' or 'Important', OR
      - Exploit_Status contains 'Exploited:Yes', OR
      - Exploit_Status contains 'Publicly Disclosed:Yes'.

    Returns a list of dicts with keys:
      CVE, CWE, Severity, publicly_disclosed, exploited, component
    """
    with get_db_connection() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = """
            SELECT 
                CVE,
                CWE,
                Severity,
                Exploit_Status,
                Tag AS component
            FROM Vulnerabilities
            WHERE KbDate = ?
              AND (
                Severity IN ('Critical', 'Important')
                OR Exploit_Status LIKE '%Exploited:Yes%'
                OR Exploit_Status LIKE '%Publicly Disclosed:Yes%'
              )
            ORDER BY
                CASE WHEN Exploit_Status LIKE '%Exploited:Yes%' THEN 0 ELSE 1 END,
                CASE WHEN Exploit_Status LIKE '%Publicly Disclosed:Yes%' THEN 0 ELSE 1 END,
                CASE Severity
                  WHEN 'Critical'  THEN 0
                  WHEN 'Important' THEN 1
                  WHEN 'Moderate'  THEN 2
                  ELSE 3
                END,
                CVE
            LIMIT 8
        """
        cur.execute(query, (kb_date,))
        db_rows = cur.fetchall()

    result = []
    for r in db_rows:
        status_raw = (r["Exploit_Status"] or "").strip()
        status_map = {}
        for kv in status_raw.split(";"):
            if ":" in kv:
                key, value = kv.split(":", 1)
                status_map[key.strip()] = value.strip()

        result.append({
            "CVE": r["CVE"],
            "CWE": r["CWE"],
            "Severity": r["Severity"],
            "publicly_disclosed": status_map.get("Publicly Disclosed", "No"),
            "exploited":          status_map.get("Exploited", "No"),
            "component":          r["component"],
        })

    return result

@app.context_processor
def inject_nav_updates():
    conn   = get_db_connection()
    rows   = conn.execute(
        "SELECT KbDate FROM updates ORDER BY CurrentReleaseDate DESC LIMIT 10"
    ).fetchall()
    conn.close()
    dates = [r["KbDate"] for r in rows]
    return {"nav_updates": dates}

@app.route('/report/<kb_date>')
@login_required
def generate_report(kb_date):
    with get_db_connection() as conn:

        comp_bin_cves = fetch_component_binary_cves(kb_date)
        high_risk     = fetch_high_risk_vulns(kb_date)

        # Top 10 CWE stats
        cwes = conn.execute("""
            SELECT CWE, COUNT(*) AS cnt
            FROM Vulnerabilities
            WHERE KbDate = ?
            GROUP BY CWE
            ORDER BY cnt DESC
            LIMIT 10
        """, (kb_date,)).fetchall()

        # For each binary in this KB, get total/added/deleted function counts
        binaries = conn.execute("""
            SELECT binary_name, binary_version
            FROM binaries
            WHERE KbDate = ?
            ORDER BY binary_name
        """, (kb_date,)).fetchall()

        funcs = []
        for b in binaries:
            name    = b["binary_name"]
            version = b["binary_version"]

            total = conn.execute("""
                SELECT COUNT(*) AS patched 
                FROM functions
                WHERE binary_name    = ?
                AND binary_version = ?
            """, (name, version)).fetchone()["patched"]

            added  = conn.execute("""
                SELECT COUNT(*) AS added
                FROM added_deleted_funcs
                WHERE binary_name    = ?
                AND binary_version = ?
                AND function_type  = 1
            """, (name, version)).fetchone()["added"]

            deleted = conn.execute("""
                SELECT COUNT(*) AS deleted
                FROM added_deleted_funcs
                WHERE binary_name    = ?
                AND binary_version = ?
                AND function_type  = 2
            """, (name, version)).fetchone()["deleted"]

            # Skip irrelevant binaries 
            if total == 0 and added == 0 and deleted == 0:
                continue

            funcs.append({
                "binary_name":       name,
                "binary_version":    version,
                "total_functions":   total,
                "added_functions":   added,
                "deleted_functions": deleted
            })

    return render_template(
        "report.html",
        kb_date       = kb_date,
        cwes          = cwes,
        funcs         = funcs, 
        comp_bin_cves = comp_bin_cves,
        high_risk     = high_risk
    )

@app.route('/report_bbcode/<kb_date>')
@login_required
def report_bbcode(kb_date: str) -> Response:
    """
    Generate a BBCode patch report for the given KB date.

    Includes:
      - Top 10 CWEs
      - High-risk vulnerabilities
      - Component-to-Binary CVE mappings
      - Function changes by binary
      - All CVE details with HTML converted to BBCode
    """

    def html_to_bbcode(html_str: str) -> str:
        """Convert a small subset of HTML to BBCode-friendly plain text."""
        if not html_str:
            return ""
        soup = BeautifulSoup(html_str, "html.parser")

        # Convert <strong> to [b]
        for strong in soup.find_all("strong"):
            strong.insert_before("[b]")
            strong.insert_after("[/b]")
            strong.unwrap()

        # Convert <a> to "text (url)"
        for a in soup.find_all("a"):
            text = a.get_text(strip=True)
            href = (a.get("href") or "").strip()
            a.replace_with(f"{text} ({href})" if href else text)

        # Flatten to text
        text = soup.get_text(separator="\n")

        # Remove extra blank lines
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return "\n".join(lines)

    with get_db_connection() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Top 10 CWEs
        cur.execute("""
            SELECT CWE, COUNT(*) AS cnt
              FROM Vulnerabilities
             WHERE KbDate = ?
             GROUP BY CWE
             ORDER BY cnt DESC
             LIMIT 10
        """, (kb_date,))
        cwes = cur.fetchall()

        # High-risk vulnerabilities + component→binary→CVEs
        high_risk     = fetch_high_risk_vulns(kb_date)
        comp_bin_cves = fetch_component_binary_cves(kb_date)

        # Function counts by binary
        cur.execute("""
            SELECT binary_name, binary_version
              FROM binaries
             WHERE KbDate = ?
             GROUP BY binary_name, binary_version
             ORDER BY binary_name
        """, (kb_date,))
        binaries = cur.fetchall()

        funcs_counts = []
        for b in binaries:
            name, ver = b["binary_name"], b["binary_version"]

            def get_count(query: str) -> int:
                cur.execute(query, (name, ver))
                return cur.fetchone()["cnt"]

            patched = get_count("""
                SELECT COUNT(*) AS cnt
                  FROM functions
                 WHERE binary_name    = ?
                   AND binary_version = ?
            """)
            added = get_count("""
                SELECT COUNT(*) AS cnt
                  FROM added_deleted_funcs
                 WHERE binary_name    = ?
                   AND binary_version = ?
                   AND function_type  = 1
            """)
            deleted = get_count("""
                SELECT COUNT(*) AS cnt
                  FROM added_deleted_funcs
                 WHERE binary_name    = ?
                   AND binary_version = ?
                   AND function_type  = 2
            """)

            funcs_counts.append({
                "binary":  f"{name} ({ver})",
                "patched": patched,
                "added":   added,
                "deleted": deleted
            })

        # All CVE details
        cur.execute("""
            SELECT CVE, CWE, Tag, FAQ AS raw_faq
              FROM Vulnerabilities
             WHERE KbDate = ?
             ORDER BY CVE ASC
        """, (kb_date,))
        all_vuln_rows = cur.fetchall()

    # --- Build BBCode ---
    bb = []
    bb.append(f"[b]Patch Report for {kb_date}[/b]\n")

    # Top 10 CWEs
    bb.append("[u]Top 10 CWEs[/u]")
    bb.append("[table]")
    bb.append("[tr][th]CWE[/th][th]Count[/th][/tr]")
    for r in cwes:
        bb.append(f"[tr][td]{r['CWE']}[/td][td]{r['cnt']}[/td][/tr]")
    bb.append("[/table]\n")

    # High-risk vulnerabilities
    bb.append("[u]High-Risk Vulnerabilities[/u]")
    bb.append("[table]")
    bb.append("[tr][th]CVE[/th][th]CWE[/th][th]Severity[/th][th]Public[/th][th]Exploited[/th][th]Component[/th][/tr]")
    for v in high_risk:
        bb.append(
            "[tr]"
            f"[td]{v['CVE']}[/td]"
            f"[td]{v['CWE']}[/td]"
            f"[td]{v['Severity']}[/td]"
            f"[td]{v['publicly_disclosed']}[/td]"
            f"[td]{v['exploited']}[/td]"
            f"[td]{v['component']}[/td]"
            "[/tr]"
        )
    bb.append("[/table]\n")

    # Component→Binary→CVEs
    bb.append("[u]Known Associated CVEs[/u]")
    bb.append("[table]")
    bb.append("[tr][th]Component[/th][th]Binary[/th][th]CVEs[/th][/tr]")
    for row in comp_bin_cves:
        bb.append(
            "[tr]"
            f"[td]{row['component']}[/td]"
            f"[td]{row['binary_name']}[/td]"
            f"[td]{row['cves']}[/td]"
            "[/tr]"
        )
    bb.append("[/table]\n")

    # Function counts by binary
    bb.append("[u]Function Changes by Binary[/u]")
    bb.append("[table]")
    bb.append("[tr][th]Binary[/th][th]Patched[/th][th]Added[/th][th]Deleted[/th][/tr]")
    for fc in funcs_counts:
        if fc['patched'] == 0 and fc['added'] == 0 and fc['deleted'] == 0:
            continue  # skip rows with no changes
        bb.append(
            "[tr]"
            f"[td]{fc['binary']}[/td]"
            f"[td]{fc['patched']}[/td]"
            f"[td]{fc['added']}[/td]"
            f"[td]{fc['deleted']}[/td]"
            "[/tr]"
        )
    bb.append("[/table]\n")

    # All CVE details
    bb.append("[u]All CVE Details[/u]")
    bb.append("[table]")
    bb.append("[tr][th]CVE[/th][th]CWE[/th][th]Tag[/th][th]Details[/th][/tr]")
    for row in all_vuln_rows:
        details = html_to_bbcode(row["raw_faq"]).replace("\n", " ")
        bb.append(
            "[tr]"
            f"[td]{row['CVE']}[/td]"
            f"[td]{row['CWE']}[/td]"
            f"[td]{row['Tag']}[/td]"
            f"[td]{details}[/td]"
            "[/tr]"
        )
    bb.append("[/table]\n")
    bb.append("[b]* Some data might be lost because of mapping incompletion[/b]")

    return Response("\n".join(bb), mimetype='text/plain')

scheduler = BackgroundScheduler()
scheduler.add_job(
    process_updates,
    'cron',
    day_of_week='Tue',
    hour=20,
    minute=10,
    timezone='Europe/Moscow',
    max_instances=1
)

# if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
#     scheduler.start()

# if __name__ == "__main__":
#     try:
#         app.run(host='0.0.0.0', port=80, debug=True, use_reloader=False)
#     finally:
#         scheduler.shutdown()

# We no longer auto-start Flask here.
# The application should be started via config_wizard.py