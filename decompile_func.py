import idaapi
import idc
import os
import sys
import gzip
import sqlite3
import traceback
import json
import ida_funcs
import ida_nalt
from ida_funcs import getn_func, get_func_name, get_func_qty

# Function type flags
DEFINED = 0
ADDED   = 1
DELETED = 2
IMPORTED = 4 # we will use bitwise  OR to mark imported added or imported deleted funcs

# ensure our project modules are importable
from config import ELDIFF_APP, DATABASE_FILE
sys.path.append(ELDIFF_APP)
from DiffManager import DiffManager
from DiffAnalysis import DiffAnalysis

ENABLE_LOGGING      = True
LOG_FILE            = "decompilation_log.txt"
ABS_DB_PATH         = DATABASE_FILE

def log_message(msg: str):
    if ENABLE_LOGGING:
        path = os.path.join(ELDIFF_APP, LOG_FILE)
        with open(path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

def get_imported_functions():
    """
    Enumerate all imported functions in the current IDB.
    Returns: List of (name, address).
    """
    imports = []
    count = ida_nalt.get_import_module_qty()
    for midx in range(count):
        def _cb(ea, name, ordinal):
            fname = name or f"ordinal_{ordinal}"
            imports.append((fname, ea))
            return True
        ida_nalt.enum_import_names(midx, _cb)
    return imports

def dump_all_funcs_to_json(output_path: str):
    """
    Dump all defined *and* imported functions into a single JSON list,
    tagging each record with .type = DEFINED or IMPORTED (bitmask).
    """
    funcs = {}

    # 1) Defined (real) functions
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        ea = f.start_ea
        funcs[ea] = {
            "name": ida_funcs.get_func_name(ea),
            "addr": ea,
            "type": DEFINED
        }

    # 2) Imported thunks
    for name, ea in get_imported_functions():
        if ea in funcs:
            funcs[ea]["type"] |= IMPORTED
        else:
            funcs[ea] = {
                "name": f"imp_{name}",
                "addr": ea,
                "type": IMPORTED
            }

    out = list(funcs.values())
    with open(output_path, "w", encoding="utf-8") as fo:
        json.dump(out, fo, indent=2)

    log_message(f"[INFO] Dumped {len(out)} total functions to {output_path}")
    return out

def is_added_deleted_exist(bin_name, bin_ver):
    """
    Return True if the `functions` table already contains at least one row
    for (binary_name, binary_version).  In that case, we assume
    Phase 1/2 has already run successfully.
    """
    q = """
        SELECT 1
          FROM added_deleted_funcs 
         WHERE binary_name    = ?
           AND binary_version = ?
         LIMIT 1
    """
    with sqlite3.connect(ABS_DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(q, (bin_name, bin_ver))
        return cur.fetchone() is not None

def identify_true_added_deleted(old_funcs, new_funcs, patched_funcs):
    """
    Identify true added and deleted functions using addresses only.

    Args:
        old_funcs: List[Dict] — [{'addr': int, ...}]
        new_funcs: List[Dict] — [{'addr': int, ...}]
        patched_funcs: List[Tuple] — (name1, name2, addr1, addr2, similarity)

    Returns:
        added: List[Dict]
        deleted: List[Dict]
    """

    # Step 1: Build sets of matched addresses from BinDiff
    matched_old_addrs = {addr1 for _, _, addr1, _, _ in patched_funcs if addr1 is not None}
    matched_new_addrs = {addr2 for _, _, _, addr2, _ in patched_funcs if addr2 is not None}

    # Step 2: Build sets of all function addresses
    old_addrs = {f["addr"] for f in old_funcs}
    new_addrs = {f["addr"] for f in new_funcs}

    # Step 3: Identify unmatched (true added / deleted) addresses
    true_added_addrs   = new_addrs - matched_new_addrs
    true_deleted_addrs = old_addrs - matched_old_addrs

    # Step 4: Extract full function info for added/deleted functions
    added   = [f for f in new_funcs if f["addr"] in true_added_addrs]
    deleted = [f for f in old_funcs if f["addr"] in true_deleted_addrs]

    return added, deleted

def phase3_process(bin_name, bin_ver, bindiff_db_path):
    """
    Phase 3: detect true added/deleted functions (w/o imports), decompile only real code,
    and insert into added_deleted_funcs with flags ADDED, DELETED, IMPORTED as needed.
    """
    ida_paths = DiffManager.get_ida_paths(ABS_DB_PATH, bin_name, bin_ver)
    cur_idb, prev_idb = [os.path.join(ELDIFF_APP, p) for p in ida_paths]

    # When opening the old IDB first, just dump all funcs (incl. imports) to JSON
    if idc.get_idb_path() == prev_idb:
        f_old = os.path.join(ELDIFF_APP, f"{bin_name}_{bin_ver}_old.json")
        dump_all_funcs_to_json(f_old)
        return

    # Otherwise we opened the new IDB second; now compare against old JSON
    f_new = os.path.join(ELDIFF_APP, f"{bin_name}_{bin_ver}_new.json")
    f_old = os.path.join(ELDIFF_APP, f"{bin_name}_{bin_ver}_old.json")
    dump_all_funcs_to_json(f_new)

    if not os.path.exists(f_old):
        log_message(f"[WARNING] Old JSON not found at {f_old}; cannot compute added/deleted.")
        return

    old_funcs = load_func_list(f_old)
    new_funcs = load_func_list(f_new)

    # Gather import stubs from either DB (same set)
    imports = get_imported_functions()  # returns [(name, addr), ...]
    imported_addrs = {addr for _, addr in imports}

    # Tag each function record with an import flag
    for f in old_funcs:
        f["type"] = IMPORTED if f["addr"] in imported_addrs else 0
    for f in new_funcs:
        f["type"] = IMPORTED if f["addr"] in imported_addrs else 0

    # Build maps by address for quick lookup
    old_map = {f["addr"]: f for f in old_funcs}
    new_map = {f["addr"]: f for f in new_funcs}

    # Compute which addresses were actually matched by BinDiff
    all_funcs = get_all_functions(bindiff_db_path)
    matched_old = {addr1 for _, _, addr1, _, _ in all_funcs if addr1 is not None}
    matched_new = {addr2 for _, _, _, addr2, _ in all_funcs if addr2 is not None}

    old_addrs = set(old_map.keys())
    new_addrs = set(new_map.keys())

    # True added/deleted are those not in the matched sets
    true_added_addrs   = new_addrs - matched_new
    true_deleted_addrs = old_addrs - matched_old

    # Process ADDED
    added_success = added_fail = 0
    for addr in true_added_addrs:
        rec = new_map[addr]
        ftype = rec["type"] | ADDED

        # skip decompile for pure imports
        if ftype & IMPORTED:
            blob = None
        else:
            code = decompile_function(addr)
            if not code:
                added_fail += 1
                log_message(f"[ERROR] Failed to decompile ADDED function {rec['name']} @ {hex(addr)}")
                continue
            blob = gzip.compress(code.encode())

        #TODO: BUG occure here because of 64 bit integer address. Converting to hex string should fix it
        insert_added_deleted_func(
            ABS_DB_PATH,
            bin_name, bin_ver,
            rec["name"], hex(addr),
            blob, ftype
        )
        added_success += 1
        log_message(f"[INFO] Recorded ADDED function {rec['name']} @ {hex(addr)}")

    log_message(f"[INFO] phase3 ADD: {added_success} succeeded, {added_fail} failed")

    # Process DELETED (always store NULL blob)
    deleted_count = 0
    for addr in true_deleted_addrs:
        rec = old_map[addr]
        ftype = rec["type"] | DELETED

        insert_added_deleted_func(
            ABS_DB_PATH,
            bin_name, bin_ver,
            rec["name"], hex(addr),
            None, ftype
        )
        deleted_count += 1
        log_message(f"[INFO] Recorded DELETED function {rec['name']} @ {hex(addr)}")

    for p in (f_old, f_new):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError as e:
            log_message(f"[ERROR] Could not remove {p}: {e}")

def load_func_list(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

def any_function_seeds_exist(bin_name, bin_ver):
    """
    Return True if the `functions` table already contains at least one row
    for (binary_name, binary_version).  In that case, we assume
    Phase 1/2 has already run successfully.
    """
    q = """
        SELECT 1
          FROM functions
         WHERE binary_name    = ?
           AND binary_version = ?
         LIMIT 1
    """
    with sqlite3.connect(ABS_DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(q, (bin_name, bin_ver))
        return cur.fetchone() is not None

def insert_added_deleted_func(db_path, binary_name, binary_version, name, address, func_blob, function_type):
    """
    Insert a function into the added_deleted_funcs table.

    Parameters:
        db_path         (str): Path to the SQLite database.
        binary_name     (str): Name of the binary (e.g. 'ntoskrnl.exe').
        binary_version  (str): Version label (e.g. '2024-Dec').
        name            (str): Function name.
        address         (str): Function start address.
        func_blob       (bytes): Gzipped function code blob.
        function_type   (int): 1 for added, 2 for deleted.
    """
    sql = """
    INSERT OR IGNORE INTO added_deleted_funcs (
        binary_name, binary_version, name, address, func_blob, function_type
    ) VALUES (?, ?, ?, ?, ?, ?)
    """
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(sql, (binary_name, binary_version, name, address, func_blob, function_type))
            conn.commit()
    except Exception as e:
        log_message(f"[ERROR] insert_added_deleted_func failed: {e}")

def compare_func_lists(old_funcs, new_funcs):
    old_map = {f["name"]: f["addr"] for f in old_funcs}
    new_map = {f["name"]: f["addr"] for f in new_funcs}

    added   = [{"name": n, "addr": a} for n, a in new_map.items() if n not in old_map]
    deleted = [{"name": n, "addr": a} for n, a in old_map.items() if n not in new_map]
    return added, deleted

# def dump_all_funcs_to_json(output_path: str):
#    pass 

def save_and_exit(exit_code=0):
    """
    Always save the IDA database (if possible), log args, then exit.
    """
    try:
        idb = idc.get_idb_path()
        idc.save_database(idb)
        log_message(f"[SUCCESS] Saved DB: {idb}")
        log_message(f"[INFO] idc.ARGV = {idc.ARGV}")
    except Exception as e:
        log_message(f"[ERROR] save_and_exit: {e}")
    finally:
        idc.qexit(exit_code)

def get_bindiff_path(name, version):
    # lookup current IDA path in our main DB
    ida_paths = DiffManager.get_ida_paths(ABS_DB_PATH, name, version)
    current_idb, _ = ida_paths

    with sqlite3.connect(ABS_DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT bindiff_path FROM binaries WHERE ida_path = ?",
            (current_idb,)
        )
        row = cur.fetchone()

    # Fail early if no path is found
    if not row or not row[0]:
        log_message(f"[ERROR] No bindiff_path entry for IDB: {current_idb}")
        return None

    bindiff_rel = row[0]
    log_message(f"[INFO] bindiff_path = {bindiff_rel}")
    return os.path.join(ELDIFF_APP, bindiff_rel)

def get_patched_functions(bd_path):
    if not os.path.exists(bd_path):
        log_message(f"[ERROR] BinDiff DB not found: {bd_path}")
        return []

    with sqlite3.connect(bd_path) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT name1, name2, address1, address2, similarity
              FROM function
             WHERE similarity < 1
        """)
        results = cur.fetchall()
    log_message(f"[INFO] Patched functions ({len(results)}): {results}")
    return results

def get_all_functions(bd_path):
    if not os.path.exists(bd_path):
        log_message(f"[ERROR] BinDiff DB not found: {bd_path}")
        return []

    with sqlite3.connect(bd_path) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT name1, name2, address1, address2, similarity
              FROM function
        """)
        results = cur.fetchall()
    log_message(f"[INFO] All functions ({len(results)})")
    return results

def decompile_function(addr):
    if not isinstance(addr, int):
        log_message(f"[ERROR] Invalid address: {addr!r}")
        return None
    if not idc.get_func_attr(addr, idc.FUNCATTR_START):
        idc.create_insn(addr)
        idc.add_func(addr)
    func = idaapi.get_func(addr)
    if not func:
        log_message(f"[ERROR] No function at {hex(addr)}")
        return None
    try:
        cfunc = idaapi.decompile(func)
        if not cfunc:
            log_message(f"[ERROR] Hex-Rays returned None for {hex(addr)}")
            return None
        code = cfunc.__str__()
        return code
    except Exception as e:
        log_message(f"[ERROR] decompile_function exception: {e}")
        return None

def func_blob_exists(bin_name, bin_ver, func_name, column):
    q = f"""
        SELECT 1 FROM functions
         WHERE binary_name    = ?
           AND binary_version = ?
           AND name1          = ?
           AND {column} IS NOT NULL
         LIMIT 1
    """
    with sqlite3.connect(ABS_DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(q, (bin_name, bin_ver, func_name))
        return cur.fetchone() is not None

if __name__ == "__main__":
    try:
        log_message("[DEBUG] Script started")

        # init hexrays
        if not idaapi.init_hexrays_plugin():
            log_message("[ERROR] Hex-Rays init failed")
            save_and_exit(1)

        if len(idc.ARGV) < 3:
            log_message("[ERROR] Usage: -Sdecompile_func.py <binary_name> <binary_version>")
            save_and_exit(1)

        bin_name, bin_ver = idc.ARGV[1], idc.ARGV[2]
        log_message(f"[INFO] Target: {bin_name} v{bin_ver}")

        # wait for auto-analysis
        log_message("[INFO] Waiting for auto-analysis...")
        idc.auto_wait()

        # Get bindiff database
        bd_path = get_bindiff_path(bin_name, bin_ver)
        if not bd_path:
            log_message("[ERROR] Could not resolve bindiff path, exiting")
            save_and_exit(1)

        patched = get_patched_functions(bd_path)
        if not patched:
            log_message("[INFO] No patched functions, nothing to decompile")
            save_and_exit(0)

        # ensure functions table
        if not DiffAnalysis.table_exists(ABS_DB_PATH, "functions"):
            DiffAnalysis.create_func_table(ABS_DB_PATH)

        # phase 1: preload rows
        for n1, n2, a1, a2, sim in patched:
            DiffAnalysis.pre_init_func_table(bin_name, bin_ver, n1, n2, a1, a2, sim)

        # phase 2: decompile & compress each
        ida_paths = DiffManager.get_ida_paths(ABS_DB_PATH, bin_name, bin_ver)
        cur_idb, prev_idb = [os.path.join(ELDIFF_APP, p) for p in ida_paths]

        for n1, n2, a1, a2, sim in patched:
            # choose address/column
            if idc.get_idb_path() == prev_idb:
                addr, col = (int(a1,16) if isinstance(a1,str) else a1), "old_code"
            else:
                addr, col = (int(a2,16) if isinstance(a2,str) else a2), "new_code"

            # skip if already done
            if func_blob_exists(bin_name, bin_ver, n1, col):
                log_message(f"[DEBUG] Skip {n1} ({col})")
                continue

            code = decompile_function(addr)
            if not code:
                log_message(f"[ERROR] Decomp failed for {n1}")
                continue

            gz = gzip.compress(code.encode())
            DiffAnalysis.add_func_blobs(bin_name, bin_ver, n1, gz, col)

        phase3_process(bin_name, bin_ver, bd_path)
        save_and_exit(0)

    except Exception:
        log_message("[CRITICAL] Unhandled exception:\n" + traceback.format_exc())
    finally:
        # always save & exit
        save_and_exit(0)
