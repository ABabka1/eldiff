import ida_funcs
import idaapi
import idc
import os
import sys
import json
import gzip
import sqlite3
import traceback

ADDED = 1
DELETED = 2

from config import ELDIFF_APP, DATABASE_FILE

# ensure our project modules are importable
sys.path.append(ELDIFF_APP)

LOG_FILE = os.path.join(ELDIFF_APP, "decompilation_log.txt")

def log_message(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def any_function_seeds_exist(bin_name, bin_ver):
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
    with sqlite3.connect(DATABASE_FILE) as conn:
        cur = conn.cursor()
        cur.execute(q, (bin_name, bin_ver))
        return cur.fetchone() is not None

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

def dump_all_funcs_to_json(output_path: str):
    funcs = []
    funcs_qty = ida_funcs.get_func_qty()

    for func in range(funcs_qty):
        f = ida_funcs.getn_func(func)
        funcs.append({"name": ida_funcs.get_func_name(f.start_ea), "addr":
                      f.start_ea})
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(funcs, f, indent=2)

        return funcs
        

def load_func_list(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_func_lists(old_funcs, new_funcs):
    old_map = {f["name"]: f["addr"] for f in old_funcs}
    new_map = {f["name"]: f["addr"] for f in new_funcs}

    added   = [{"name": n, "addr": a} for n, a in new_map.items() if n not in old_map]
    deleted = [{"name": n, "addr": a} for n, a in old_map.items() if n not in new_map]
    return added, deleted

def fetch_deleted_rows(bin_name, bin_ver):
    q = """
        SELECT id, name, address
        FROM added_deleted_funcs
        WHERE binary_name = ?
        AND binary_version = ?
        AND function_type = ?
        AND func_blob IS NULL
    """
    with sqlite3.connect(DATABASE_FILE) as conn:
        cur = conn.cursor()
        cur.execute(q, (bin_name, bin_ver, DELETED))
        return cur.fetchall()

def update_deleted_blob(rowid, gz_blob):
    q = """
    UPDATE added_deleted_funcs
    SET func_blob = ?
    WHERE id = ?
    """
    with sqlite3.connect(DATABASE_FILE) as conn:
        cur = conn.cursor()
        cur.execute(q, (gz_blob, rowid))
        conn.commit()
        return True


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


if __name__ == "__main__":
    try:
        log_message("[INFO] decompile_added_deleted.py started")
       
        # init hexrays
        if not idaapi.init_hexrays_plugin():
            log_message("[ERROR] Hex-Rays init failed")
            save_and_exit(1)

        if len(idc.ARGV) < 3:
            log_message("[ERROR] Usage: -Sdecompile_added_deleted.py <binary_name> <binary_version>")
            save_and_exit(1)

        bin_name, bin_ver = idc.ARGV[1], idc.ARGV[2]

        # if any_function_seeds_exist(bin_name, bin_ver):
        #     log_message(f"[INFO] Added/deleted functions already processed for {bin_name} {bin_ver}") 
        #     save_and_exit(0)

        log_message(f"[INFO] Target: {bin_name} v{bin_ver}")

        # wait for auto-analysis
        log_message("[INFO] Waiting for auto-analysis...")
        idc.auto_wait()

        deleted = fetch_deleted_rows(bin_name, bin_ver)
        if not deleted:
            log_message(f"[INFO] No deleted stubs to process for {bin_name} {bin_ver}")
            save_and_exit(0)


        count_success = 0
        count_fail = 0

        for (rowid, func_name, addr) in deleted:
            addr = int(addr, 16) if isinstance(addr, str) else addr
            code = decompile_function(addr)
            if not code:
                log_message(f"[ERROR] Failed to decompile DELETED function {func_name} @ {hex(addr)} (rowid={rowid})")
                count_fail += 1
                continue

            gz = gzip.compress(code.encode())
            if update_deleted_blob(rowid, gz):
                count_success += 1
                log_message(f"[INFO] Updated DELETED function {func_name} @ rowid={rowid}")

            else:
                count_fail += 1

        log_message(f"[INFO] decompile_added_deleted.py finished: {count_success} succeeded, {count_fail} failed for {bin_name} {bin_ver}")

    except Exception:
        log_message("[CRITICAL] unhandled exception: \n" + traceback.format_exc())

    finally:
        save_and_exit(0)
