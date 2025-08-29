import subprocess
import os
import shutil
import time
import sqlite3
from PatchExtractorManager import *
# from Utils import *
import gzip
import tempfile
import difflib
from Utils import Utils
from config import ELDIFF_APP, DATABASE_FILE, get_bindiff_path, get_ida_path, get_num_ctx_line, get_phase123_path, get_phase4_path

# Statuses for analyzed files
PENDING = 0x0
IN_PROGRESS = 0x1
COMPLETED = 0x2

logger = logging.getLogger(__name__)

class DiffManager():
    @staticmethod
    def test_logger():
        logger.warning("Test logger")

    @staticmethod
    def get_name_from_file_path(path) -> str:
        name = os.path.splitext(os.path.basename(path))[0]
        return name

    @staticmethod
    # TODO: rewrite to make a generic function to add any columng
    def create_column(cursor, column_name):
       cursor.execute(f"ALTER TABLE binaries ADD COLUMN {column_name} TEXT;")

    @staticmethod
    def get_bin_id_by_bin_path(cursor, binary_path):
        cursor.execute("SELECT id FROM binaries WHERE binary_path = ?", (binary_path,))
        result = cursor.fetchone()
        return result[0] if result else None

    @staticmethod
    def is_ida_path_exist_for_binary(cursor, binary_path) -> bool:
        cursor.execute("SELECT ida_path FROM binaries WHERE binary_path = ?", (binary_path,))
        result = cursor.fetchone()
        if result[0]:
            return True
        else:
            return False
        
    @staticmethod
    def is_binexport_exist_for_binary(cursor, binary_path) -> bool:
        cursor.execute("SELECT binexport_path FROM binaries WHERE binary_path = ?", (binary_path,))
        result = cursor.fetchone()
        if result[0]:
            return True
        else:
            return False

    # @staticmethod
    # def binexport_folder_lookup(binary_path):
    @staticmethod
    def file_exists_in_folder(file_name, folder_name):
    # Create the full path to the file
        file_path = os.path.join(folder_name, file_name)
        
        # Check if the file exists
        return os.path.isfile(file_path)


    @staticmethod
    def run_ida_batch(binary_path, db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        binary_name = os.path.basename(binary_path)
        ida_db_name = binary_name + ".i64"
        binexport_db_name = binary_name + ".BinExport"
        base_path = os.path.dirname(os.path.dirname(binary_path))
        binexport_db_path = os.path.join(base_path, "binexport")

        if not DiffManager.column_exists_in_table("binaries", "ida_path", cursor):
            try:
                DiffManager.create_column(cursor, "ida_path")
                conn.commit()
                logger.info(f"ida_path column added to the binaries table")
            except sqlite3.Error as e:
                logger.error(f"Error adding ida_path column: {e}")

        if DiffManager.is_ida_path_exist_for_binary(cursor, binary_path):
            logger.warning(f"IDA database already exists for {binary_path}")
            if DiffManager.is_binexport_exist_for_binary(cursor, binary_path):
                logger.warning(f"BinExport database already exists for {binary_path}")
            # TODO: if not set the binexport path accordingly based on the path in binexport folder
            if DiffManager.file_exists_in_folder(binexport_db_name, binexport_db_path):
                logger.warning(f"BinExport database exist for the {binexport_db_name} in {binexport_db_path}")
                cursor.execute("UPDATE binaries SET binexport_path = ? WHERE binary_path = ?", (os.path.join(binexport_db_path, binexport_db_name), binary_path),)
                conn.commit()

            conn.close()
            return None

        binary_id = DiffManager.get_bin_id_by_bin_path(cursor, binary_path)

        command = [get_ida_path(), "-B", binary_path]
        try:
            subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
        )

            source_ida_db_path = os.path.join(os.path.dirname(binary_path), ida_db_name)
            ida_databases_path = os.path.join(base_path, "ida_databases")
            
            dest_path = os.path.join(ida_databases_path, ida_db_name)
            if os.path.exists(source_ida_db_path):
                path = shutil.move(source_ida_db_path, dest_path)
                DiffManager.update_database_with_ida_path(binary_id, path, cursor)
                conn.commit()
                conn.close()
                return path

            else:
               conn.close()
               return None 

        except subprocess.CalledProcessError as e:
            logger.exception(f"Error for {binary_path}")

    # @staticmethod
    # def get_binary_from_binaries(db_path, kb_date):
    #     try:
    #         conn = sqlite3.connect(db_path)  # Establish the database connection
    #         cursor = conn.cursor()

    #         cursor.execute("""SELECT binary_path, KbDate, binary_version FROM binaries WHERE KbDate = ?""", (kb_date,))
    #         records = cursor.fetchall()

    #         if records:
    #             return records  # Return the record if found
    #         else:
    #             return None  # Return None if no record is found
    #     except sqlite3.Error as e:
    #         print(f"An error occurred: {e}")  # Handle any database errors
    #     finally:
    #         if conn:
    #             conn.close()  # Ensure the connection is closed

    @staticmethod
    def get_binary_path_from_ida_path(cursor, ida_db_path):
        cursor.execute("SELECT binary_path FROM binaries WHERE ida_path = ?",
                       (ida_db_path,))
        result = cursor.fetchone()
        return result[0] if result else None

    @staticmethod
    def is_binexport_exist_in_db(cursor, binary_path) -> bool:
        cursor.execute("SELECT binexport_path FROM binaries WHERE binary_path = ?", (binary_path,))
        result = cursor.fetchone()
        return bool(result and result[0])      

    @staticmethod
    def generate_binexport(binary_path, ida_dir):
        """
        Generate a BinExport file using bindiff.exe.
        """
        if binary_path:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Check if binexport_path column exist in binaries table
            if not DiffManager.column_exists_in_table("binaries", "binexport_path", cursor):
                try:
                    DiffManager.create_column(cursor, "binexport_path")
                    conn.commit()
                    print("[+] binexport path column added to binaries table")
                except sqlite3.Error as e:
                    print(f"Error adding binexport_path column: {e}")

            # TODO: Check if BinExport file already exist in the database
            # BUG: ida_db_path is not path to he actual file, but only to the directory
            if DiffManager.is_binexport_exist_in_db(cursor, binary_path):
                print(f"BinExport path already exists for IDA database: {binary_path}")
                conn.close()
                return

            base_path = os.path.dirname(binary_path)
            # file_version = PatchExtractorManager.parse_file_version_from_path(base_path)
            binexport_path = os.path.join(base_path, "binexport")
            print(f"binexport_path is {binexport_path}")

            command = [
                get_bindiff_path(),
                "--export",
                ida_dir,
                "--output_dir",
                binexport_path
            ]

            try:
                subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                binexport_file = next((f for f in os.listdir(binexport_path) if
                                    f.endswith(".BinExport") and
                                    os.path.isfile(os.path.join(binexport_path, f))), None,)

                if binexport_file:
                    binexport_file_path = os.path.join(binexport_path, binexport_file)
                    #BUG: looks like a bug here, cause ida_db_path is not the file path
                    cursor.execute("UPDATE binaries SET binexport_path = ? WHERE binary_path = ?", (binexport_file_path, binary_path), )
                    conn.commit()
                    print(f"Updated BinExport path for {binary_path}: {binexport_file_path}")
                else:
                    print(f"No BinExport file generated for {binary_path}")
            except subprocess.CalledProcessError as e:
                print(f"Error {e.returncode} while generating BinExport for {binary_path}: {e.stderr.strip()}")
            finally:
                conn.close()
        else:
            return

    @staticmethod
    def generate_binexport_for_kbdate(upd_path, kb_date: str):
        """
        Process all IDA databases for a KB date and update BinExport paths
        """
        try:
            with sqlite3.connect(DATABASE_FILE) as conn:
                cursor = conn.cursor()

                # 1. Get all binaries for this KB date
                cursor.execute("""
                    SELECT binary_path, ida_path 
                    FROM binaries 
                    WHERE KbDate = ? 
                """, (kb_date,))
                
                binaries = cursor.fetchall()
                
                # 2. Get common base path for IDA databases
                if not binaries:
                    return
                    
                sample_path = binaries[0][1]
                ida_base_dir = os.path.dirname(sample_path)
                
                # 3. Generate BinExport for all IDA databases
                command = [
                    get_bindiff_path(),
                    "--export",
                    ida_base_dir,
                    "--output_dir",
                    os.path.join(upd_path, "binexport")
                ]
                
                subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )

                # 4. Update database with generated paths
                binexport_dir = os.path.join(upd_path, "binexport")
                for root, _, files in os.walk(binexport_dir):
                    for file in files:
                        if file.endswith(".BinExport"):
                            # Extract binary name from filename
                            binary_name = file.rsplit('.', 1)[0]
                            binexport_path = os.path.join(root, file)
                            
                            # Update all matching binaries (handle multiple versions)
                            cursor.execute("""
                                UPDATE binaries 
                                SET binexport_path = ? 
                                WHERE binary_name = ? 
                                AND KbDate = ?
                            """, (binexport_path, binary_name, kb_date))
                
                conn.commit()
                logger.info(f"Updated BinExport paths for {kb_date}")

        except Exception as e:
            logger.exception(f"Error processing {kb_date}")

    @staticmethod
    def get_previous_version_path_binexport(cursor, binary_name, current_version):
        cursor.execute("""SELECT binexport_path FROM binaries WHERE binary_name = ? AND binary_version < ? ORDER BY binary_version DESC LIMIT 1""", (binary_name, current_version,))
        prev_version = cursor.fetchone()
        return prev_version[0] if prev_version else None

    @staticmethod
    def generate_bindiff(kb_date, db_path, upd_dir):
        conn  = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if not DiffManager.column_exists_in_table("binaries", "bindiff_path", cursor):
            DiffManager.create_column(cursor, "bindiff_path")
        
        cursor.execute("""SELECT binary_name, binexport_path, binary_version, binary_path FROM binaries WHERE KbDate = ?""", (kb_date,))
        binaries = cursor.fetchall()

        for binary_name, current_binexport, current_version, binary_path in binaries:
            # Find the previous verion's of BinExport db's
            previous_version = DiffManager.get_previous_version_path_binexport(cursor, binary_name, current_version)
            if not previous_version or not current_binexport:
                logger.warning(f"No previous version found for {binary_name}")
                continue

            # Construct the output path for the .BinDiff file
            output_dir = os.path.dirname(os.path.dirname(binary_path))
            base_path = os.path.dirname(os.path.dirname(binary_path))
            bindiff_path = os.path.join(upd_dir, "bindiff")
            expected_bindiff_file =  f"{binary_name}_vs_{binary_name}.BinDiff"
            expected_bindiff_path = os.path.join(bindiff_path, expected_bindiff_file)

            command = [
                get_bindiff_path(),
                "--primary",
                previous_version,
                "--secondary",
                current_binexport,
                "--output_dir",
                bindiff_path,
            ]

            try:
                subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                # Check if BinDiff file generated by name and udpate db with path to it 
                logger.info(f"Generated BinDiff for {binary_name} successfull")
                if os.path.isfile(expected_bindiff_path):
                    logger.info(f"Located BinDiff file: {expected_bindiff_path}")

                    cursor.execute("""UPDATE binaries SET bindiff_path = ? WHERE binary_name = ? and KbDate = ?""",
                                    (expected_bindiff_path, binary_name, kb_date),)
                    conn.commit()
                else:
                    logger.warning(f"Expected BinDiff file not found: {expected_bindiff_path}.")

            except subprocess.CalledProcessError as e:
                logger.exception("Failed to generate BinDiff")

        conn.close()

    # @staticmethod
    # def run_full_analysis(binary_path):
    #     """
    #     Perform the full analysis: create .i64 and generate BinExport file.
    #     """
    #     ida_db_path = DiffManager.run_ida_batch(binary_path, DATABASE_FILE)

    #     if ida_db_path:
    #         # BUG: binexport process all the ida databases at once. We should to run it outside the run_full_analysis loop
    #         DiffManager.generate_binexport(os.path.dirname(ida_db_path))
    #     else:
    #         return None
        
    @staticmethod
    def column_exists_in_table(table_name, column_name, cursor) -> bool:
        """
        Checks if a specific column exists in a given table.
        """
        exists = False
        try:
            query = f"PRAGMA table_info({table_name});"
            cursor.execute(query)
            columns = cursor.fetchall()
            for column in columns:
                if column[1] == column_name:  # Column name is in the second position
                    exists = True
                    break
        except sqlite3.Error as e:
            print(f"Database error while checking column existence: {e}")
            
        return exists

    @staticmethod
    def update_database_with_ida_path(binary_id, ida_path, cursor):
        """
        Updates the database with the IDA database path for the specified binary ID.
        """
        try:
            query = "UPDATE binaries SET ida_path = ? WHERE id = ?;"
            cursor.execute(query, (ida_path, binary_id))
            logger.info(f"Database updated with IDA path: {ida_path} for binary ID: {binary_id}")
        except sqlite3.Error as e:
            logger.error(f"Database error while updating IDA path")


    @staticmethod
    def update_binary_hashes(database_path, kb_date):
        """Update the Binaries table with hashes for each binary."""
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()

        cursor.execute("SELECT ID, binary_path FROM binaries WHERE KbDate = ?", (kb_date,))
        rows = cursor.fetchall()

        # Iterate through each row and update the binary_hash
        for row in rows:
            binary_id, binary_path = row
            if binary_path:
                abs_path = os.path.join(ELDIFF_APP, binary_path)
                binary_hash = Utils.calculate_file_hash(abs_path)
                if binary_hash:
                    # Update the binary_hash column for the current binary
                    cursor.execute(
                        "UPDATE binaries SET binary_hash = ? WHERE ID = ?",
                        (binary_hash, binary_id)
                    )
                    logger.info(f"Updated binary ID {binary_id} with hash: {binary_hash}")
                else:
                    logger.warning(f"Skipping binary ID {binary_id} due to missing file.")
            else:
                logger.warning(f"Skipping binary ID {binary_id} due to empty binary_path.")

        # Commit changes and close the connection
        conn.commit()
        conn.close()
        print("All hashes updated successfully.")

    @staticmethod
    def get_ida_paths(db_path, binary_name, current_version):
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Execute the query
        cursor.execute("""
            SELECT ida_path
            FROM binaries
            WHERE binary_name = ?
            AND binary_version <= ?
            AND ida_path is NOT NULL
            ORDER BY binary_version DESC
            LIMIT 2
        """, (binary_name, current_version))

        # Fetch the results
        results = cursor.fetchall()
        conn.close()

        # Return the IDA paths
        return [row[0] for row in results]


    @staticmethod
    def fetch_bindiff_paths(db_path, KbDate):
        """
        Fetch all bindiff_paths from the binaries table for a specific updateid.
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT bindiff_path
            FROM binaries
            WHERE KbDate = ?
        """, (KbDate,))

        # Fetch all results
        bindiff_paths = [row[0] for row in cursor.fetchall()]
        conn.close()

        return bindiff_paths

    @staticmethod
    def fetch_functions_from_bindiff(bindiff_path):
        """
        Open a BinDiff database and fetch functions with similarity < 1.
        """
        with sqlite3.connect(bindiff_path) as conn:

            functions = conn.execute("""
                SELECT name1, address1, address2, similarity
                FROM function
                WHERE similarity < 1
                ORDER BY similarity DESC
            """).fetchall()

        return functions
    
    @staticmethod
    def decompile_function(ida_path, script_path, database_path, address):
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
        temp_output = temp_file.name
        temp_file.close()
        
        try:
            command = [
                ida_path,
                "-A",
                f'-S{script_path} {address} {temp_output}',
                database_path
            ]

            subprocess.run(command, check=True)

            with open(temp_output, "r") as f:
                decompiled_code = f.read()

        finally:
            os.remove(temp_output)

        return decompiled_code

    @staticmethod
    def make_diff(db_path, binary_name, binary_version):
        """
        Generate unified diffs with descriptive file names
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        try:
            # Fetch all function pairs with both old and new code
            cursor.execute('''
                SELECT rowid, name1, name2, old_code, new_code 
                FROM functions
                WHERE binary_name = ?
                AND binary_version = ?
                AND old_code IS NOT NULL 
                AND new_code IS NOT NULL
                AND diff is NULL
            ''', (binary_name, binary_version))
            
            for rowid, name1, name2, old_gz, new_gz in cursor.fetchall():
                try:
                    # Decompress both versions
                    old_code = gzip.decompress(old_gz).decode()
                    new_code = gzip.decompress(new_gz).decode()

                    # Create descriptive file names
                    fromfile = f"{name1}_old"
                    tofile = f"{name2}_new"
                    
                    # Generate unified diff
                    diff = difflib.unified_diff(
                        old_code.splitlines(),
                        new_code.splitlines(),
                        fromfile=fromfile,
                        tofile=tofile,
                        n = get_num_ctx_line(),
                        lineterm=''
                    )
                    diff_text = '\n'.join(list(diff))
                    
                    diff_gz = gzip.compress(diff_text.encode())
                    cursor.execute('''
                        UPDATE functions 
                        SET diff = ?
                        WHERE rowid = ?
                    ''', (diff_gz, rowid))
                    
                except (gzip.BadGzipFile, UnicodeDecodeError) as e:
                    logger.exception(f"Skipping corrupt data in row {rowid}")
                    continue
            
            cursor.execute('''
            UPDATE binaries
            SET status = 1
            WHERE binary_name = ? 
            AND binary_version = ?
            AND EXISTS (
                SELECT 1 
                FROM functions 
                WHERE functions.binary_name = binaries.binary_name
                AND functions.binary_version = binaries.binary_version
                AND functions.diff IS NOT NULL
                AND LENGTH(functions.diff) > 0
            ) ''', (binary_name, binary_version))
            
            conn.commit()
            
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            conn.rollback()
        finally:
            conn.close()

    @staticmethod
    def process_added_deleted_functions(db_path, ida_exe_path, script_path, binary_name, binary_version):

        ida_paths = DiffManager.get_ida_paths(db_path, binary_name, binary_version)
        if len(ida_paths) != 2:
            logger.warning(f"Found {len(ida_paths)} for {binary_name} {binary_version}") 
            return False

        old_idb = ida_paths[1]
        old_idb_abs = os.path.join(ELDIFF_APP, old_idb)
        
        if not os.path.isfile(old_idb_abs):
            logger.error(f"Old IDB not found on disk: {old_idb_abs}")
            return False

        cmd = [
            ida_exe_path,
            "-A",  # batch mode: no GUI, exit on finish
            f'-S{script_path} {binary_name} {binary_version}',
            old_idb_abs
        ]

        logger.warning(f"Running IDA: {cmd}")
        subprocess.run(cmd)
        return True


    @staticmethod
    def analyze_funcs(db_path, ida_exe_path, script_path, binary_name, binary_version):
        # get_ida_paths returns [latest_idb, previous_idb] (descending)
        ida_paths = DiffManager.get_ida_paths(db_path, binary_name, binary_version)

        if len(ida_paths) != 2:
            logger.warning(f"Incorrect number of IDA DBs for {binary_name} {binary_version}")
            return

        # Swap them so that we process the *previous* IDB first, then the current one
        prev_idb, curr_idb = ida_paths[1], ida_paths[0]

        # 1) Open the old IDB, let the decompile‐script dump its function list (“_old.json”)
        cmd_old = [
            ida_exe_path,
            "-A",
            f'-S{script_path} {binary_name} {binary_version}',
            os.path.join(ELDIFF_APP, prev_idb)
        ]
        logger.warning(f"Running IDA on {prev_idb}: {cmd_old}")
        subprocess.run(cmd_old)

        # 2) Open the new IDB, let the same script dump its function list (“_new.json”)
        cmd_new = [
            ida_exe_path,
            "-A",
            f'-S{script_path} {binary_name} {binary_version}',
            os.path.join(ELDIFF_APP, curr_idb)
        ]
        logger.warning(f"Running IDA on {curr_idb}: {cmd_new}")
        subprocess.run(cmd_new)
        
    @staticmethod
    def check_diff_status(db_path, binary_name, binary_version):
        """Check if diff already exists for this binary"""
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT status FROM binaries
                WHERE binary_name = ? AND binary_version = ?
            ''', (binary_name, binary_version))
            result = cursor.fetchone()
            return result[0] if result else False

# Example usage
# ida_path = r"C:\Program Files\IDA Pro 8.3\ida64.exe"
# script_path = r"D:\eldiff\decompile_func.py"
# database_path = r"D:\Downloads\test\Updates\2024-Dec\x64\10.0.22621.4601\ida_databases\clfs.sys.i64"
# address = "0x1C00023CC"
# output_file = r"output.c"

# data = DiffManager.decompile_function(ida_path, script_path, database_path, address)
# print(data)

# binary_files = [r"D:\Downloads\test\Updates\2024-Dec\x64\10.0.22621.4601\binaries\clfs.sys",
#                 r"D:\Downloads\test\Updates\2024-Oct\x64\10.0.22621.4317\binaries\clfs.sys"]

# asyncio.run(DiffManager.run_ida_batch_for_files(binary_files))

# records = DiffManager.get_binary_from_binaries("./scripts/updates.db", "2025-Feb")
# file_paths = [item[0] for item in records]

# for i in records:
#     binary_path, update_id, binary_version = i
#     DiffManager.run_full_analysis(binary_path)

# DiffManager.generate_bindiff("2025-Feb", EL_DIFF_DB_PATH)
# DiffManager.update_binary_hashes(EL_DIFF_DB_PATH, "2024-12-10")

# binary_name = "win32kfull.sys"
# current_version = "10.0.22621.4601"
# ida_paths = DiffManager.get_ida_paths(EL_DIFF_DB_PATH, binary_name, current_version)

# if len(ida_paths) == 2:
#     current_ida_path, previous_ida_path = ida_paths
#     print(f"Current IDA Path: {current_ida_path}")
#     print(f"Previous IDA Path: {previous_ida_path}")
# else:
#     print("Not enough IDA databases found.")


# def main():
#     updateid = "2024-Dec"

#     # Step 1: Fetch all bindiff_paths for the given updateid
#     bindiff_paths = DiffManager.fetch_bindiff_paths(EL_DIFF_DB_PATH, updateid)
#     if not bindiff_paths:
#         print(f"No BinDiff databases found for updateid: {updateid}")
#         return

#     print(f"Found {len(bindiff_paths)} BinDiff databases for updateid: {updateid}")

#     all_func = []
#     # Step 2: Process each BinDiff database
#     for bindiff_path in bindiff_paths:
#         print(f"\nProcessing BinDiff database: {bindiff_path}")

#         # Fetch functions with similarity < 1
#         if not bindiff_path:
#             continue
#         functions = DiffManager.fetch_functions_from_bindiff(bindiff_path)
#         if not functions:
#             print("No functions found with similarity < 1.")
#             continue

#         # Display the results
#         print(f"Found {len(functions)} functions with similarity < 1:")
#         for name1, address1, address2, similarity in functions:
#             print(f"Function: {name1}")
#             all_func.append(name1)
#             print(f"Address1: {hex(address1)}, Address2: {hex(address2)}")
#             print(f"Similarity: {similarity}")
#             print("-" * 40)

#     print(f"Sum functions: {len(all_func)}")

# if __name__ == "__main__":
# # #     main()

#     ida_path = r"C:\Program Files\IDA Pro 8.3\ida64.exe"
#     script_path = r"D:\eldiff\decompile_func.py" 
#     database_path = r"D:\Downloads\test\Updates\2025-Feb\x64\10.0.22621.4890\ida_databases\win32kfull.sys.i64"
# #     # database_path = r"D:\Downloads\test\Updates\2024-Oct\x64\10.0.22621.4317\ida_databases\clfs.sys.i64"
#     binary_name = "win32kfull.sys"
#     binary_version = "10.0.22621.4890"

#     # command = [
#     #     ida_path,
#     #     "-A",
#     #     f'-S{script_path} {binary_name} {binary_version}',
#     #     database_path
#     # ]

#     # subprocess.run(command)

#     DiffManager.analyze_funcs(EL_DIFF_DB_PATH, ida_path, script_path, binary_name, binary_version)
#     DiffManager.make_diff(EL_DIFF_DB_PATH)

# DiffManager.analyze_funcs(r"D:\eldiff\scripts\updates.db", ida_path, script_path, "ksthunk.sys", "10.0.22621.5037")
# DiffManager.update_binary_hashes(EL_DIFF_DB_PATH)


# upd_dir = r"updates\2024-12-10"
# x64_bin_path =  r"D:\eldiff\updates\2024-12-10\x64"
# with sqlite3.connect(db_path) as conn:
# DiffManager.make_diff(db_path, "cldflt.sys", "10.0.22621.4830")
#     cur = conn.cursor()
#     # pull down each distinct (name, version) exactly once
#     cur.execute("""
#         SELECT DISTINCT binary_name, binary_version
#           FROM binaries 
#          WHERE KbDate = ?
#     """, (kb_date,))
#     binaries = cur.fetchall()  # list of (name, version)

# for binary_name, binary_version in binaries:
#     print(f"→ Processing {binary_name} v{binary_version}")
#     DiffManager.analyze_funcs(
#         db_path,
#         MicrosoftUpdateFetcher.IDA_EXE_PATH,
#         MicrosoftUpdateFetcher.SCRIPT_PATH,
#         binary_name,
#         binary_version
#     )
#     DiffManager.make_diff(
#         db_path,
#         binary_name,
#         binary_version
#     )
# conn = sqlite3.connect(db_path)
# cur = conn.cursor()
# cur.execute("SELECT binary_name from binaries where KbDate = ?", (kb_date,))
# binaries = cur.fetchall()

# binaries = [item[0] for item in binaries]

# for b in binaries:
#     cur.execute("SELECT binary_version from binaries where binary_name = ? AND KbDate = ?", (b, kb_date,))
#     v = cur.fetchone()[0]
    # print(b, v)
def main():
    db_path = DATABASE_FILE 
    kb_date = "2025-08-12"
    binaries = PatchExtractorManager.get_binaries_for_kbdate(db_path, kb_date)
    for binary_name, binary_version, binary_path in binaries:
        DiffManager.analyze_funcs(db_path, get_ida_path(), get_phase123_path(), binary_name, binary_version)
        DiffManager.make_diff(db_path, binary_name, binary_version)
        DiffManager.process_added_deleted_functions(db_path,
                                                    get_ida_path(),
                                                    get_phase4_path(),
                                                    binary_name,
                                                    binary_version)
if __name__ == "__main__":
    main()
