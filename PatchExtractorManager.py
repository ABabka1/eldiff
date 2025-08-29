import os
import sqlite3
import re
import subprocess
import logging
from packaging import version
from typing import Dict, Tuple, List, Set, Optional
from collections import Counter
from config import POPULAR_BINARIES
import shutil
from packaging import version
from config import ELDIFF_APP, DATABASE_FILE, UPDATES_DIR, X64_DIR, get_system32_path, get_winsxs_path, get_extensions, get_python_path 

logger = logging.getLogger(__name__)

class PatchExtractorManager():
    @staticmethod
    def test_logger():
        logger.warning("Test logger")

    @staticmethod
    # This is another update_id from the microsoft website
    def get_kb_from_update_id(kb_date, db_path):
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''SELECT URL FROM Vulnerabilities WHERE KbDate = ?''', (kb_date,))
                record = cursor.fetchone()

            if record and record[0]:
                url = record[0]
                match = re.search(r'\?q=([^&]+)', url)
                return match.group(1) if match else None
            return None

        except sqlite3.Error as e:
            logger.error("Database error: %s", e)
            return None
        except Exception as e:
            logger.exception("An unexpected error occurred")
            return None

    @staticmethod
    def run_patch_extract(script_path, patch_file, output_path):
        command = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-Patch", patch_file,
            "-Path", output_path
        ]

        try:
            result = subprocess.run(command, capture_output=True, text=True)
            print("Output:", result.stdout)
            print("Error:", result.stderr)
            return True
        except subprocess.CalledProcessError as e:
            print("Output:", e.stdout)
            print("Error:", e.stderr)
            return False

    @staticmethod
    def find_forward_reverse_delta_by_name(path, filename, delta_type):
        """
        Search for a specific file in a specific subfolder within a directory tree.

        Args:
            path (str): The root directory to traverse.
            filename (str): The name of the file to search for.
            delta_type (str): The subfolder name to look for (e.g., 'f' or 'r').
            base_path (str): Path to base binary for version extraction

        Returns:
            str: The full path to the file if found, otherwise None.
        """
        # base_version = PatchExtractorManager.parse_file_version_from_path(base_path)
        # if not base_version:
        #     return None


        for root, dirs, files in os.walk(path):
            if delta_type in dirs:
                subfolder_path = os.path.join(root, delta_type)
                for file in files:
                    if file.lower() == filename:
                        return os.path.join(subfolder_path, file)
        return None

    @staticmethod
    def find_any_delta_files(path, delta_type):
        """
        TODO: rewrite this function with async I/O
        Search for any files in a specific delta subfolder ('f' or 'r') within a directory tree.

        Args:
            path (str): The root directory to traverse.
            delta_type (str): The subfolder name to look for (e.g., 'f' or 'r').

        Returns:
            list: A list of full paths to the files found in the specified delta subfolder.
        """
        delta_files = []

        for root, dirs, files in os.walk(path):
            if delta_type in dirs:
                subfolder_path = os.path.join(root, delta_type)
                for file in os.listdir(subfolder_path):
                    delta_files.append(os.path.join(subfolder_path, file))

        return delta_files

    @staticmethod
    def filter_files_by_extensions(file_list, extensions):
        filtered_files = {}

        for file_path in file_list:
            _, ext = os.path.splitext(file_path)
            if ext.lower() in extensions:
                filename = os.path.basename(file_path)
                filtered_files[filename] = file_path

        return filtered_files

    @staticmethod
    def find_any_files_in_delta(path, delta_type):
        """
        Search for any files in a specific delta subfolder ('f' or 'r') within a directory tree.

        Args:
            path (str): The root directory to traverse.
            delta_type (str): The subfolder name to look for (e.g., 'f' or 'r').

        Returns:
            list: A list of full paths to the files found in the specified delta subfolder.
        """
        found_files = []

        for root, dirs, files in os.walk(path):
            if delta_type in dirs:
                subfolder_path = os.path.join(root, delta_type)
                for file in os.listdir(subfolder_path):
                    found_files.append(os.path.join(subfolder_path, file))

        return found_files

    @staticmethod
    def parse_file_version_from_path(file_path) -> Optional[str]:
        match = re.search(r'\d{2}.\d{1}.\d{5}.\d+', file_path)
        if match:
            return match.group(0) if match else None

    @staticmethod
    def get_reverse_delta_list_for_patches(patched_binaries):
        r_delta_list = []
        for b in patched_binaries:
            name = os.path.basename(b)
            rev_delta = PatchExtractorManager.find_forward_reverse_delta_by_name(get_winsxs_path(), name, "r")
            if rev_delta:
                r_delta_list.append(rev_delta)

        return r_delta_list

    @staticmethod
    def find_base_binary(filename: str, search_path: str = get_system32_path()) -> Optional[str]:
        for root, dirs, files in os.walk(search_path):
            for file in files:
                if file.lower() == filename:
                    return os.path.join(root, file)  # Return the full path of the found file

        return None

    @staticmethod
    def populate_binaries_table(db_path, kb_date, patched_binaries):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        for patched_binary in patched_binaries:
            binary_name = os.path.basename(patched_binary)
            binary_version = PatchExtractorManager.parse_file_version_from_path(patched_binary)
            kb = PatchExtractorManager.get_kb_from_update_id(kb_date, db_path)

            base_path = PatchExtractorManager.find_base_binary2(binary_name, binary_version, get_winsxs_path()) or PatchExtractorManager.find_base_binary2(binary_name, binary_version, get_system32_path())
            if not base_path:
                continue

            binary_path = "None"
            base_version = PatchExtractorManager.parse_file_version_from_path(base_path)
            if base_version and version.parse(base_version) == version.parse(binary_version):
                binary_path = base_path

            logger.info(f"Base path for {binary_name} v{binary_version} is: {base_path}")
            if base_path is None:
                continue

            cursor.execute('''INSERT OR IGNORE INTO binaries (binary_name, forward_delta_path, base_path, KB, KbDate, binary_path, binary_version) VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (binary_name, patched_binary, base_path, kb, kb_date, binary_path, binary_version))

            conn.commit()
        conn.close()

    @staticmethod
    def apply_patch(base_path, forward_delta_path, reverse_delta_path, output_path, patch_script_path):
        """
        Applies forward and reverse deltas to create the patched binary.
        """
        try:
            cmd = [
                get_python_path(), patch_script_path,
                "-i", base_path,
                "-o", output_path,
                reverse_delta_path,
                forward_delta_path
            ]
            subprocess.run(cmd, check=True)
            logger.info(f"Successfully created patched binary at: {output_path}")
            return True
        except subprocess.CalledProcessError as e:
            logger.exception(f"Failed to apply patch for {base_path}: {e}")
            return False

    @staticmethod
    def create_folder_structure(upd_dir):
        """
        Creates the required folder structure for binaries.
        """
        directories = {
            "binaries": os.path.join(upd_dir, "binaries"),
            "ida_databases": os.path.join(upd_dir, "ida_databases"),
            "binexport": os.path.join(upd_dir, "binexport"),
            "bindiff": os.path.join(upd_dir, "bindiff"),
            "diffs": os.path.join(upd_dir, "diffs"),
        }
        for path in directories.values():
            os.makedirs(path, exist_ok=True)
        return directories

    @staticmethod
    def process_and_update_binaries(db_path, upd_dir, patch_script_path, kb_date):
        """
        Process binaries, apply patches, create folder structure, and update the database.
        """
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()

        cursor.execute("""
            SELECT ID, binary_name, forward_delta_path, base_path, KbDate, binary_version FROM binaries WHERE KbDate = ?
        """, (kb_date,))
        rows = cursor.fetchall()

        folders = PatchExtractorManager.create_folder_structure(upd_dir)

        for row in rows:
            row_id, binary_name, forward_delta_path, base_path, kb_date, patched_version = row
            reverse_delta_path = os.path.join(os.path.dirname(base_path), 'r', binary_name)
            if not os.path.exists(reverse_delta_path):
                logger.warning(f"Reverse delta not found for {binary_name}, skipping...")
                continue

            patched_binary_path = os.path.join(folders["binaries"], binary_name)

            base_ver = PatchExtractorManager.parse_file_version_from_path(base_path)
            if base_ver and version.parse(base_ver) == version.parse(patched_version):
                if not os.path.exists(patched_binary_path):
                    shutil.copy2(base_path, patched_binary_path)
                    logger.info(f"Copied base {binary_name} v{base_ver} -> {patched_binary_path}")
                else:
                    logger.warning(f"Already copied: {patched_binary_path}")

                cursor.execute("""
                    UPDATE binaries
                    SET binary_path = ?
                    WHERE ID = ?
                """, (patched_binary_path, row_id))
                logger.info(f"Database updated for {binary_name}")

                continue  # IMPORTANT: avoid apply_patch below

            if not os.path.exists(patched_binary_path):
                success = PatchExtractorManager.apply_patch(base_path, forward_delta_path, reverse_delta_path, patched_binary_path, patch_script_path)
                if success:
                    cursor.execute("""
                        UPDATE binaries
                        SET binary_path = ?
                        WHERE ID = ?
                    """, (patched_binary_path, row_id))
                    logger.info(f"Database updated for {binary_name}")
            else:
                logger.warning(f"Patched binary already exists: {patched_binary_path}")

        conn.commit()
        conn.close()

    @staticmethod
    def get_binaries_for_kbdate(db_path: str, kb_date: str) -> list:
        """Get all binaries with names and versions for a specific KbDate"""
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT binary_name, binary_version, binary_path
                FROM binaries 
                WHERE KbDate = ?
            """, (kb_date,))
            binaries = cursor.fetchall()
            return binaries 

    @staticmethod
    def find_patched_binaries2(path: str) -> list:
        files = PatchExtractorManager.find_any_files_in_delta(path, "f")
        versions = {}
        patched_binaries = []

        # First pass: collect versions and their corresponding files
        for file in files:
            if file.endswith(".exe"):
                v = PatchExtractorManager.parse_file_version_from_path(file)
                if v is not None:
                    versions[file] = v  # Store the version with the file name

        # Determine the latest version
        if versions:
            latest_ver = max(versions.values())

            # Second pass: collect files that match the latest version
            for file, v in versions.items():
                if v == latest_ver:
                    patched_binaries.append(file)

        return patched_binaries

    @staticmethod
    def find_base_binary2(filename: str, expected_version: Optional[str], search_path: str = get_winsxs_path()) -> Optional[str]:
        """
        Searches for a file by name in the specified search_path and returns the full path
        of the candidate whose version is less than or equal to the expected_version.
        If multiple candidates qualify, the one with the highest version (still ≤ expected_version)
        is returned.
        If no candidate is found, returns None.
        """
        candidates = []
        # Walk the search path for matches (case-insensitive)
        for root, dirs, files in os.walk(search_path):
            for file in files:
                if file.lower() == filename.lower():
                    full_path = os.path.join(root, file)
                    file_ver = PatchExtractorManager.parse_file_version_from_path(full_path)
                    if file_ver:
                        try:
                            # Only accept candidates with a version that is less than or equal to expected_version.
                            if version.parse(file_ver) <= version.parse(expected_version):
                                candidates.append((full_path, version.parse(file_ver)))
                        except Exception as e:
                            # If version parsing fails, skip this candidate.
                            continue

        if candidates:
            # Select the candidate with the highest version (but still within the acceptable range)
            best_candidate = max(candidates, key=lambda item: item[1])
            return best_candidate[0]
        return None

    @staticmethod
    def find_patched_binaries3(db_path: str, kb_date: str, delta_path: str) -> list:
        """
        Find updated files with versions newer than previous patch
        Supports any file type with version in path
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 1. Get previous max versions for all files
        cursor.execute("""
            SELECT binary_name, MAX(binary_version) 
            FROM binaries 
            WHERE KbDate < ?
            GROUP BY binary_name
        """, (kb_date,))
        previous_versions = {row[0]: row[1] for row in cursor.fetchall()}

        # 2. Process all delta files
        patched_files = []
        for file_path in PatchExtractorManager.find_any_files_in_delta(delta_path, "f"):
            # Extract base name and version from path
            file_name = os.path.basename(file_path)
            base_name = re.sub(r'_\d+\.\d+\.\d+\.\d+.*', '', file_name)
            current_version = PatchExtractorManager.parse_file_version_from_path(file_path)
            
            if not current_version:
                continue  # Skip files without valid version

            # 3. Version comparison logic
            prev_version = previous_versions.get(base_name)
            
            # New file or version check
            if not prev_version or PatchExtractorManager.is_newer_version(current_version, prev_version):
                patched_files.append({
                    'path': file_path,
                    'name': base_name,
                    'version': current_version
                })

        conn.close()
        return patched_files

    @staticmethod
    def is_newer_version(current: str, previous: str) -> bool:
        """Compare versions using existing parsing and component-wise comparison"""
        try:
            c_parts = list(map(int, current.split('.')))
            p_parts = list(map(int, previous.split('.')))
            
            # Pad versions to compare all components
            max_len = max(len(c_parts), len(p_parts))  # Fixed line
            c_parts += [0] * (max_len - len(c_parts))
            p_parts += [0] * (max_len - len(p_parts))
            
            return c_parts > p_parts
        except ValueError:
            return False

    @staticmethod
    def version_to_tuple(ver_str):
        """
        Convert '10.0.22621.5038' -> (10,0,22621,5038).
        If major > 10, normalize it back to 10 so Windows‑11 file versions
        compare correctly against Windows‑10 thresholds.
        """
        parts = [int(x) for x in ver_str.split('.')]
        # Pad to 4 elements if needed
        while len(parts) < 4:
            parts.append(0)
        major, minor, build, rev = parts[:4]
        if major > 10:
            major = 10
        return (major, minor, build, rev)


    @staticmethod
    def load_previous_max_versions(db_path, kb_date):
        """
        Returns dict: { binary_name: max_version_tuple } for all binaries
        whose KbDate < kb_date.
        """
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        cur.execute("SELECT binary_name, binary_version FROM binaries WHERE KbDate < ?", (kb_date,))
        prev = {}
        for name, ver in cur.fetchall():
            try:
                vt = PatchExtractorManager.version_to_tuple(ver)
            except Exception:
                continue
            if name not in prev or vt > prev[name]:
                prev[name] = vt
        conn.close()
        return prev


    @staticmethod
    def extract_base_name(filename):
        """
        Given 'tcpip_10.0.22621.5038.sys' -> 'tcpip'
        """
        return filename.split('_', 1)[0].lower()


    @staticmethod
    def find_new_patched_files(
        delta_root: str,
        threshold: Tuple[int, ...],
        allowed_extensions: Optional[List[str]] = None
    ) -> List[Dict[str, object]]:
        """
        Walk the 'f' delta folder and return only those files whose
        extension is in allowed_extensions and whose version tuple
        is strictly greater than threshold.
        """
        if allowed_extensions is None:
            allowed_extensions = get_extensions()

        results = []
        for path in PatchExtractorManager.find_any_files_in_delta(delta_root, "f"):
            ext = os.path.splitext(path)[1].lower()
            if ext not in allowed_extensions:
                continue

            fname = os.path.basename(path)
            base  = PatchExtractorManager.extract_base_name(fname)
            ver   = PatchExtractorManager.parse_file_version_from_path(path)
            if not ver:
                continue

            try:
                vtuple = PatchExtractorManager.version_to_tuple(ver)
            except ValueError:
                continue

            if vtuple > threshold:
                results.append({
                    'path':          os.path.relpath(path, ELDIFF_APP),
                    'name':          base.lower(),
                    'version':       ver,
                    'version_tuple': vtuple
                })

        return results

    @staticmethod
    def get_dynamic_baseline(kb_date: str, db_path) -> Dict[str, Tuple[int, ...]]:
        """
        Retrieve maximum versions for each binary from updates before target date
        Returns: {binary_name: max_version_tuple}
        """
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT binary_name, MAX(binary_version)
                FROM binaries
                WHERE KbDate < ?
                GROUP BY binary_name
            """, (kb_date,))
            
            baseline = {}
            for binary_name, version_str in cursor.fetchall():
                if version_str:  # Handle possible NULL values
                    baseline[binary_name] = PatchExtractorManager.version_to_tuple(version_str)
            
            conn.close()
            return baseline
        
        except sqlite3.Error as e:
            logger.error(f"Database error in get_dynamic_baseline: {str(e)}")
            return {}

    @staticmethod
    def fetch_tags(db_path: str, kb_date: str) -> List[str]:
        """
        Query the Vulnerabilities table for all distinct component tags associated with a given KB date.

        :param db_path: Path to the SQLite database file
        :param kb_date: KB date string (e.g. '2025-03-11')
        :return: List of unique component tag strings
        """
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT Tag FROM Vulnerabilities WHERE KbDate = ?",
            (kb_date,)
        )
        rows = cur.fetchall()
        conn.close()
        # Normalize tags
        return [row[0] for row in rows if row[0]]

    @staticmethod
    def fetch_component_mapping(db_path: str) -> Dict[str, str]:
        """
        Fetch the component->binary_name mapping from the database.

        :param db_path: Path to the SQLite database file
        :return: Dict mapping lowercase component -> lowercase binary_name
        """
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT component, binary_name FROM component_mapping"
        )
        rows = cur.fetchall()
        conn.close()
        return {component.lower(): binary_name.lower() for component, binary_name in rows}


    @staticmethod
    def get_candidate_binaries(
        tags: List[str],
        mapping: Dict[str, str],
        popular: Optional[List[str]] = None
    ) -> set:
        """
        Build the set of binary names to process:
        - All binaries mapped from today's CVE tags
        - Plus any from POPULAR_BINARIES
        """
        candidates = {
            mapping[tag.lower()]
            for tag in tags
            if tag.lower() in mapping
        }
        if popular:
            candidates |= {name.lower() for name in popular}
        return candidates

    @staticmethod
    def filter_patched_binaries(
        patched_binaries: List[Dict[str, str]],
        candidate_names: Set[str]
    ) -> List[Dict[str, str]]:
        """
        Filter the list of patched binaries to only those in candidate_names.
        """
        return [fb for fb in patched_binaries if fb['name'].lower() in candidate_names]

    @staticmethod
    def fetch_global_threshold(db_path: str, kb_date: str) -> Tuple[int, ...]:
        """
        Returns the max version tuple across all binaries
        in earlier KBs than kb_date.
        """
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT MAX(binary_version) FROM binaries WHERE KbDate < ?",
            (kb_date,)
        )
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            return PatchExtractorManager.version_to_tuple(row[0])
        return (0,) 

def fetch_all_kb_dates(db_path):
    """Retrieve all distinct KbDates from the updates table"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT KbDate FROM updates ORDER BY KbDate DESC")
    dates = [row[0] for row in cursor.fetchall()]
    conn.close()
    return dates

def process_kb_date(kb_date, comp_map, POPULAR_BINARIES):
    """Process a single KbDate and return statistics"""
    x64_path = os.path.join(UPDATES_DIR, kb_date, X64_DIR)
    
    if not os.path.exists(x64_path):
        return None

    try:
        tags = PatchExtractorManager.fetch_tags(DATABASE_FILE, kb_date)
        threshold = PatchExtractorManager.fetch_global_threshold(DATABASE_FILE, kb_date)
        
        scanned = PatchExtractorManager.find_new_patched_files(x64_path, threshold)
        if not scanned:
            return None

        extensions = [os.path.splitext(f['path'])[1].lower() for f in scanned]
        counts = Counter(extensions)
        
        candidates = PatchExtractorManager.get_candidate_binaries(
            tags, comp_map, POPULAR_BINARIES 
        )
        candidate_count = len([f for f in scanned if f['name'] in candidates])

        return {
            'date': kb_date,
            'total_files': len(scanned),
            'sys': counts.get('.sys', 0),
            'exe': counts.get('.exe', 0),
            'dll': counts.get('.dll', 0),
            'efi': counts.get('.efi', 0),
            'candidates': candidate_count
        }
    except Exception as e:
        print(f"Error processing {kb_date}: {str(e)}")
        return None

# def main():
#     # Fetch component mapping once (shared across all dates)
#     comp_map = PatchExtractorManager.fetch_component_mapping(DATABASE_FILE)
    
#     # Retrieve and process all KbDates
#     all_dates = fetch_all_kb_dates(DATABASE_FILE)
#     results = []
    
#     print(f"Processing {len(all_dates)} KB dates...")
#     for kb_date in all_dates:
#         stats = process_kb_date(kb_date, comp_map, POPULAR_BINARIES)
#         if stats:
#             results.append(stats)
    
#     # Generate summary report
#     print("\nStatistical Summary:")
#     print("Date\t\tTotal\tSys\tExe\tDll\tEfi\tCandidates")
#     print("-" * 60)
#     for res in results:
#         print(f"{res['date']}\t{res['total_files']}\t{res['sys']}\t"
#               f"{res['exe']}\t{res['dll']}\t{res['efi']}\t{res['candidates']}")
    
#     # Additional aggregates
#     total_files = sum(r['total_files'] for r in results)
#     total_candidates = sum(r['candidates'] for r in results)
#     print(f"\nTOTALS: {len(results)} updates with {total_files} files "
#           f"({total_candidates} candidates)")

# if __name__ == "__main__":
#     main()