import os
import re
import time
import sqlite3
import logging
import requests
import xmltodict

from bs4 import BeautifulSoup
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fake_useragent import UserAgent
from typing import Optional
from config import DATABASE_FILE, get_tor_port, get_tor_ip, use_tor, get_product_id

logger = logging.getLogger(__name__)

class MicrosoftUpdateFetcher:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()

        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        self.session.mount("http://", HTTPAdapter(max_retries=retries))

        # random UA
        ua = UserAgent(os="Windows", browsers=['Edge', 'Chrome', 'Firefox'], platforms='desktop')
        self.session.headers.update({"User-Agent": ua.random})

        if use_tor():
            tor_proxy = f"socks5h://{get_tor_ip()}:{get_tor_port()}"
            self.session.proxies.update({"http": tor_proxy, "https": tor_proxy})

    def fetch_cvrf_xml(self, cvrf_url: str) -> Optional[dict]:
        try:
            resp = self.session.get(cvrf_url, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"CVRF download failed {cvrf_url} : {e}", exc_info=True)
            return None
        try:
            return xmltodict.parse(resp.content)
        except Exception as e:
            logger.error(f"CVRF parse failed {cvrf_url} : {e}", exc_info=True)
            return None

    def get_all_cvrf_updates(self) -> Optional[dict]:
        url = 'https://api.msrc.microsoft.com/cvrf/v3.0/Updates'
        headers = { 'Accept' : 'application/json' }
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("Failed to fetch all CVRF updates: %s", e, exc_info=True)
            return None

    def fetch_and_save_updates_from_db(self, database_path, base_directory):
        updates_list = self.fetch_updates_from_db(database_path)

        if not os.path.exists(base_directory):
            os.makedirs(base_directory)

        for update in updates_list:
            update_id, release_date, cvrf_url = update

            try:
                new_release_date = datetime.strptime(
                    release_date, '%Y-%m-%dT%H:%M:%SZ'
                ).strftime('%Y-%m-%d')
            except ValueError:
                logger.warning("Invalid date format for %s. Skipping...", release_date)
                continue

            file_directory = os.path.join(base_directory, update_id)
            file_name = f"{new_release_date}.xml"
            file_path = os.path.join(file_directory, file_name)

            if os.path.exists(file_path):
                logger.info("File already exists: %s. Skipping...", file_path)
                continue

            os.makedirs(file_directory, exist_ok=True)

            try:
                resp = self.session.get(cvrf_url, timeout=self.timeout)
                resp.raise_for_status()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(resp.text)
                logger.info("Saved: %s", file_path)
            except Exception as e:
                logger.error("Error fetching %s: %s", cvrf_url, str(e), exc_info=True)

    def load_updates_info_by_kbdate(self, db_path, kb_date, data):
        if data is not None:
            return data

        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT CvrfUrl FROM updates WHERE KbDate = ?", (kb_date,))
            row = cur.fetchone()

        if not row:
            return None

        cvrf_url = row[0]
        resp = self.session.get(cvrf_url, timeout=self.timeout)
        resp.raise_for_status()
        return xmltodict.parse(resp.content)

    def get_update_id_by_kb(self, kb, product_id, data) -> Optional[str]:
        url = f"https://catalog.update.microsoft.com/v7/site/Search.aspx?q={kb}" 
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()

        prod_name = self.get_prod_name_by_id(product_id, data)
        soup = BeautifulSoup(resp.content, "html.parser")

        updates = [
            (l.get_text(strip=True), l["onclick"].split('"')[1])
            for l in soup.find_all("a", class_="contentTextItemSpacerNoBreakLink")
            if prod_name in l.get_text() and l.has_attr("onclick") and 'goToDetails' in l["onclick"]
        ]
        return updates[0][1] if updates else None

    def get_kb_link(self, update_id):
        url = "https://catalog.update.microsoft.com/DownloadDialog.aspx"
        payload = f"updateIDs=[{{\"updateID\":\"{update_id}\"}}]"
        url_pattern = r"downloadInformation\s*\[0\]\.files\s*\[0\]\.url\s*=\s*'(https:\/\/[^\']+)'"

        headers = {
            "Host": "catalog.update.microsoft.com",
            "User-Agent": self.session.headers.get("User-Agent"),
            "Content-Type": "application/x-www-form-urlencoded"
        }

        resp = self.session.post(url, data=payload, headers=headers, timeout=self.timeout)
        if resp.status_code != 200:
            logger.error("KB link fetch failed: %s (HTTP %s)", update_id, resp.status_code)
            return ""

        match = re.search(url_pattern, resp.text)
        return match.group(1) if match else ""

    def download_msu_file(self, download_url: str, save_directory: str) -> Optional[str]:
        filename = os.path.basename(download_url)
        save_path = os.path.join(save_directory, filename)

        if os.path.exists(save_path):
            logger.info("File already exists: %s. Skipping download.", save_path)
            return save_path 

        os.makedirs(save_directory, exist_ok=True)
        start_time = time.time()

        try:
            resp = self.session.get(download_url, stream=True, timeout=30, verify=True)
            resp.raise_for_status()

            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0

            with open(save_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1024*1024):
                    if not chunk:
                        continue
                    f.write(chunk)
                    downloaded += len(chunk)
                    logger.info("Downloaded %d / %d bytes", downloaded, total)

            elapsed = time.time() - start_time
            if total and downloaded != total:
                logger.error("Download incomplete: got %d of %d bytes", downloaded, total)
                return None

            logger.info("Download completed: %s (%.1f s)", save_path, elapsed)
            return save_path
        except Exception as e:
            logger.error("Download failed: %s", e, exc_info=True)
            return None

    def get_security_updates(self) -> list:
        url = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates"
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        pattern = r'^\d{4}-[A-Za-z]{3}$'
        return [
            u for u in resp.json().get('value', [])
            if 'security updates' in u.get('DocumentTitle', '').lower()
            and 'early' not in u.get('DocumentTitle', '').lower()
            and re.match(pattern, u.get('ID', ''))
        ]

    def save_updates_to_database(self, entries, db_path=DATABASE_FILE):
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS updates (
                ID TEXT PRIMARY KEY,
                InitialReleaseDate TEXT,
                CurrentReleaseDate TEXT,
                CvrfUrl TEXT,
                KbDate TEXT
            )''')
            for entry in entries:
                cur.execute('''INSERT OR REPLACE INTO updates 
                               (ID, InitialReleaseDate, CurrentReleaseDate, CvrfUrl) 
                               VALUES (?, ?, ?, ?)''',
                            (entry["ID"], entry["InitialReleaseDate"], 
                             entry["CurrentReleaseDate"], entry["CvrfUrl"]))
            # conn.commit()

    def fetch_updates_from_db(self, database_path):
        with sqlite3.connect(database_path) as conn:
            rows = conn.execute("SELECT ID, InitialReleaseDate, CvrfUrl FROM updates ORDER BY InitialReleaseDate ASC").fetchall()
            return rows 

    @staticmethod
    def get_existing_updates(conn: sqlite3.Connection) -> dict:
        """
        Retrieve all existing updates from the DB.

        :param conn: sqlite3 connection object
        :return: dict of {UpdateID: (InitialReleaseDate, CurrentReleaseDate)}
        """
        cursor = conn.cursor()
        cursor.execute("SELECT ID, InitialReleaseDate, CurrentReleaseDate FROM updates")
        updates = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
        return updates

    @staticmethod
    def kb_date_exists(db_path: str, kb_date: str) -> bool:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT KbDate FROM updates WHERE KbDate = ? LIMIT 1", (kb_date,))
            return cur.fetchone() is not None

    def insert_vuln_for_all_upd_new(self, kb_date, product_id, db_path, data):
        try:
            up = MicrosoftUpdateFetcher.load_updates_info_by_kbdate(self, db_path, kb_date, data)
            if not up:
                logger.warning(f"No updates found for {kb_date}")
                return
            cves = MicrosoftUpdateFetcher.get_cve_by_product_id(product_id, up)
            if not cves:
                logger.warning(f"No CVEs found for {product_id} on {kb_date}")
                return
        
            with sqlite3.connect(db_path) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                cur = conn.cursor()

                with conn:
                    for cve in cves:
                        v = MicrosoftUpdateFetcher.get_vuln_info(cve, up)
                        n = MicrosoftUpdateFetcher.get_notes_from_vuln_info(v)
                        f = MicrosoftUpdateFetcher.get_fixes(cve, product_id, up)
                        th = MicrosoftUpdateFetcher.get_threat_info(cve, product_id, up)

                        cur.execute('''INSERT OR REPLACE INTO Vulnerabilities (
                            CVE, CWE, Tag, FAQ, URL, FixedBuild, 
                            Impact, Severity, Exploit_Status, KbDate
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                        (
                            cve, 
                            n.get("CWE", "N/A"),
                            n.get("Tag", "N/A"), 
                            n.get("FAQ", "N/A"),
                            f.get("vuln:URL", "No URL"),
                            f.get("vuln:FixedBuild", "No FixedBuild"),
                            th.get("Impact", "N/A"),
                            th.get("Severity", "N/A"),
                            th.get("Exploit Status", "N/A"),
                            kb_date  # Using KbDate instead of Update_ID
                        ))

        except sqlite3.Error as e:
            logger.error("Database error for %s: %s", kb_date, str(e), exc_info=True)
            raise
        except KeyError as e:
            logger.error("Missing expected key in data: %s", str(e), exc_info=True)
            raise

    @staticmethod
    def get_notes_from_vuln_info(vuln_info):
        result = {
            "CVE": vuln_info.get('vuln:CVE', 'N/A'),
            "CWE": [],
            "Tag": [],
            "FAQ": []
        }

        cwe_info = vuln_info.get('vuln:CWE', [])
        if isinstance(cwe_info, dict):
            cwe_info = [cwe_info]

        for cwe in cwe_info:
            cwe_id = cwe.get('@ID', 'N/A')
            cwe_text = cwe.get('#text', 'N/A')
            result["CWE"].append(f"{cwe_id} - {cwe_text}")

        notes = vuln_info.get('vuln:Notes', {}).get('vuln:Note', [])
        for note in notes:
            if '#text' in note and note.get('@Type') == 'Tag':
                result["Tag"].append(note['#text'])
            elif '#text' in note and note.get('@Type') == 'FAQ':
                result["FAQ"].append(note['#text'])

        for key, value in result.items():
            if isinstance(value, list):
                result[key] = ' '.join(value)        

        return result
    
    @staticmethod
    def get_threat_info(cve, product_id, data):
        vuln_info = MicrosoftUpdateFetcher.get_vuln_info(cve, data)
        threats_data = vuln_info["vuln:Threats"]["vuln:Threat"] # type: ignore

        # Filter the threats based on ProductID and @Type
        desc = {}
        types_to_include = ["Impact", "Severity"]
        
        for threat in threats_data:
            product_match = threat.get("vuln:ProductID") == product_id
            type_match = threat["@Type"] in types_to_include

            if product_match and type_match:
                desc[threat["@Type"]] = threat["vuln:Description"]
            
            # Add Exploit Status description if present
            if threat["@Type"] == "Exploit Status":
                desc["Exploit Status"] = threat["vuln:Description"]

        return desc

    @staticmethod
    def extract_update_id(initial_release_date):
        return datetime.strptime(initial_release_date, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d")

    @staticmethod
    def extract_kb_from_url(url: str) -> Optional[str]:
        if '/kb/' in url.lower():
            parts = url.split('/')
            try:
                kb_index = parts.index('kb') if 'kb' in parts else parts.index('KB')
                return f"KB{parts[kb_index + 1].split('?')[0].split('&')[0]}"
            except (ValueError, IndexError):
                pass
        if 'q=' in url.lower():
            match = re.search(r'(KB\d+)', url, re.IGNORECASE)
            if match:
                return match.group(0).upper()
        match = re.search(r'(KB\d+)', url, re.IGNORECASE)
        return match.group(0).upper() if match else None

    @staticmethod
    def get_kb_from_update_id(update_id, db_path):
        try:
            with sqlite3.connect(db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT URL FROM Vulnerabilities WHERE Update_ID = ?", (update_id,))
                record = cur.fetchone()
            if record and record[0]:
                match = re.search(r'\?q=([^&]+)', record[0])
                return match.group(1) if match else None
            return None
        except Exception as e:
            logger.error("DB error in get_kb_from_update_id: %s", e, exc_info=True)
            return None

    @staticmethod
    def get_kb_date_from_page(url, update_id, prod_name):
        try:
            resp = requests.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for l in soup.find_all("a", class_="contentTextItemSpacerNoBreakLink"):
                if prod_name in l.get_text():
                    row = soup.find('tr', id=lambda x: x and x.startswith(update_id))
                    if not row:
                        continue
                    tds = row.find_all('td')
                    return tds[4].get_text(strip=True)
            return None
        except Exception as e:
            logger.error("Error extracting KB date from page %s: %s", url, e, exc_info=True)
            return None

    @staticmethod
    def get_id_from_updates(data):
        updates = data['value']
        pattern = r'^\d{4}-[A-Za-z]{3}$'
        return [u['ID'] for u in updates if re.match(pattern, u['ID'])]

    @staticmethod
    def get_all_from_updates(data):
        updates = data['value']
        pattern = r'^\d{4}-[A-Za-z]{3}$'
        valid = [
            {
                "ID": u["ID"],
                "CvrfUrl": u["CvrfUrl"],
                "InitialReleaseDate": u["InitialReleaseDate"],
                "CurrentReleaseDate": u["CurrentReleaseDate"]
            }
            for u in updates if re.match(pattern, u["ID"])
        ]
        return sorted(valid, key=lambda x: datetime.strptime(x["InitialReleaseDate"], '%Y-%m-%dT%H:%M:%SZ'))

    @staticmethod
    def get_cve_by_product_id(product_id, data):
        cves = []
        if not MicrosoftUpdateFetcher.is_product_id_exist(product_id, data):
            logger.warning("Skipping file: ProductID %s not found", product_id)
            return cves
        try:
            for vuln in data['cvrf:cvrfdoc']['vuln:Vulnerability']:
                if product_id in vuln['vuln:ProductStatuses']['vuln:Status']['vuln:ProductID']:
                    cves.append(vuln['vuln:CVE'])

        except KeyError as e:
            logger.warning("KeyError while processing CVE data: %s", str(e), exc_info=True)

        logger.info("Found %d CVEs for ProductID %s", len(cves), product_id)
        return cves 

    @staticmethod
    def is_product_id_exist(product_id, data):
        try:
            # Access the product tree in the data
            product_tree = data['cvrf:cvrfdoc']['prod:ProductTree']
            
            # Check if 'prod:FullProductName' exists in the product tree
            prod_name = product_tree.get('prod:FullProductName', [])
            
            # Return True if any product has the given @ProductID
            return any(item['@ProductID'] == product_id for item in prod_name)
        
        except KeyError as e:
            # If any KeyError occurs (like missing 'prod:ProductTree'), return False
            print(f"KeyError: {e}")
            return False    

    @staticmethod
    def get_fixes(cve: str, product_id: str, data: dict) -> dict:
        # Retrieve vulnerability information for the given CVE
        vuln_info = MicrosoftUpdateFetcher.get_vuln_info(cve, data)
        
        # Safely get 'vuln:Remediations' using .get()
        rem = vuln_info.get('vuln:Remediations', None) # type: ignore

        if rem:
            # Get 'vuln:Remediation' only if it exists
            rem = rem.get('vuln:Remediation', None)

            if rem:
                for fix in rem:
                    # Check if the fix matches the "Vendor Fix" type and contains the product_id
                    if fix.get("@Type") == "Vendor Fix" and product_id in fix.get("vuln:ProductID", []):
                        # Extract URL and FixedBuild if available
                        url = fix.get("vuln:URL", "")
                        fixed_build = fix.get("vuln:FixedBuild", "")
                        
                        return {
                            "vuln:URL": url,
                            "vuln:FixedBuild": fixed_build
                        }
            else:
                logger.warning("No vuln:Remediation node found for CVE %s (Product %s)", cve, product_id, exc_info=True)
        else:
            logger.warning("No vuln:Remediation node found for CVE %s (Product %s)", cve, product_id, exc_info=True)

    @staticmethod
    def get_vuln_info(cve, data):
        vulns = data['cvrf:cvrfdoc']['vuln:Vulnerability']
        for vuln in vulns:
            if (vuln['vuln:CVE'] == cve):
                return vuln
        return {}    

    @staticmethod
    def get_prod_name_by_id(product_id, data) -> Optional[str]:
        prod_name = data['cvrf:cvrfdoc']['prod:ProductTree']['prod:FullProductName']
        for name in prod_name:
            if name.get("@ProductID") == product_id:
                return name.get("#text")
                
        return None

    @staticmethod
    def format_catalog_date(date_str: str) -> str:
        """
        Convert a date string from "m/d/Y" to "YYYY-MM-D" format.
        Example: "3/11/2025" -> "2025-03-11"
        """
        try:
            date_obj = datetime.strptime(date_str, "%m/%d/%Y")
            return date_obj.strftime("%Y-%m-%d")  # ISO format with leading zeros
        except ValueError:
            return date_str