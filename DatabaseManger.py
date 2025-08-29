import sqlite3
import os
import logging
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        if os.path.exists(self.db_path):
            logger.info("Database already exists at %s, skipping initialization.", self.db_path)
            return
        else:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

    def initialize(self):
        """Initialize the database and all tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            logger.info(f"Initializing database: {self.db_path}")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Vulnerabilities (
                    CVE TEXT PRIMARY KEY,
                    CWE TEXT,
                    Tag TEXT,
                    FAQ TEXT,
                    URL TEXT,
                    FixedBuild TEXT,
                    Impact TEXT,
                    Severity TEXT,
                    Exploit_Status TEXT,
                    Update_ID TEXT,
                    KbDate TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS added_deleted_funcs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_name TEXT NOT NULL,
                    binary_version TEXT NOT NULL,
                    name TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    func_blob BLOB,
                    function_type INTEGER NOT NULL,
                    UNIQUE(binary_name, binary_version, name, address, function_type)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS binaries (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_name TEXT NOT NULL,
                    forward_delta_path TEXT,
                    base_path TEXT NOT NULL,
                    KB TEXT NOT NULL,
                    UpdateID TEXT,
                    binary_path TEXT NOT NULL,
                    binary_version TEXT NOT NULL,
                    ida_path TEXT,
                    binexport_path TEXT,
                    bindiff_path TEXT,
                    binary_hash INTEGER,
                    KbDate TEXT,
                    status INTEGER DEFAULT 0,
                    UNIQUE(binary_name, KbDate)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS component_mapping (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT NOT NULL,
                    binary_name TEXT NOT NULL
                )
            """)

            cursor.execute("SELECT COUNT(*) FROM component_mapping")
            if cursor.fetchone()[0] == 0:
                mappings = [
                    (1, "Windows Common Log File System Driver", "clfs.sys"),
                    (2, "Windows Composite Image File System", "cimfs.sys"),
                    (3, "Windows DWM Core Library", "dwmcore.dll"),
                    (4, "Windows Telephony Service", "tapisrv.dll"),
                    (5, "Windows Kernel", "ntoskrnl.exe"),
                    (6, "Windows USB Print Driver", "usbprint.sys"),
                    (7, "Windows upnphost.dll", "upnphost.dll"),
                    (8, "Windows HTTP.sys", "http.sys"),
                    (9, "Microsoft Streaming Service", "mskssrv.sys"),
                    (10, "Windows Resilient File System (ReFS)", "refs.sys"),
                    (11, "Windows Composite Image File System", "cimfs.sys"),
                    (12, "Windows Win32 Kernel Subsystem", "win32kfull.sys"),
                    (13, "Windows TCP/IP", "tcpip.sys"),
                    (14, "Kernel Streaming WOW Thunk Service Driver", "ksthunk.sys"),
                    (15, "Windows exFAT File System", "exfat.sys"),
                    (16, "Windows Fast FAT Driver", "fastfat.sys"),
                    (17, "Windows USB Video Driver", "usbvideo.sys"),
                    (18, "Microsoft Management Console", "mmc.exe"),
                    (19, "Microsoft Local Security Authority Server (lsasrv)", "lsasrv.dll"),
                    (20, "Windows Message Queuing", "mqsvc.exe"),
                    (21, "Windows Kerberos", "kerberos.dll"),
                    (22, "Windows Ancillary Function Driver for WinSock", "afd.sys"),
                    (23, "Winlogon", "winlogon.exe"),
                    (26, "Windows Hyper-V NT Kernel Integration VSP", "vkrnlintvsp.sys"),
                    (27, "Windows Hyper-V", "hvix64.exe"),
                    (28, "Windows Hyper-V", "hvax64.exe"),
                    (29, "Windows Hyper-V", "hvloader.dll"),
                    (30, "Windows Hyper-V", "kdhvcom.dll"),
                    (31, "Windows Power Dependency Coordinator", "pdc.sys"),
                    (32, "Windows Cryptographic Services", "cryptsvc.dll"),
                    (33, "Windows Remote Desktop Services", "termsrv.dll"),
                    (34, "Windows BitLocker", "fvevol.sys"),
                    (35, "Windows Core Messaging", "CoreMessaging.dll"),
                    (36, "Windows Boot Manager", "bootmgfw.efi"),
                    (37, "Windows Boot Loader", "winload.exe"),
                    (38, "Windows Task Scheduler", "WPTaskScheduler.dll"),
                    (39, "Windows Secure Channel", "schannel.dll"),
                    (40, "Windows Local Session Manager (LSM)", "lsm.dll"),
                    (41, "Windows LDAP - Lightweight Directory Access Protocol", "Wldap32.dll"),
                    (42, "Web Threat Defense (WTD.sys)", "wtd.sys"),
                    (43, "Windows Storage Port Driver", "storport.sys"),
                    (44, "Windows Storage VSP Driver", "storvsp.sys"),
                    (45, "Windows NT OS Kernel", "ntoskrnl.exe"),
                    (46, "Kernel Transaction Manager", "ntoskrnl.exe"),
                ]
                cursor.executemany(
                    "INSERT INTO component_mapping (id, component, binary_name) VALUES (?, ?, ?)",
                    mappings
                )
                logger.info("Component mapping table initialized with default values.")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS functions (
                    ID INTEGER PRIMARY KEY,
                    binary_name TEXT NOT NULL,
                    binary_version TEXT,
                    name1 TEXT,
                    name2 TEXT,
                    address1 TEXT,
                    address2 TEXT,
                    old_code BLOB,
                    new_code BLOB,
                    diff BLOB,
                    similarity REAL,
                    UNIQUE(binary_name, binary_version, address1, address2)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS updates (
                    ID TEXT,
                    InitialReleaseDate TEXT,
                    CurrentReleaseDate TEXT,
                    CvrfUrl TEXT,
                    KbDate TEXT PRIMARY KEY
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )
            """)

            cursor.execute("SELECT id FROM users WHERE username = ?", ("eldiff",))
            if not cursor.fetchone():
                default_password = "damagelib"
                password_hash = generate_password_hash(default_password)
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    ("eldiff", password_hash)
                )
                logger.info("Default user created (username=eldiff, password=damagelib).")

            conn.commit()
            logger.info("Database initialized successfully.")
