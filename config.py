from pathlib import Path
import configparser

# This is a list of binaries that eldiff will always look in the patched binaries list
#TODO: expand it
POPULAR_BINARIES = ['acpi.sys', 'afd.sys', 'ahcache.sys', 'appid.sys',
                    'applockerfltr.sys', 'bindflt.sys', 'bthenum.sys',
                    'bthmini.sys', 'bthport.sys', 'bthusb.sys', 'classpnp.sys',
                    'cldflt.sys', 'clfs.sys', 'clipsp.sys', 'cng.sys',
                    'crashdmp.sys', 'dam.sys', 'dumpfve.sys', 'dxgkrnl.sys',
                    'dxgmms1.sys', 'dxgmms2.sys', 'exfat.sys', 'fastfat.sys',
                    'fltmgr.sys', 'fvevol.sys', 'fwpkclnt.sys', 'hdaudio.sys',
                    'http.sys', 'hvsifltr.sys','ks.sys', 'ksecdd.sys',
                    'ksecpkg.sys', 'ksthunk.sys', 'luafv.sys', 'mbbcx.sys',
                    'monitor.sys', 'mqac.sys', 'mrxsmb.sys', 'msgpioclx.sys',
                    'mskssrv.sys', 'msquic.sys', 'mssecflt.sys', 'ndis.sys',
                    'netio.sys', 'netvsc.sys', 'ntfs.sys', 'p9rdr.sys',
                    'pci.sys', 'prjflt.sys', 'processr.sys',
                    'rdpvideominiport.sys', 'refs.sys', 'refsv1.sys',
                    'rmcast.sys', 'srv.sys', 'srv2.sys', 'srvnet.sys',
                    'storport.sys', 'tbs.sys', 'tcpip.sys', 'tcpipreg.sys',
                    'tpm.sys', 'usbccgp.sys', 'usbhub3.sys', 'usbprint.sys',
                    'usbvideo.sys', 'usbxhci.sys', 'vhdmp.sys',
                    'vkrnlintvsp.sys', 'vmsproxy.sys', 'vmsproxyhnic.sys',
                    'vmswitch.sys', 'win32k.sys', 'win32kbase.sys',
                    'win32kfull.sys', 'winnat.sys', 'winsetupmon.sys',
                    'wmiacpi.sys', 'wtd.sys', 'xboxgip.sys',
                     'hvloader.dll', 'kdhvcom.dll', 'winload.exe',
                    'bootmgfw.efi', 'cryptsvc.dll', 'ole32.dll', 'ntoskrnl.exe']

# Map human-readable names to product IDs. 
# TODO: Maybe we need to clear not necessary stuff from here
PRODUCT_ID_MAP = {
    # Microsoft Office
    # "Microsoft 365 Apps for Enterprise for 32-bit Systems": "11762",
    # "Microsoft 365 Apps for Enterprise for 64-bit Systems": "11763",
    # "Microsoft Office LTSC 2021 for 64-bit editions": "11952",
    # "Microsoft Office LTSC 2021 for 32-bit editions": "11953",
    # "Microsoft Office LTSC 2024 for 32-bit editions": "12420",
    # "Microsoft Office LTSC 2024 for 64-bit editions": "12421",
    # "Microsoft Office 2019 for 32-bit editions": "11573",
    # "Microsoft Office 2019 for 64-bit editions": "11574",
    # "Microsoft Office LTSC for Mac 2021": "11951",
    # "Microsoft Office for Android": "12155",
    # "Microsoft Office LTSC for Mac 2024": "12440",
    # "Microsoft Office 2016 (32-bit edition)": "10753",
    # "Microsoft Office 2016 (64-bit edition)": "10754",
    # "Microsoft SharePoint Enterprise Server 2016": "10950",
    # "Microsoft SharePoint Server 2019": "11585",
    # "Microsoft SharePoint Server Subscription Edition": "11961",
    # "Office Online Server": "10836",
    # "Microsoft Excel 2016 (32-bit edition)": "10739",
    # "Microsoft Excel 2016 (64-bit edition)": "10740",
    # "Microsoft Word 2016 (32-bit edition)": "10746",
    # "Microsoft Word 2016 (64-bit edition)": "10747",
    # "Microsoft Outlook 2016 (32-bit edition)": "10765",
    # "Microsoft Outlook 2016 (64-bit edition)": "10766",
    # "Microsoft PowerPoint 2016 (32-bit edition)": "10741",
    # "Microsoft PowerPoint 2016 (64-bit edition)": "10742",
    # "Microsoft AutoUpdate for Mac": "10949",

    # Windows
    "Windows Server 2022": "11923",
    "Windows Server 2022 (Server Core installation)": "11924",
    "Windows 11 Version 22H2 for ARM64-based Systems": "12085",
    "Windows 11 Version 22H2 for x64-based Systems": "12086",
    "Windows Server 2025 (Server Core installation)": "12437",
    "Windows 11 Version 23H2 for ARM64-based Systems": "12242",
    "Windows 11 Version 23H2 for x64-based Systems": "12243",
    "Windows Server 2022, 23H2 Edition (Server Core installation)": "12244",
    "Windows 11 Version 24H2 for ARM64-based Systems": "12389",
    "Windows 11 Version 24H2 for x64-based Systems": "12390",
    "Windows Server 2025": "12436",
    "Windows Server 2019": "11571",
    "Windows Server 2019 (Server Core installation)": "11572",
    "Windows Server 2016": "10816",
    "Windows Server 2016 (Server Core installation)": "10855",
    "Windows 10 Version 1809 for 32-bit Systems": "11568",
    "Windows 10 Version 1809 for x64-based Systems": "11569",
    "Windows 10 Version 21H2 for 32-bit Systems": "11929",
    "Windows 10 Version 21H2 for ARM64-based Systems": "11930",
    "Windows 10 Version 21H2 for x64-based Systems": "11931",
    "Windows 10 Version 22H2 for x64-based Systems": "12097",
    "Windows 10 Version 22H2 for ARM64-based Systems": "12098",
    "Windows 10 Version 22H2 for 32-bit Systems": "12099",
    "Windows 10 for 32-bit Systems": "10729",
    "Windows 10 for x64-based Systems": "10735",
    "Windows 10 Version 1607 for 32-bit Systems": "10852",
    "Windows 10 Version 1607 for x64-based Systems": "10853",
    "Windows App Client for Windows Desktop": "12457",
    "Remote Desktop client for Windows Desktop": "11849",
    "Windows Security App": "16766",

    # Developer Tools
    # ".NET 8.0 installed on Windows": "12414",
    # ".NET 8.0 installed on Linux": "12415",
    # ".NET 8.0 installed on Mac OS": "12416",
    # ".NET 9.0 installed on Linux": "12432",
    # ".NET 9.0 installed on Mac OS": "12433",
    # ".NET 9.0 installed on Windows": "12434",
    # "Microsoft Visual Studio 2022 version 17.12": "12459",
    # "Microsoft Visual Studio 2022 version 17.8": "12271",
    # "Microsoft Visual Studio 2022 version 17.10": "12322",
    # "Microsoft Visual Studio 2022 version 17.14": "16767",
    # "Windows SDK": "16764",

    # ESU
    # "Windows Server 2008 for 32-bit Systems Service Pack 2": "9312",
    # "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)": "10287",
    # "Windows Server 2008 for x64-based Systems Service Pack 2": "9318",
    # "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)": "9344",
    # "Windows Server 2008 R2 for x64-based Systems Service Pack 1": "10051",
    # "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)": "10049",
    # "Windows Server 2012": "10378",
    # "Windows Server 2012 (Server Core installation)": "10379",
    # "Windows Server 2012 R2": "10483",
    # "Windows Server 2012 R2 (Server Core installation)": "10543",

    # Browser
    "Microsoft Edge (Chromium-based)": "11655",

    # Microsoft Dynamics
    # "Power Automate for Desktop": "12410",

    # Mariner
    # "Azure Linux 3.0 ARM": "12357",
    # "CBL Mariner 2.0 x64": "12139",
    # "CBL Mariner 2.0 ARM": "12140",
    # "Azure Linux 3.0 x64": "12356",
}

# PRODUCT_ID_MAP = {
#     "Windows 11 Version 23H2 for x64-based Systems": "12243",
#     "Windows 10 Version 22H2 for x64-based Systems": "12097"
# }

ELDIFF_APP = Path(__file__).resolve().parent
CONFIG_FILE = ELDIFF_APP / "config.ini"
DATABASE_FILE = ELDIFF_APP / "data/updates.db"
UPDATES_DIR = ELDIFF_APP / "updates"
X64_DIR = "x64"
# Number of unified diff context lines around the changed one.

_config = configparser.ConfigParser()
_config.read(CONFIG_FILE)

def get_setting(section: str, key: str, fallback=None):
    return _config.get(section, key, fallback=fallback)

def get_extensions() -> list[str]:
    exts = _config.get("Analysis", "Extensions", fallback=".sys,.dll,.exe,.efi").split(",")
    return [e.strip().lower() for e in exts if e.strip()]

def get_system32_path() -> str:
    return get_setting("General", "system32path", fallback=r"C:\Windows\System32")

def get_winsxs_path() -> str:
    return get_setting("General", "winsxspath", fallback=r"C:\Windows\WinSxS") 

def get_python_path() -> str:
    return get_setting("General", "pythonpath", fallback=r"C:\Python312\python.exe")

def get_product_id() -> str:
    return get_setting("General", "productid", fallback=None)

def get_bindiff_path() -> str:
    return get_setting("Tools", "bindiffpath", fallback=r"C:\Program Files\BinDiff\bin\bindiff.exe")

def get_ida_path() -> str:
    return get_setting("Tools", "idapath", fallback=r"C:\Program Files\IDA Pro 8.3\idat64.exe")

def get_patch_extract_path() -> Path:
    return ELDIFF_APP / get_setting("Scripts", "patchextract", fallback="scripts/PatchExtract.ps1")

def get_delta_patch_path() -> Path:
    return ELDIFF_APP / get_setting("Scripts", "deltapatch", fallback="delta_patch.py")

def get_phase123_path() -> Path:
    return ELDIFF_APP / get_setting("Scripts", "phase123", fallback="decompile_func.py")

def get_phase4_path() -> Path:
    return ELDIFF_APP / get_setting("Paths", "phase4", fallback="decompile_added_deleted.py")

def get_num_ctx_line() -> int:
    return _config.getint("Diff", "numctxline", fallback=30)
    # return int(get_setting("Diff", "numctxline", fallback=30))

def use_tor() -> bool:
    return _config.getboolean("Network", "usetor", fallback=True)

def get_tor_ip() -> str:
    return get_setting("Network", "torip", fallback="127.0.0.1")

def get_tor_port() -> int:
    return _config.getint("Network", "torport", fallback=9050)

def reload_config():
    _config.read(CONFIG_FILE)
