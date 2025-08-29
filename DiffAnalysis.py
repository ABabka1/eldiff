from DiffManager import *
import difflib
from config import DATABASE_FILE

class DiffAnalysis():
    @staticmethod
    def create_new_del_funcs(db_path: str) -> bool:
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS added_deleted_funcs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          binary_name    TEXT    NOT NULL,
          binary_version TEXT    NOT NULL,
          name           TEXT    NOT NULL,
          func_blob      BLOB    NOT NULL,
          function_type  INTEGER NOT NULL,
            -- 1 = added, 2 = deleted
          UNIQUE(binary_name, binary_version, name, function_type)
        );
        """

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(create_table_sql)
            conn.commit()
            conn.close()

            return True
        except sqlite3.Error as e:
            print(f"[!] SQLite error while creating added_deleted_funcs: {e}")

            return False


    @staticmethod
    def create_func_table(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS functions(
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
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
            );
        ''')
        conn.commit()
        conn.close()
        print("Binaries table initialized successfully.")
        return True

    @staticmethod
    def table_exists(db_path, table_name):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?;
            """, (table_name,))
            
            result = cursor.fetchone()
            conn.close()

            return result is not None 


    @staticmethod
    def gen_uni_diff(old_code, new_code):
        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            old_lines, new_lines, 
            fromfile="old_code", tofile="new_code",
            lineterm=""
        )
        
        return ''.join(diff)

    @staticmethod
    def pre_init_func_table(binary_name, binary_version, name1, name2, address1, address2, similarity):
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                        INSERT OR IGNORE INTO functions (
                        binary_name, binary_version, name1, name2, address1, address2, similarity
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (binary_name, binary_version, name1, name2, address1, address2, similarity),)

            conn.commit()

    @staticmethod
    def add_func_blobs(binary_name: str, binary_version: str, name1: str, code_gz: bytes, column):
        """
        Add compressed code blobs to pre-initialized function entries
        
        :param code_gz: Gzip-compressed code bytes
        :param is_previous_db: True if updating old_code column
        """
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE functions 
                SET {column} = ?
                WHERE binary_name = ? 
                AND binary_version = ?
                AND name1 = ?
            """, (code_gz, binary_name, binary_version, name1))

        conn.commit()

