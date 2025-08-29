import sys
import os
import threading
import configparser
import logging

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QComboBox, QCheckBox,
    QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout, QMessageBox,
    QTabWidget, QPlainTextEdit, QSpinBox, QGroupBox, QFormLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QIcon

# Import the pipeline from eldiff.py
from eldiff import scheduler, logger as eldiff_logger, process_updates, app as flask_app
from config import PRODUCT_ID_MAP

CONFIG_FILE = "config.ini"

# --- Custom Logging Handler for Qt ---
class QtLogHandler(logging.Handler, QObject):
    log_signal = pyqtSignal(str)

    def __init__(self):
        logging.Handler.__init__(self)
        QObject.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)


class SettingsGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("El Diff – Windows Patch Analysis Tool")
        self.setGeometry(200, 200, 560, 300)

        self.config = configparser.ConfigParser()

        # # -- Icon -- 
        # self.setWindowIcon(QIcon(r"D:\eldiff\img\dama.png"))

        # --- Tabs ---
        self.tabs = QTabWidget()
        self.settings_tab = QWidget()
        self.advanced_tab = QWidget() 
        self.logs_tab = QWidget()

        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.advanced_tab, "Advanced")
        self.tabs.addTab(self.logs_tab, "Logs")

        # --- Settings UI ---
        self.init_settings_ui()

        # --- Advanced UI ---
        self.init_advanced_ui()

        # --- Logs UI ---
        self.init_logs_ui()

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        # Load if file exists
        if os.path.exists(CONFIG_FILE):
            self.load_settings()

        # --- Attach live logger ---
        self.log_handler = QtLogHandler()
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.log_handler.log_signal.connect(self.append_log)
        eldiff_logger.addHandler(self.log_handler)
        eldiff_logger.setLevel(logging.INFO)

    def init_advanced_ui(self):
        main_layout = QVBoxLayout()
        diff_group = QGroupBox("Diff Settings")
        diff_layout = QFormLayout()
        

        self.ctx_input = QLineEdit()
        self.ctx_input.setFixedWidth(40) 
        self.ctx_input.setText("30") 
        diff_layout.addRow("Unified diff context lines:", self.ctx_input)

        diff_group.setLayout(diff_layout)
        main_layout.addWidget(diff_group)

        main_layout.addStretch()
        self.advanced_tab.setLayout(main_layout)

    def init_settings_ui(self):
        layout = QVBoxLayout()

        # ProductID
        self.product_label = QLabel("ProductID:")
        self.product_dropdown = QComboBox()
        self.product_dropdown.addItems(list(PRODUCT_ID_MAP.keys()))
        layout.addWidget(self.product_label)
        layout.addWidget(self.product_dropdown)

        # IDA Path
        self.ida_label = QLabel("IDA Path:")
        self.ida_path = QLineEdit()
        self.ida_browse = QPushButton("Browse")
        self.ida_browse.clicked.connect(self.browse_ida)
        hl1 = QHBoxLayout()
        hl1.addWidget(self.ida_path)
        hl1.addWidget(self.ida_browse)
        layout.addWidget(self.ida_label)
        layout.addLayout(hl1)

        # BinDiff Path
        self.bindiff_label = QLabel("BinDiff Path:")
        self.bindiff_path = QLineEdit()
        self.bindiff_browse = QPushButton("Browse")
        self.bindiff_browse.clicked.connect(self.browse_bindiff)
        hl2 = QHBoxLayout()
        hl2.addWidget(self.bindiff_path)
        hl2.addWidget(self.bindiff_browse)
        layout.addWidget(self.bindiff_label)
        layout.addLayout(hl2)

        # Python Path
        self.python_label = QLabel("Python Path:")
        self.python_path = QLineEdit()
        self.python_browse = QPushButton("Browse")
        self.python_browse.clicked.connect(self.browse_python)
        hl3 = QHBoxLayout()
        hl3.addWidget(self.python_path)
        hl3.addWidget(self.python_browse)
        layout.addWidget(self.python_label)
        layout.addLayout(hl3)

        # Tor options
        self.tor_checkbox = QCheckBox("Use Tor")
        layout.addWidget(self.tor_checkbox)

        self.tor_ip_label = QLabel("Tor Proxy:")
        self.tor_ip_field = QLineEdit("127.0.0.1")
        self.tor_port_field = QLineEdit("9050")
        self.tor_port_field.setFixedWidth(60) 
        hl_tor = QHBoxLayout()
        hl_tor.addWidget(self.tor_ip_label)
        hl_tor.addWidget(self.tor_ip_field)
        hl_tor.addWidget(QLabel("Port:"))
        hl_tor.addWidget(self.tor_port_field)
        hl_tor.addStretch()
        layout.addLayout(hl_tor)

        # Save + Start buttons
        hl_buttons = QHBoxLayout()
        self.save_button = QPushButton("Save Settings")
        self.save_button.clicked.connect(self.save_settings)
        hl_buttons.addWidget(self.save_button)

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_pipeline)
        hl_buttons.addWidget(self.start_button)

        layout.addLayout(hl_buttons)
        self.settings_tab.setLayout(layout)

    def init_logs_ui(self):
        layout = QVBoxLayout()
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)
        self.logs_tab.setLayout(layout)

    def append_log(self, msg: str):
        """Append new log message to the log view live."""
        self.log_view.appendPlainText(msg)
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def browse_ida(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select IDA Executable")
        if path:
            self.ida_path.setText(path)

    def browse_bindiff(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select BinDiff Executable")
        if path:
            self.bindiff_path.setText(path)

    def browse_python(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Python Executable")
        if path:
            self.python_path.setText(path)

    def save_settings(self):
        selected_name = self.product_dropdown.currentText()
        selected_id = PRODUCT_ID_MAP[selected_name]

        self.config["General"] = {
            "productid": selected_id,
            "system32path": r"C:/Windows/system32",
            "winsxspath": r"C:/Windows/WinSxS",
            "pythonpath": self.python_path.text()
        }

        self.config["Tools"] = {
            "IDAPath": self.ida_path.text(),
            "BinDiffPath": self.bindiff_path.text(),
        }

        self.config["Network"] = {
            "usetor": "yes" if self.tor_checkbox.isChecked() else "no",
            "torip": self.tor_ip_field.text(),
            "torport": self.tor_port_field.text()
        }

        self.config["Diff"] = {
            "numctxline": self.ctx_input.text()
        }

        with open(CONFIG_FILE, "w") as f:
            self.config.write(f)

        QMessageBox.information(self, "Saved", "Settings saved successfully!")

    def load_settings(self):
        self.config.read(CONFIG_FILE)

        saved_id = self.config.get("General", "productid", fallback="")
        for name, pid in PRODUCT_ID_MAP.items():
            if pid == saved_id:
                self.product_dropdown.setCurrentText(name)
                break

        # self.product_dropdown.setCurrentText(
        #     self.config.get("General", "productid", fallback="")
        # )
        self.ida_path.setText(self.config.get("Tools", "idapath", fallback=""))
        self.bindiff_path.setText(self.config.get("Tools", "bindiffpath", fallback=""))
        self.python_path.setText(self.config.get("General", "pythonpath", fallback=""))

        self.tor_checkbox.setChecked(self.config.get("Network", "usetor", fallback="no") == "yes")
        self.tor_ip_field.setText(self.config.get("Network", "torip", fallback="127.0.0.1"))
        self.tor_port_field.setText(self.config.get("Network", "torport", fallback="9050"))
        self.ctx_input.setText(self.config.get("Diff", "numctxline", fallback="30"))

    def start_pipeline(self):
        self.save_settings()

        threading.Thread(target=process_updates, daemon=True).start()

        if not scheduler.running:
            scheduler.start()

        def run_flask():
            flask_app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False)

        threading.Thread(target=run_flask, daemon=True).start()
        QMessageBox.information(
            self,
            "Started",
            "Access at http://127.0.0.1:80\nDefault creds eldiff:damagelib"
        )

    def closeEvent(self, event):
        """Ensure scheduler and logging shut down cleanly when GUI closes."""
        try:
            if scheduler.running:
                scheduler.shutdown(wait=False)
        except Exception as e:
            print(f"Scheduler shutdown error: {e}")

        try:
            if hasattr(self, "log_handler"):
                eldiff_logger.removeHandler(self.log_handler)
                self.log_handler.setParent(None)
                self.log_handler.deleteLater()
                self.log_handler = None
        except Exception as e:
            print(f"Logger cleanup error: {e}")

        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = SettingsGUI()
    gui.show()
    sys.exit(app.exec())
