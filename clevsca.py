import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog, QMessageBox, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QSpinBox, QTextBrowser
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon
import aiohttp
import asyncio
import socket
import requests
import os


class WebScan(QThread):
    update_output = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            r = requests.get(self.url)
            status = str(r.status_code) 
            header = str(r.headers)
            cookie = str(r.cookies)

            self.update_output.emit("Web Scanning...\n")
            self.update_output.emit(f"*URL* : {self.url}\n")
            self.update_output.emit(f"*Connect* : {status}\n")
            self.update_output.emit(f"*Header* : {header}\n")
            self.update_output.emit(f"*Cookie* : {cookie}\n\n")
        except requests.exceptions.RequestException as e:
            self.update_output.emit(f"Error: {e}\n")


class DirScan(QThread):
    update_output = pyqtSignal(str)

    def __init__(self, url, scan_types):
        super().__init__()
        self.url = url
        self.scan_types = scan_types

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        self.update_output.emit("Directory Scanning...\n")

        scan_files = {
            'alpha': 'alpha.txt',
            'numbers': 'numbers.txt',
            'alphanum': 'alphanum.txt'
        }

        scan_dir_list = []

        for scan_type in self.scan_types:
            scan_file = scan_files.get(scan_type)
            if scan_file and os.path.exists(scan_file):
                with open(scan_file, 'r') as f:
                    scan_dir_list.extend(f.read().splitlines())
            else:
                self.update_output.emit(f"File not found: {scan_file}\n")

        found_dir = []

        async with aiohttp.ClientSession() as session:
            tasks = []
            for dir_name in scan_dir_list:
                full_url = self.url.rstrip('/') + '/' + dir_name
                tasks.append(self.check_directory(session, full_url))
            
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    found_dir.append(result)

        if not found_dir:
            self.update_output.emit("No directories found.\n")
        else:
            self.update_output.emit("\nScan complete. Found directories:\n")
            for dir in found_dir:
                self.update_output.emit(f"{dir}\n")

    async def check_directory(self, session, url):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    self.update_output.emit(f"Found: {url}\n")
                    return url
                else: 
                    self.update_output.emit(f"Trying: {url} - {response.status}\n")
        except aiohttp.ClientError as e:
            self.update_output.emit(f"An error occurred: {e}\n")
        return None


class PortScan(QThread):
    update_output = pyqtSignal(str)

    def __init__(self, url, start_port, end_port, batch_size=1000, timeout=5):
        super().__init__()
        self.url = url
        self.start_port = start_port
        self.end_port = end_port
        self.batch_size = batch_size
        self.timeout = timeout

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        open_ports = []
        self.update_output.emit(f"Scanning {self.url} for open ports...\n")
        host = socket.gethostbyname(self.url.split('//')[1])

        ports = list(range(self.start_port, self.end_port + 1))
        for i in range(0, len(ports), self.batch_size):
            batch_ports = ports[i:i + self.batch_size]
            self.update_output.emit(f"Scanning ports {batch_ports[0]} to {batch_ports[-1]}...\n")
            tasks = [self.scan_port(host, port) for port in batch_ports]
            results = await asyncio.gather(*tasks)
            open_ports.extend(filter(None, results))

        if not open_ports:
            self.update_output.emit("No open ports found.\n")
        else:
            self.update_output.emit("\nScan complete. Open ports:\n")
            for port in open_ports:
                self.update_output.emit(f"Port {port}: OPEN\n")

    async def scan_port(self, host, port):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except asyncio.TimeoutError:
            self.update_output.emit(f"Port {port}: Timeout\n")
        except Exception as e:
            self.update_output.emit(f"Port {port}: {e}\n")
            return None


class PortRange(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Port Range Input")
        self.setGeometry(100, 100, 300, 100)

        layout = QFormLayout(self)
        self.start_port_spinbox = QSpinBox(self)
        self.start_port_spinbox.setRange(1, 65535)
        self.start_port_spinbox.setValue(1)
        self.end_port_spinbox = QSpinBox(self)
        self.end_port_spinbox.setRange(1, 65535)
        self.end_port_spinbox.setValue(65535)
        
        layout.addRow("Start Port:", self.start_port_spinbox)
        layout.addRow("End Port:", self.end_port_spinbox)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def getValues(self):
        return self.start_port_spinbox.value(), self.end_port_spinbox.value()


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setGeometry(900, 500, 300, 600)

        self.setWindowTitle('clevsca')
        self.setWindowIcon(QIcon('./clevsca.ico'))
        layout = QVBoxLayout()

        url_layout = QHBoxLayout()
        url_label = QLabel('URL:')
        self.url_entry = QLineEdit()
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_entry)

        scan_options_layout = QHBoxLayout()
        self.options_label = QLabel('Directory Scan options:')
        self.alpha_checkbox = QCheckBox('alpha(abc)')
        self.numbers_checkbox = QCheckBox('numbers(123)')
        self.alphanum_checkbox = QCheckBox('alphanum(abc123)')
        scan_options_layout.addWidget(self.options_label)
        scan_options_layout.addWidget(self.alpha_checkbox)
        scan_options_layout.addWidget(self.numbers_checkbox)
        scan_options_layout.addWidget(self.alphanum_checkbox)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        buttons_layout = QHBoxLayout()
        self.webscan_button = QPushButton('Web Scan')
        self.webscan_button.clicked.connect(self.start_webscan)
        self.dirscan_button = QPushButton('Directory Scan')
        self.dirscan_button.clicked.connect(self.start_dirscan)
        self.portscan_button = QPushButton('Port Scan')
        self.portscan_button.clicked.connect(self.show_port_range_dialog)
        self.save_button = QPushButton('Save Results')
        self.save_button.clicked.connect(self.save_results)
        self.reset_button = QPushButton('Reset')
        self.reset_button.clicked.connect(self.reset)
        self.info_button = QPushButton('Info')
        self.info_button.clicked.connect(self.show_info)
        
        buttons_layout.addWidget(self.webscan_button)
        buttons_layout.addWidget(self.dirscan_button)
        buttons_layout.addWidget(self.portscan_button)
        buttons_layout.addWidget(self.save_button)
        buttons_layout.addWidget(self.reset_button)
        buttons_layout.addWidget(self.info_button)

        layout.addLayout(url_layout)
        layout.addLayout(scan_options_layout)
        layout.addWidget(self.output_area)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    def start_webscan(self):
        url = self.url_entry.text()
        self.webscan = WebScan(url)
        self.webscan.update_output.connect(self.update_output_area)
        self.webscan.start()

    def start_dirscan(self):
        url = self.url_entry.text()
        scan_types = []
        if self.alpha_checkbox.isChecked():
            scan_types.append('alpha')
        if self.numbers_checkbox.isChecked():
            scan_types.append('numbers')
        if self.alphanum_checkbox.isChecked():
            scan_types.append('alphanum')
        self.dirscan = DirScan(url, scan_types)
        self.dirscan.update_output.connect(self.update_output_area)
        self.dirscan.start()

    def show_port_range_dialog(self):
        dialog = PortRange(self)
        if dialog.exec_():
            start_port, end_port = dialog.getValues()
            self.start_portscan(start_port, end_port)

    def start_portscan(self, start_port, end_port):
        url = self.url_entry.text()
        self.portscan = PortScan(url, start_port, end_port)
        self.portscan.update_output.connect(self.update_output_area)
        self.portscan.start()

    def reset(self):
        self.output_area.clear()

    def save_results(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_area.toPlainText())

    def show_info(self):
            info_dialog = QDialog(self)
            info_dialog.setWindowTitle("Info")
            layout = QVBoxLayout(info_dialog)
            info_dialog.resize(500, 300)
            
            info_browser = QTextBrowser()
            cflink1 = "<a href='https://www.clevflo.com'>https://www.clevflo.com</a>"
            cflink2 = "<a href='https://github.com/clevflo/'>https://github.com/clevflo/</a>"
            email = "<a href='mailto:cl3vfl0@gmail.com'>cl3vfl0@gmail.com</a>"
            info_browser.setHtml(f"Website : {cflink1}<br>Github : {cflink2}<br>Email : {email}")
            info_browser.setOpenExternalLinks(True)

            layout.addWidget(info_browser)

            button_box = QDialogButtonBox(QDialogButtonBox.Ok)
            button_box.accepted.connect(info_dialog.accept)
            layout.addWidget(button_box)

            info_dialog.exec_()

    def update_output_area(self, text):
        self.output_area.append(text)


def main():
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
