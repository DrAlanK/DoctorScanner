import sys
import asyncio
import aiohttp
import time
import random
import ipaddress
import urllib.parse
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTextEdit, QLabel, QSpinBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar, 
                             QRadioButton, QButtonGroup, QCheckBox, QGroupBox, QFileDialog,
                             QComboBox, QMenu, QLineEdit, QMessageBox, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QFont, QColor, QAction, QIcon, QDesktopServices

# رفع مشکل بسته شدن ناگهانی Event Loop در ویندوز
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ==========================================
# UI Component: Collapsible Section (منوی کشویی)
# ==========================================
class CollapsibleSection(QWidget):
    def __init__(self, title, is_open=False):
        super().__init__()
        self.toggle_btn = QPushButton(f"▼  {title}" if is_open else f"◀  {title}")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setChecked(is_open)
        
        # استایل دکمه باز و بسته کردن
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                text-align: right;
                padding: 12px 15px;
                background-color: #1E293B;
                color: #38BDF8;
                border: 1px solid #334155;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #27374D; }
            QPushButton:checked {
                border-bottom-left-radius: 0px;
                border-bottom-right-radius: 0px;
                border-bottom: none;
                background-color: #162032;
            }
        """)
        
        self.content_area = QFrame()
        self.content_area.setStyleSheet("""
            QFrame {
                background-color: #0F172A;
                border: 1px solid #334155;
                border-top: none;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
            }
        """)
        
        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(15, 15, 15, 15)
        self.content_layout.setSpacing(10)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 10)
        layout.addWidget(self.toggle_btn)
        layout.addWidget(self.content_area)
        
        self.toggle_btn.toggled.connect(self.toggle_content)
        self.content_area.setVisible(is_open)
        
    def toggle_content(self, checked):
        title_text = self.toggle_btn.text()[3:] # حذف فلش قبلی
        if checked:
            self.toggle_btn.setText(f"▼  {title_text}")
            self.content_area.show()
        else:
            self.toggle_btn.setText(f"◀  {title_text}")
            self.content_area.hide()

    def set_content_layout(self, layout):
        self.content_layout.addLayout(layout)


# ==========================================
# Core Network & Async Scanner Thread
# ==========================================
class AsyncScannerWorker(QThread):
    progress = pyqtSignal(int)
    result_found = pyqtSignal(dict)
    finished_scan = pyqtSignal()
    log_msg = pyqtSignal(str)

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.is_running = True

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.async_scan())
        except Exception as e:
            self.log_msg.emit(f"خطای سیستمی در اسکنر: {str(e)}")
        finally:
            loop.close()
            self.finished_scan.emit()

    async def async_scan(self):
        ips = self.config['ips']
        ports = self.config['ports']
        workers = self.config['workers']
        timeout = self.config['timeout'] / 1000.0
        
        queue = asyncio.Queue()
        for ip in ips:
            for port in ports:
                queue.put_nowait((ip, port))
                
        total_tasks = queue.qsize()
        if total_tasks == 0:
            return

        completed = 0
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        
        async def worker_task(session):
            nonlocal completed
            while not queue.empty() and self.is_running:
                ip, port = queue.get_nowait()
                try:
                    res = await self.verify_ip(session, ip, port, timeout)
                    if res:
                        self.result_found.emit(res)
                except Exception:
                    pass
                finally:
                    completed += 1
                    if completed % max(1, (total_tasks // 100)) == 0 or completed == total_tasks:
                        self.progress.emit(int((completed / total_tasks) * 100))
                    queue.task_done()

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [asyncio.create_task(worker_task(session)) for _ in range(workers)]
            await asyncio.gather(*tasks)

    async def verify_ip(self, session, ip, port, timeout_sec):
        protocol = "http" if port in [80, 8080, 8880, 2052, 2082, 2086, 2095] else "https"
        speed_size = self.config['speed_size']
        url = self.config['speed_url'] or f"{protocol}://speed.cloudflare.com"
        
        headers = {
            "Host": urllib.parse.urlparse(url).netloc or "speed.cloudflare.com",
            "User-Agent": "Mozilla/5.0"
        }
        
        if self.config['ws_check']:
            headers["Upgrade"] = "websocket"
            headers["Connection"] = "Upgrade"

        dl_speed, ul_speed = 0.0, 0.0
        try:
            start_time = time.time()
            async with session.get(f"{url}/__down?bytes={speed_size}", headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_sec)) as response:
                if 'cloudflare' not in response.headers.get('Server', '').lower():
                    return None
                
                content = await response.read()
                elapsed = time.time() - start_time
                ping_ms = int(elapsed * 1000)
                
                if self.config['dl_test'] and elapsed > 0:
                    dl_speed = round((len(content) * 8 / 1000000) / elapsed, 2)
                    
            if self.config['min_speed'] > 0 and dl_speed < self.config['min_speed']:
                return None

            return {
                "ip": ip, "port": port, "ping": ping_ms, 
                "dl_speed": dl_speed, "ul_speed": ul_speed
            }
        except:
            return None

    def stop(self):
        self.is_running = False

# ==========================================
# Main GUI Application
# ==========================================
class DoctorScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Doctor Scanner Pro | Ultimate Edition")
        self.resize(1100, 800)
        self.alive_ips = []
        self.worker = None
        
        self.LARGE_SUBNETS = ["104.16.0.0/12", "104.24.0.0/14", "172.64.0.0/13", "108.162.192.0/18"]
        self.SMALL_SUBNETS = ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "173.245.48.0/20", "188.114.96.0/20"]

        self.apply_modern_theme()
        self.setup_ui()

    def apply_modern_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { 
                background-color: #0F172A; 
                color: #F8FAFC; 
                font-family: 'Segoe UI', Tahoma, Arial; 
            }
            QPushButton {
                background-color: #0284C7; 
                color: white;
                border: none; 
                border-radius: 6px;
                padding: 10px 15px; 
                font-weight: bold; 
                font-size: 13px;
            }
            QPushButton:hover { background-color: #0369A1; }
            QPushButton:pressed { background-color: #075985; }
            QPushButton:disabled { background-color: #334155; color: #94A3B8; }
            
            QPushButton#StartBtn { background-color: #10B981; font-size: 15px; padding: 12px; }
            QPushButton#StartBtn:hover { background-color: #059669; }
            
            QPushButton#StopBtn { background-color: #EF4444; font-size: 15px; padding: 12px; }
            QPushButton#StopBtn:hover { background-color: #DC2626; }
            
            QLineEdit, QTextEdit, QSpinBox, QComboBox {
                background-color: #1E293B; 
                color: #F8FAFC;
                border: 1px solid #334155; 
                border-radius: 6px; 
                padding: 8px;
            }
            QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #38BDF8; 
            }
            
            QTabWidget::pane { 
                border: 1px solid #1E293B; 
                border-radius: 8px; 
                background: #0F172A; 
            }
            QTabBar::tab { 
                background: #1E293B; 
                color: #94A3B8; 
                padding: 12px 25px; 
                border: 1px solid #334155; 
                border-bottom: none;
                border-top-left-radius: 8px; 
                border-top-right-radius: 8px; 
                margin-left: 4px;
            }
            QTabBar::tab:selected { 
                background: #0F172A; 
                color: #38BDF8; 
                font-weight: bold; 
                border-top: 3px solid #38BDF8;
                border-bottom: 1px solid #0F172A;
            }
            
            QTableWidget { 
                background-color: #1E293B; 
                color: #F8FAFC; 
                gridline-color: #334155; 
                border: 1px solid #334155;
                border-radius: 8px;
            }
            QHeaderView::section { 
                background-color: #0F172A; 
                color: #38BDF8; 
                border: none;
                border-right: 1px solid #334155;
                border-bottom: 1px solid #334155;
                padding: 10px; 
                font-weight: bold; 
            }
            QTableWidget::item:selected { background-color: rgba(56, 189, 248, 0.2); color: #38BDF8; }
            
            QProgressBar { 
                border: 1px solid #334155; 
                border-radius: 6px; 
                text-align: center; 
                color: white; 
                font-weight: bold; 
                background-color: #1E293B;
                height: 25px;
            }
            QProgressBar::chunk { background-color: #10B981; border-radius: 5px; }
            
            /* راست‌چین کردن لیبل‌های کنار رادیوباتن‌ها و چک‌باکس‌ها */
            QRadioButton, QCheckBox { layout-direction: Qt.RightToLeft; }
        """)

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header 
        header_layout = QHBoxLayout()
        lbl_logo = QLabel("🌐")
        lbl_logo.setStyleSheet("font-size: 45px;")
        
        lbl_title = QLabel("DOCTOR SCANNER PRO")
        lbl_title.setStyleSheet("font-size: 26px; font-weight: 900; color: #F8FAFC; letter-spacing: 2px;")
        
        lbl_subtitle = QLabel("Ultimate Edition | رابط کاربری مدرن")
        lbl_subtitle.setStyleSheet("font-size: 14px; color: #38BDF8; margin-top: 5px;")
        
        title_vbox = QVBoxLayout()
        title_vbox.addWidget(lbl_title)
        title_vbox.addWidget(lbl_subtitle)
        title_vbox.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        header_layout.addLayout(title_vbox)
        header_layout.addWidget(lbl_logo)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Tabs
        self.tabs = QTabWidget()
        self.tab_scanner = QWidget()
        self.tab_results = QWidget()
        self.tab_injector = QWidget()
        self.tab_creator = QWidget() # تب جدید سازنده
        
        self.tabs.addTab(self.tab_scanner, "⚙️ تنظیمات اسکنر")
        self.tabs.addTab(self.tab_results, "📊 نتایج زنده")
        self.tabs.addTab(self.tab_injector, "💉 تزریق به کانفیگ")
        self.tabs.addTab(self.tab_creator, "👤 سازنده و درباره")
        
        layout.addWidget(self.tabs)
        
        self.build_scanner_tab()
        self.build_results_tab()
        self.build_injector_tab()
        self.build_creator_tab()

    def build_scanner_tab(self):
        # اضافه کردن اسکرول برای راحتی در نمایش کشویی‌ها
        layout = QVBoxLayout(self.tab_scanner)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(10)
        
        # --- 1. Source Box (منبع آی‌پی) ---
        sec_source = CollapsibleSection("منبع تولید آی‌پی (Source)", is_open=True)
        src_layout = QVBoxLayout()
        
        radio_layout = QHBoxLayout()
        self.rb_random = QRadioButton("رندوم (ساب‌نت‌های کلادفلر)")
        self.rb_random.setChecked(True)
        self.rb_manual = QRadioButton("ورود دستی (IP/CIDR)")
        self.rb_file = QRadioButton("از فایل (TXT)")
        radio_layout.addWidget(self.rb_file)
        radio_layout.addWidget(self.rb_manual)
        radio_layout.addWidget(self.rb_random)
        
        self.random_options_widget = QWidget()
        rand_opt_layout = QHBoxLayout(self.random_options_widget)
        rand_opt_layout.setContentsMargins(0, 10, 0, 0) 
        self.rb_surface = QRadioButton("اسکن سطحی و سریع (رنج‌های کوچک)")
        self.rb_deep = QRadioButton("اسکن عمیق و دقیق (رنج‌های بزرگ)")
        self.rb_surface.setChecked(True)
        self.rb_surface.setStyleSheet("color: #94A3B8;")
        self.rb_deep.setStyleSheet("color: #94A3B8;")
        rand_opt_layout.addStretch()
        rand_opt_layout.addWidget(self.rb_deep)
        rand_opt_layout.addWidget(self.rb_surface)
        

        self.txt_manual = QTextEdit()
        self.txt_manual.setPlaceholderText("آی‌پی‌ها یا رنج‌ها را اینجا وارد کنید...\nمثال:\n104.16.0.0/24\n1.1.1.1")
        self.txt_manual.setMaximumHeight(80)
        self.txt_manual.hide()
        
        self.file_widget = QWidget()
        file_layout = QHBoxLayout(self.file_widget)
        file_layout.setContentsMargins(0,0,0,0)
        self.btn_file = QPushButton("📂 انتخاب فایل")
        self.btn_file.clicked.connect(self.select_file)
        self.lbl_file = QLabel("هیچ فایلی انتخاب نشده است")
        self.lbl_file.setStyleSheet("color: #94A3B8;")
        file_layout.addWidget(self.lbl_file)
        file_layout.addWidget(self.btn_file)
        self.file_widget.hide()
        
        self.rb_random.toggled.connect(lambda: self.random_options_widget.setVisible(self.rb_random.isChecked()))
        self.rb_manual.toggled.connect(lambda: self.txt_manual.setVisible(self.rb_manual.isChecked()))
        self.rb_file.toggled.connect(lambda: self.file_widget.setVisible(self.rb_file.isChecked()))
        
        src_layout.addLayout(radio_layout)
        src_layout.addWidget(self.random_options_widget)
        src_layout.addWidget(self.txt_manual)
        src_layout.addWidget(self.file_widget)
        sec_source.set_content_layout(src_layout)
        layout.addWidget(sec_source)

        # --- 2. Settings Box (تنظیمات پایه) ---
        sec_settings = CollapsibleSection("تنظیمات پایه اسکنر", is_open=True)
        set_layout = QHBoxLayout()
        
        self.spin_count = QSpinBox(); self.spin_count.setRange(10, 500000); self.spin_count.setValue(5000)
        self.spin_workers = QSpinBox(); self.spin_workers.setRange(1, 2000); self.spin_workers.setValue(100)
        self.spin_timeout = QSpinBox(); self.spin_timeout.setRange(500, 20000); self.spin_timeout.setValue(3000)
        
        set_layout.addWidget(self.spin_timeout)
        set_layout.addWidget(QLabel("تایم‌اوت (ms):"))
        set_layout.addWidget(self.spin_workers)
        set_layout.addWidget(QLabel("همزمانی (Workers):"))
        set_layout.addWidget(self.spin_count)
        set_layout.addWidget(QLabel("تعداد تولید IP:"))
        
        sec_settings.set_content_layout(set_layout)
        layout.addWidget(sec_settings)

        # --- 3. Ports Box (پورت‌ها) ---
        sec_ports = CollapsibleSection("تنظیمات پورت‌های هدف", is_open=False)
        port_layout = QVBoxLayout()
        
        grid_ports = QHBoxLayout()
        self.port_cbs = {}
        for p in [8080, 80, 2096, 2087, 2083, 2053, 8443, 443]:
            cb = QCheckBox(str(p))
            if p == 443: cb.setChecked(True)
            self.port_cbs[p] = cb
            grid_ports.addWidget(cb)
        
        config_port_layout = QHBoxLayout()
        self.txt_config_port = QLineEdit()
        self.txt_config_port.setPlaceholderText("vless://...")
        self.txt_config_port.setEnabled(False)
        self.cb_from_config = QCheckBox("تست بر اساس پورت کانفیگ (استخراج خودکار):")
        self.cb_from_config.toggled.connect(self.txt_config_port.setEnabled)
        
        config_port_layout.addWidget(self.txt_config_port)
        config_port_layout.addWidget(self.cb_from_config)
        
        port_layout.addLayout(grid_ports)
        port_layout.addLayout(config_port_layout)
        sec_ports.set_content_layout(port_layout)
        layout.addWidget(sec_ports)

        # --- 4. Advanced Box (پیشرفته) ---
        sec_adv = CollapsibleSection("تنظیمات پیشرفته (سرعت و دانلود)", is_open=False)
        adv_layout = QVBoxLayout()
        
        h1 = QHBoxLayout()
        self.chk_ul = QCheckBox("تست آپلود (بتا)")
        self.chk_ul.setEnabled(False) 
        self.chk_dl = QCheckBox("تست دانلود")
        self.chk_dl.setChecked(True)
        self.chk_ws = QCheckBox("بررسی WebSocket (هدرها)")
        h1.addWidget(self.chk_ul); h1.addWidget(self.chk_ws); h1.addWidget(self.chk_dl)
        
        h2 = QHBoxLayout()
        self.combo_size = QComboBox()
        self.combo_size.addItems(["100 KB", "512 KB", "1 MB", "10 MB"])
        self.combo_size.setCurrentText("512 KB")
        self.spin_min_speed = QSpinBox(); self.spin_min_speed.setSuffix(" Mbps")
        
        h2.addWidget(self.spin_min_speed)
        h2.addWidget(QLabel("حداقل سرعت مطلوب:"))
        h2.addStretch()
        h2.addWidget(self.combo_size)
        h2.addWidget(QLabel("حجم فایل تست:"))
        
        adv_layout.addLayout(h1)
        adv_layout.addLayout(h2)
        sec_adv.set_content_layout(adv_layout)
        layout.addWidget(sec_adv)

        layout.addStretch() # هل دادن همه باکس ها به بالا

        # --- Actions (دکمه‌های اصلی) ---
        btn_layout = QHBoxLayout()
        self.btn_stop = QPushButton("🛑 توقف")
        self.btn_stop.setObjectName("StopBtn")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        
        self.btn_start = QPushButton("⚡ شروع عملیات اسکن")
        self.btn_start.setObjectName("StartBtn")
        self.btn_start.clicked.connect(self.start_scan)
        
        btn_layout.addWidget(self.btn_stop, stretch=1)
        btn_layout.addWidget(self.btn_start, stretch=3)
        layout.addLayout(btn_layout)
        
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

    def build_results_tab(self):
        layout = QVBoxLayout(self.tab_results)
        
        act_layout = QHBoxLayout()
        btn_clear = QPushButton("🗑 پاکسازی")
        btn_clear.clicked.connect(self.clear_results)
        btn_export = QPushButton("💾 ذخیره نتایج (TXT)")
        btn_export.clicked.connect(self.export_results)
        
        self.lbl_stats = QLabel("آی‌پی‌های سالم: 0")
        self.lbl_stats.setStyleSheet("color: #10B981; font-weight: bold; font-size: 14px;")
        
        act_layout.addWidget(btn_clear)
        act_layout.addWidget(btn_export)
        act_layout.addStretch()
        act_layout.addWidget(self.lbl_stats)
        layout.addLayout(act_layout)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["آی‌پی (IP)", "پورت", "پینگ (Ping)", "دانلود (DL)", "آپلود (UL)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        # Fix RTL Display for table headers
        self.table.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        layout.addWidget(self.table)

    def build_injector_tab(self):
        layout = QVBoxLayout(self.tab_injector)
        
        lbl_in = QLabel("📝 کانفیگ‌های خام خود را اینجا وارد کنید (VLESS, Trojan, VMess):")
        layout.addWidget(lbl_in)
        
        self.txt_inj_in = QTextEdit()
        self.txt_inj_in.setLayoutDirection(Qt.LayoutDirection.LeftToRight) # کانفیگ ها چپ چین باشند
        layout.addWidget(self.txt_inj_in)
        
        self.btn_inject = QPushButton("💉 جایگذاری هوشمند بهترین آی‌پی پیدا شده روی پورت متناظر")
        self.btn_inject.setStyleSheet("background-color: #8B5CF6; font-size: 14px; padding: 12px;")
        self.btn_inject.clicked.connect(self.inject_configs)
        layout.addWidget(self.btn_inject)
        
        lbl_out = QLabel("✅ کانفیگ‌های بهینه‌شده:")
        layout.addWidget(lbl_out)
        
        self.txt_inj_out = QTextEdit()
        self.txt_inj_out.setReadOnly(True)
        self.txt_inj_out.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.txt_inj_out.setStyleSheet("border: 1px solid #10B981; background-color: #0F172A;")
        layout.addWidget(self.txt_inj_out)

    def build_creator_tab(self):
        """طراحی بسیار شیک برای تب سازنده (شما فقط لینک‌ها را عوض کنید)"""
        layout = QVBoxLayout(self.tab_creator)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)
        
        # آیکون یا پروفایل
        icon_lbl = QLabel("👨‍💻")
        icon_lbl.setStyleSheet("font-size: 90px; background-color: #1E293B; border-radius: 50px; padding: 20px;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # نام سازنده (اینجا نام خودتان را بنویسید)
        name_lbl = QLabel("توسعه یافته توسط: [دکتر آلان]")
        name_lbl.setStyleSheet("font-size: 26px; font-weight: 900; color: #38BDF8;")
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # توضیحات کوتاه
        desc_lbl = QLabel("خودم به خودم میگم دکتر. البته یسری ها هم اینو میگن. ولی در کل دکتر خوبی نیستم😁. خوشحال میشم یه سری به چنل تلگرام و اکانت گیت هابم برنی")
        desc_lbl.setStyleSheet("font-size: 15px; color: #94A3B8;")
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # دکمه‌های شبکه‌های اجتماعی
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)
        
        # 🟢 اینجا لینک تلگرام خود را جایگزین کنید
        self.telegram_url = "https://t.me/DrAlanCH"
        
        # 🟢 اینجا لینک گیت هاب خود را جایگزین کنید
        self.github_url = "https://github.com/DrAlanK"
        
        btn_tg = QPushButton("✈️  کانال تلگرام")
        btn_tg.setStyleSheet("""
            QPushButton { background-color: #0088cc; color: white; padding: 12px 25px; font-size: 15px; border-radius: 8px; }
            QPushButton:hover { background-color: #0099e6; }
        """)
        btn_tg.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.telegram_url)))
        
        btn_gh = QPushButton("🐙  گیت‌هاب من")
        btn_gh.setStyleSheet("""
            QPushButton { background-color: #24292e; color: white; padding: 12px 25px; font-size: 15px; border-radius: 8px; }
            QPushButton:hover { background-color: #2f363d; }
        """)
        btn_gh.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.github_url)))
        
        btn_layout.addStretch()
        btn_layout.addWidget(btn_gh)
        btn_layout.addWidget(btn_tg)
        btn_layout.addStretch()
        
        # اضافه کردن ویجت ها به صفحه
        layout.addStretch()
        layout.addWidget(icon_lbl, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_lbl)
        layout.addWidget(desc_lbl)
        layout.addSpacing(20)
        layout.addLayout(btn_layout)
        layout.addStretch()

    # ================== Logic Methods ==================
    def select_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل آی‌پی", "", "Text Files (*.txt)")
        if fname:
            self.lbl_file.setText(fname)
            self.selected_file_path = fname

    def show_context_menu(self, pos):
        menu = QMenu(self)
        menu.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        menu.setStyleSheet("""
            QMenu { background-color: #1E293B; color: white; border: 1px solid #334155; } 
            QMenu::item:selected { background-color: #0284C7; }
        """)
        copy_ip_act = QAction("📋 کپی آی‌پی", self)
        copy_all_act = QAction("📑 کپی تمام آی‌پی‌ها", self)
        
        copy_ip_act.triggered.connect(self.copy_selected_ip)
        copy_all_act.triggered.connect(self.copy_all_ips)
        
        menu.addAction(copy_ip_act)
        menu.addAction(copy_all_act)
        menu.exec(self.table.mapToGlobal(pos))

    def copy_selected_ip(self):
        row = self.table.currentRow()
        if row >= 0:
            ip = self.table.item(row, 0).text()
            QApplication.clipboard().setText(ip)

    def copy_all_ips(self):
        ips = [f"{item['ip']}:{item['port']}" for item in self.alive_ips]
        QApplication.clipboard().setText("\n".join(ips))

    def export_results(self):
        if not self.alive_ips: return
        fname, _ = QFileDialog.getSaveFileName(self, "ذخیره نتایج", "Doctor_Scanner_Results.txt", "Text Files (*.txt)")
        if fname:
            with open(fname, 'w', encoding='utf-8') as f:
                for res in self.alive_ips:
                    f.write(f"{res['ip']}:{res['port']} | Ping: {res['ping']}ms | DL: {res['dl_speed']}Mbps\n")
            QMessageBox.information(self, "موفق", "نتایج با موفقیت ذخیره شد.")

    def clear_results(self):
        self.table.setRowCount(0)
        self.alive_ips.clear()
        self.lbl_stats.setText("آی‌پی‌های سالم: 0")

    def generate_ips(self):
        target_ips = []
        count = self.spin_count.value()
        
        if self.rb_random.isChecked():
            subnets = self.LARGE_SUBNETS if self.rb_deep.isChecked() else self.SMALL_SUBNETS
            networks = [ipaddress.IPv4Network(b) for b in subnets]
            
            sampled = set()
            attempts = 0
            while len(sampled) < count and attempts < count * 3:
                attempts += 1
                net = random.choice(networks)
                rand_int = random.randint(int(net.network_address)+1, int(net.broadcast_address)-1)
                rand_ip = str(ipaddress.IPv4Address(rand_int))
                sampled.add(rand_ip)
            target_ips = list(sampled)
            
        elif self.rb_manual.isChecked():
            raw = self.txt_manual.toPlainText()
            for line in raw.split():
                line = line.strip()
                if '/' in line:
                    try: target_ips.extend([str(ip) for ip in ipaddress.IPv4Network(line, strict=False).hosts()])
                    except: pass
                elif line:
                    target_ips.append(line)
                    
        elif self.rb_file.isChecked() and hasattr(self, 'selected_file_path'):
            try:
                with open(self.selected_file_path, 'r', encoding='utf-8') as f:
                    target_ips = [line.strip() for line in f if line.strip()]
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در خواندن فایل: {e}")
                
        return target_ips[:count]

    def start_scan(self):
        ips = self.generate_ips()
        if not ips: 
            QMessageBox.warning(self, "اخطار", "هیچ آی‌پی برای اسکن یافت نشد! لطفاً تنظیمات منبع را بررسی کنید.")
            return
        
        ports = [p for p, cb in self.port_cbs.items() if cb.isChecked()]
        
        if self.cb_from_config.isChecked():
            conf = self.txt_config_port.text().strip()
            try:
                parsed = urllib.parse.urlparse(conf)
                if parsed.port and parsed.port not in ports:
                    ports.append(parsed.port)
            except: pass

        if not ports: 
            QMessageBox.warning(self, "اخطار", "حداقل یک پورت باید انتخاب شود.")
            return

        size_map = {"100 KB": 100000, "512 KB": 512000, "1 MB": 1000000, "10 MB": 10000000}
        
        config = {
            'ips': ips,
            'ports': ports,
            'workers': self.spin_workers.value(),
            'timeout': self.spin_timeout.value(),
            'ws_check': self.chk_ws.isChecked(),
            'dl_test': self.chk_dl.isChecked(),
            'speed_size': size_map[self.combo_size.currentText()],
            'min_speed': self.spin_min_speed.value(),
            'speed_url': ""
        }

        self.table.setRowCount(0)
        self.alive_ips.clear()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setValue(0)
        self.tabs.setCurrentIndex(1) 
        self.lbl_stats.setText(f"⏳ در حال اسکن (تعداد وظایف: {len(ips) * len(ports)})...")

        self.worker = AsyncScannerWorker(config)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.result_found.connect(self.add_result)
        self.worker.finished_scan.connect(self.scan_finished)
        self.worker.log_msg.connect(lambda msg: QMessageBox.critical(self, "خطا", msg))
        self.worker.start()

    def add_result(self, data):
        self.alive_ips.append(data)
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        ip_item = QTableWidgetItem(data['ip']); ip_item.setForeground(QColor("#38BDF8"))
        port_item = QTableWidgetItem(str(data['port']))
        ping_item = QTableWidgetItem(f"{data['ping']} ms")
        ping_item.setForeground(QColor("#10B981") if data['ping'] < 1000 else QColor("#F59E0B"))
        
        dl_item = QTableWidgetItem(f"{data['dl_speed']} Mbps" if data['dl_speed'] else "-")
        ul_item = QTableWidgetItem("-") 
        
        for item in [ip_item, port_item, ping_item, dl_item, ul_item]:
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
        self.table.setItem(row, 0, ip_item)
        self.table.setItem(row, 1, port_item)
        self.table.setItem(row, 2, ping_item)
        self.table.setItem(row, 3, dl_item)
        self.table.setItem(row, 4, ul_item)
        
        self.lbl_stats.setText(f"آی‌پی‌های سالم: {len(self.alive_ips)}")

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.btn_stop.setEnabled(False)
            self.lbl_stats.setText("🛑 متوقف شد.")

    def scan_finished(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setValue(100)
        self.lbl_stats.setText(f"✅ پایان عملیات | سالم: {len(self.alive_ips)}")

    def inject_configs(self):
        raw_text = self.txt_inj_in.toPlainText()
        if not self.alive_ips:
            self.txt_inj_out.setPlainText("❌ هیچ آی‌پی سالمی وجود ندارد! ابتدا اسکن کنید.")
            return

        out_lines = []
        for line in raw_text.strip().split('\n'):
            line = line.strip()
            if not line: continue
            
            try:
                parsed = urllib.parse.urlparse(line)
                port = parsed.port if parsed.port else 443
                
                suitable = [x for x in self.alive_ips if x['port'] == port]
                if suitable:
                    suitable.sort(key=lambda x: (-x.get('dl_speed', 0), x.get('ping', 9999)))
                    best_ip = suitable[0]['ip']
                    
                    if '@' in parsed.netloc:
                        user_pass, host_port = parsed.netloc.split('@', 1)
                        new_netloc = f"{user_pass}@{best_ip}:{port}"
                    else:
                        new_netloc = f"{best_ip}:{port}"
                        
                    new_parsed = parsed._replace(netloc=new_netloc)
                    out_lines.append(urllib.parse.urlunparse(new_parsed))
                else:
                    out_lines.append(f"{line} # (آی‌پی سالمی برای پورت {port} یافت نشد)")
            except Exception as e:
                out_lines.append(line)

        self.txt_inj_out.setPlainText('\n'.join(out_lines))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # 🔴 این خط بسیار حیاتی است: کل برنامه را راست‌چین و استاندارد فارسی می‌کند
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    
    window = DoctorScannerApp()
    window.show()
    sys.exit(app.exec())