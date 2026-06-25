# DoctorScanner

<p align="center">
  <img src="assets/DoctorScanner.png" width="160" height="160" style="border-radius: 50%; box-shadow: 0 0 20px #d4af37;" alt="Doctor Scanner Logo" />
</p>

<h1 align="center">⚜️ Doctor Scanner Pro ⚜️</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-gold?style=for-the-badge&logo=python&logoColor=black" alt="Python Version" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status" />
</p>

<p align="center">
  <a href="https://t.me/YOUR_CHANNEL_ID" target="_blank">
    <img src="https://img.shields.io/badge/Telegram-Join_Channel-blue?style=for-the-badge&logo=telegram" alt="Telegram Channel">
  </a>
</p>

<p align="right" dir="rtl">
<b>دکتر اسکنر (Doctor Scanner Pro)</b> یک ابزار فوق پیشرفته، پرسرعت و سبک برای تست پایداری و استخراج آی‌پی‌های سالم و تمیز کلادفلر (Cloudflare) در لایه ۴ شبکه (TCP Handshake) است. این پروژه با معماری نان-بلاکنیگ (Async) و چندرشته‌ای (Multi-threaded) طراحی شده تا بهینه‌ترین خروجی را با کمترین مصرف منابع ارائه دهد.
</p>

---

<h2 align="right" dir="rtl">⚡ ویژگی‌های کلیدی ابزار</h2>

* **تم اختصاصی نئون-طلایی :** رابط کاربری تاریک بسیار مدرن با اسکرول‌بار و المان‌های نئونی اختصاصی (در نسخه ویندوز).
* **سیستم پایش موازی (High-Concurrency):** قابلیت تنظیم رشته‌های موازی (Workers) تا ۳۰۰ رید همزمان برای سرعت بی‌سابقه.
* **تب‌بندی هوشمند دوحالته:**
    * **اسکن خودکار (Auto Scan):** دارای دو متد *سطحی/سریع* (بازه عمومی تمیز) و *عمیق/جامع* (کل رنج‌های ساختار دیتاسنتر کلادفلر).
    * **اسکن دستی (Manual Scan):** امکان تایپ مستقیم، کپی رنج‌های CIDR و تک آی‌پی، یا ایمپورت آنی فایل متنی (`.txt`).
* **کنترلرهای پیشرفته (Custom Steppers):** مدیریت دقیق پورت‌ها، تایم‌اوت (میلی‌ثانیه) و سقف نمونه‌برداری.
* **نصب خودکار پیش‌نیازها:** اسکریپت هوشمند که کتابخانه‌های لازم را در اجرای اول به صورت خودکار نصب می‌کند.

---

<h2 align="right" dir="rtl">💻 راهنمای دانلود و اجرا در ویندوز</h2>

<p align="right" dir="rtl">
اگر از سیستم‌عامل ویندوز استفاده می‌کنید و نیازی به سورس‌کد ندارید، می‌توانید نسخه گرافیکی و آماده (exe) را مستقیماً از بخش Releases دانلود کنید:
</p>
<div align="right" dir="rtl">
  <ul>
    <li>به بخش <b><a href="../../releases">Releases</a></b> در همین ریپازیتوری بروید.</li>
    <li>فایل اجرایی ویندوز را دانلود کرده و با دابل‌کلیک اجرا کنید.</li>
  </ul>
</div>

---

<h2 align="right" dir="rtl">📱 راهنمای اجرا در اندروید (ترموکس - Termux)</h2>

<p align="right" dir="rtl">
برای اجرای نسخه خط فرمان (CLI) در اندروید، ابتدا برنامه Termux را نصب کرده و سپس دستورات زیر را خط به خط در آن وارد کنید:
</p>

```bash
# ۱. آپدیت پکیج‌های ترموکس
apt update && apt upgrade -y

# ۲. نصب گیت و پایتون
apt install git python -y

# ۳. کلون کردن مخزن پروژه
git clone https://github.com/DrAlanK/doctor-scanner.git

# ۴. ورود به پوشه پروژه
cd doctor-scanner

# ۵. اجرای اسکنر (پیش‌نیازها به صورت خودکار نصب می‌شوند)
python main.py
