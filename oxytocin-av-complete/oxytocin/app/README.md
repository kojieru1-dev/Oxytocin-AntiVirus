# 🛡️ Oxytocin AV

> **Security that feels human.** Cross-platform antivirus for Windows, Linux, and macOS.

![Version](https://img.shields.io/badge/version-1.0.0-00d4aa)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

- 🔍 **Real-time protection** — watches your filesystem 24/7
- 🧠 **Heuristic detection** — catches threats without known signatures
- 🔒 **Ransomware patterns** — detects suspicious encryption behavior
- ☁️ **VirusTotal lookup** — optional cloud-based threat intelligence
- 🪶 **Lightweight** — minimal CPU and memory footprint
- 🚫 **Zero telemetry** — your files never leave your machine

---

## ⚡ Quick Install

### Option 1: pip (all platforms)
```bash
pip install oxytocin-av
```

### Option 2: From source
```bash
git clone https://github.com/YOUR_USERNAME/oxytocin-av.git
cd oxytocin-av
pip install -r requirements.txt
python oxytocin_av.py version
```

---

## 🚀 Usage

### Scan a directory
```bash
oxytocin-av scan /path/to/folder
```

### Quick scan (executables only — faster)
```bash
oxytocin-av scan --quick
```

### Scan and auto-quarantine threats
```bash
oxytocin-av scan /Downloads --quarantine
```

### Enable real-time protection
```bash
oxytocin-av protect /home/myuser
```

### Cloud lookup with VirusTotal
```bash
oxytocin-av scan /Downloads --vt YOUR_VIRUSTOTAL_API_KEY
```

### Manage quarantine
```bash
oxytocin-av quarantine --list
oxytocin-av quarantine --clear
```

### Update definitions
```bash
oxytocin-av update
```

---

## 📦 Building Installers

### Windows (.exe installer with PyInstaller)
```bash
pip install pyinstaller
pyinstaller --onefile --name=OxytocinAV oxytocin_av.py
# Output: dist/OxytocinAV.exe
```

### macOS (.app bundle)
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name=OxytocinAV oxytocin_av.py
# Output: dist/OxytocinAV.app
```

### Linux (.deb package)
```bash
# See build-deb.sh script included in /scripts/
bash scripts/build-deb.sh
```

---

## 🌐 Website & Payments

The website is in `/website/index.html`. Deploy it free on:

**Netlify:**
1. Go to [netlify.com](https://netlify.com) → New site from Git
2. Connect your GitHub repo
3. Set publish directory to `website/`
4. Done! You'll get a free `.netlify.app` URL

**GitHub Pages:**
1. Go to repo Settings → Pages
2. Set source to `main` branch, `/website` folder
3. Done! URL: `https://YOUR_USERNAME.github.io/oxytocin-av`

**PayPal Setup:**
1. Go to [developer.paypal.com](https://developer.paypal.com)
2. Create an app → copy your Client ID
3. Create subscription plans (Pro $4.99/mo, Business $9.99/mo)
4. Replace `YOUR_CLIENT_ID_HERE`, `plan_PRO_ID_HERE`, `plan_BIZ_ID_HERE` in `index.html`

---

## 📁 Project Structure

```
oxytocin-av/
├── website/
│   └── index.html          ← Full website with PayPal
├── app/
│   ├── oxytocin_av.py      ← Core scanner engine
│   ├── setup.py            ← pip package config
│   └── requirements.txt    ← Python dependencies
├── scripts/
│   └── build-deb.sh        ← Linux package builder
├── README.md
└── LICENSE
```

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<p align="center">Made with ❤️ by the Oxytocin AV team</p>
