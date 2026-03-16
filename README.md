# 🛡 Threat Link Detector

A real-time URL threat intelligence tool built for cybersecurity analysis.
Scan any URL and get an instant verdict with deep analysis across 10+ threat engines.

---

## 🚀 Features

- **Real-Time URL Scanning** via urlscan.io API
- **Multi-Engine Detection** — 10 engines (Google Safe Browsing, Cisco Talos, PhishTank, URLHaus, AbuseIPDB and more)
- **Heuristic Engine** — URL entropy, typosquatting, suspicious keyword detection, homograph attack detection, subdomain depth analysis
- **Threat Database Checks** — 8 blacklist feeds checked per scan
- **Redirect Chain Visualization** — trace every hop from input to final destination
- **Domain Intelligence** — WHOIS-style data including domain age estimate, registrar, hosting provider
- **TLS/SSL Certificate Analysis** — issuer, validity timeline, trust status
- **Site Preview** — live screenshot + favicon + domain identity card
- **Scan Timeline** — step-by-step log of the entire analysis process
- **Threat History Analytics** — dashboard showing total, safe, suspicious and malicious scans
- **Scan History** — last 10 scans saved locally with one-click rescan
- **Export PDF** — full dark-themed scan report download
- **Copy JSON** — raw scan data to clipboard
- **Backend Status Indicator** — live green/red dot showing if backend is online

---

## 📁 Project Structure
```
Threat-Link-Detector/
├── backend.py       # FastAPI backend — urlscan.io API integration
├── index.html       # Frontend — full threat intelligence dashboard
└── README.md
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Threat-Link-Detector.git
cd Threat-Link-Detector
```

### 2. Install Python dependencies
```bash
pip install fastapi uvicorn httpx certifi
```

### 3. Start the backend
```bash
python -m uvicorn backend:app --reload
```
Backend runs on `http://localhost:8000`

### 4. Start the frontend
Open a second terminal in the same folder:
```bash
python -m http.server 5500
```
Then open your browser and go to:
```
http://localhost:5500
```
Click `index.html` to launch the app.

---

## 🔑 API Key

This project uses the [urlscan.io](https://urlscan.io) API.
The API key is included in `backend.py`. To use your own:
1. Sign up at [urlscan.io](https://urlscan.io)
2. Go to **Settings → API Key**
3. Replace the `API_KEY` value in `backend.py`

---

## 🖥️ Usage

1. Make sure both terminals are running (backend + frontend server)
2. Open `http://localhost:5500` in your browser
3. Enter any URL in the input box (must start with `http://` or `https://`)
4. Click **▶ SCAN** or press **Enter**
5. Wait 30–45 seconds for the full analysis to complete
6. Review the results across all panels
7. Click **⬇ EXPORT PDF** to save the full report

---

## 📊 Result Panels

| Panel | Description |
|---|---|
| Verdict Zone | SAFE / SUSPICIOUS / MALICIOUS with animated score ring |
| Threat Summary Pills | Quick-glance indicators for SSL, malicious flag, score, categories |
| Site Preview | Favicon, domain identity, live screenshot |
| Multi-Engine Scan | VirusTotal-style detection across 10 engines |
| URL Information | Input, resolved URL, domain, server |
| Network & Location | IP address, city, country, ASN, hosting |
| TLS/SSL Certificate | Issuer, trust status, validity timeline |
| Domain Intelligence | Age estimate, registrar, hosting, country |
| Threat Database Checks | 8 blacklist feeds (Google, PhishTank, Spamhaus etc) |
| Redirect Chain | Full hop-by-hop chain from input to destination |
| Threat Intelligence | Verdict details, categories, brands, tags |
| Heuristic Engine | Entropy, typosquatting, keywords, homograph, subdomain depth |
| Scan Timeline | Step-by-step log with timestamps |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python, FastAPI |
| Server | Uvicorn (ASGI) |
| Threat API | urlscan.io REST API |
| PDF Export | jsPDF |
| Fonts | Google Fonts (Orbitron, Exo 2, Share Tech Mono) |

---

## 📄 License

© 2025 Threat Link Detector. All rights reserved.
Built for B.E. IT VI Semester Mini Project — Stanley College of Engineering and Technology for Women.
