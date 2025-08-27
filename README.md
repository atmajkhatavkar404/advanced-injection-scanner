# 💉 Advanced Injection Scanner 
🚀 A powerful web vulnerability scanner with a modern Dark Theme GUI built using Python and ttkbootstrap.
This tool helps penetration testers, security researchers, and bug bounty hunters quickly identify injection vulnerabilities such as:
	•	🔥 SQL Injection (SQLi)
	•	🕵️ Cross-Site Scripting (XSS)
	•	📂 Local/Remote File Inclusion (LFI/RFI)

With a smooth and attractive interface, it makes vulnerability testing faster, more efficient, and beginner-friendly.

⸻

✨ Features

✅ Beautiful Dark Theme GUI (ttkbootstrap)
✅ SQLi detection (Reflected + Error-based)
✅ XSS detection via payload reflection
✅ Custom payloads support (payloads/ directory)
✅ Progress bar & live logging console
✅ Log saving for every scan
✅ Theme switcher (20+ built-in themes!)

⸻

🎥 Demo Screenshot

(Add your screenshot here once you run it — a dark terminal-style GUI will look amazing!)

⸻

⚡ Installation

Clone the repository and install the required dependencies:

git clone https://github.com/atmajkhatavkar404/advanced-injection-scanner.git
cd injection-scanner
pip install -r requirements.txt

Requirements:
	•	Python 3.8+
	•	requests
	•	ttkbootstrap

Install dependencies manually if needed:
pip install requests ttkbootstrap

🚀 Usage

Run the scanner with:
python scanner.py

Steps:
	1.	Enter a target URL with parameters (e.g. http://example.com/page.php?id=1)
	2.	Choose your favorite dark theme
	3.	Click Start Scan
	4.	Watch vulnerabilities being detected in real time

🛡️ Disclaimer

⚠️ For educational and ethical penetration testing purposes only.
The author is not responsible for any misuse or illegal activities.
Always get proper authorization before testing any target.

⸻

⭐ Contributing

Want to add more payloads or detection methods?
Pull requests are welcome!
