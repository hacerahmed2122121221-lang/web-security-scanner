# Automated Web Security Scanner Dashboard

#### Video URL: (will be added upon publication)

#### Description:
This project is an Automated Web Security Scanner Dashboard developed by Ahmed Ayman Fikry as the final project for Harvard's CS50x course.

The application is built using Python and the Flask web framework. It provides a user-friendly, responsive interface powered by Bootstrap 5 (RTL) that allows security analysts and web administrators to scan websites for common security vulnerabilities and missing security headers.

### Features & Architecture:
- **`app.py`**: Serves as the core backend controller, handling routing, session management, dynamic templates rendering, and interactions with the SQLite database.
- **`scanner.py`**: Houses the security testing logic using Python's `requests` and `BeautifulSoup` libraries. It checks for missing security headers (such as HSTS, Content Security Policy, X-Frame-Options) and evaluates exposed endpoints/sensitive files (like `robots.txt`, `.env`, and `.git`).
- **`database.db`**: An SQLite database managed via CS50 SQL to store historical scan records, status, timestamps, and detailed findings per scan.
- **Templates**: Jinja2 HTML templates (`layout.html`, `index.html`, `dashboard.html`, `history.html`) that structure the presentation layer.

### How to Run:
1. Install dependencies: `pip install -r requirements.txt`
2. Initialize and run the application: `python app.py` or `flask run`
