# PhishGuard: Phishing URL Checker
## How It Works - A Guide for Everyone

### Introduction
PhishGuard is an intelligent security tool designed to protect users from malicious websites. When a user enters a link (URL), the system acts like a digital detective, analyzing various characteristics of the website to determine if it is safe, suspicious, or a dangerous phishing attempt.

### 1. The User Experience (Frontend)
- **Input:** You simply paste a website link into the search bar and click "Scan URL".
- **Real-time Processing:** Within seconds, the screen displays a beautiful, easy-to-read dashboard.
- **The Result:** You receive a **Risk Score** (from 0 to 100) and a Status (Safe, Suspicious, or Phishing). The dashboard also explains *why* it received that score with positive (green) and negative (red) indicators.

### 2. The Brain Behind the Operation (The Backend)
The backend of this project is built using **Next.js API Routes** (running on a Node.js server). This allows the application to function as a fast, real-time processing engine that handles heavy investigations without slowing down the user's browser.

When you click "Scan", the backend performs several specialized checks simultaneously:

#### A. Identity & Reputation Checks
- **Trusted Domain Whitelist:** It first checks if the website is a globally recognized brand (like Google, Apple, or Amazon). If it is, the system marks it as trusted, preventing false alarms.
- **WHOIS & Domain Age:** It looks up when the website was created. Scammers frequently register new domain names that only exist for a few days. If a site was created very recently, the system raises a red flag.
- **IP Address Analysis:** Legitimate websites use readable domain names. Scammers sometimes try to hide by using raw numerical IP addresses (like `http://192.168.1.5`). The backend detects this immediately.

#### B. Security & Encryption Checks
- **HTTPS & SSL Certificates:** It verifies if the website uses a secure, encrypted connection (the padlock icon in your browser). It also actively fetches the security certificate to ensure it is valid, unexpired, and issued by a trusted authority.

#### C. Behavioral & Content Checks
- **Suspicious Keywords:** The system scans the URL for manipulative words often used by hackers, such as "login", "verify", "secure", "update", or "bank".
- **Hidden Redirects:** It tracks exactly where the link leads. Scammers often bounce users through multiple hidden links to mask their true destination. The backend detects these "redirect chains".
- **URL Length & Subdomains:** Phishing links are often excessively long or contain multiple fake subdomains (e.g., `login.secure-account.paypal-update.com`) to confuse the user.

### 3. The Risk Scoring Engine
Once the backend gathers all this digital evidence, it feeds it into a mathematical **Risk Scoring Engine**. 
- The system starts with a score of 0.
- Each suspicious finding adds penalty points to the score (e.g., missing HTTPS adds 25 points, suspicious subdomains add 20 points, recent registration adds 40 points).
- If the final score is **0 - 24**, the site is marked **Safe**.
- If the score is **25 - 59**, it is marked **Suspicious**.
- A score of **60 or higher** triggers a severe **Phishing** alert.

### Summary
In a matter of seconds, the PhishGuard backend performs a comprehensive forensic investigation of a website. It gathers public internet intelligence, inspects technical security layers, and applies smart heuristic rules—translating complex cybersecurity data into a simple, easy-to-understand safety report for the user.
