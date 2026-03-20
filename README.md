<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

<h1 align="center">🛡️ PhishGuard: Real-Time Phishing URL Checker</h1>

<p align="center">
  <strong>Advanced AI-driven URL analysis to protect you from malicious websites, scams, and credential theft.</strong>
</p>

<p align="center">
  <a href="#sparkles-features">Features</a> •
  <a href="#rocket-tech-stack">Tech Stack</a> •
  <a href="#gear-getting-started">Getting Started</a> •
  <a href="#mag_right-how-it-works">How It Works</a>
</p>

---

## 📝 Description

**PhishGuard** is a modern, responsive web application built with **Next.js** that scans URLs for potential phishing threats in real-time. It analyzes given links through multiple security checks including SSL/TLS verification, domain analysis, and heuristic scanning to assign a comprehensive **Risk Score** and determine if a website is `Safe`, `Suspicious`, or `Phishing`.

Preview the app in AI Studio: [AI Studio Preview Link](https://ai.studio/apps/59e9b9bd-0908-4803-942f-22809c04b4fc)

## ✨ Features

- **🔍 Real-Time Analysis**: Quickly scans URLs to detect phishing indicators.
- **📊 Risk Scoring**: Calculates a precise risk score (0-100) based on multiple security parameters.
- **🛡️ Multi-layered Scanning**:
  - **HTTPS Check**: Verifies if the connection is encrypted securely.
  - **IP vs Domain Check**: Flags URLs masquerading with raw IP addresses.
  - **Subdomain Analysis**: Detects deceptive and excessive subdomains.
  - **Suspicious Keywords**: Checks for common phishing trigger words (e.g., `login`, `verify`, `secure`, `bank`).
- **🕰️ Scan History**: Saves your previous scan results locally in the browser for quick reference.
- **📋 Copy Report**: Easily copy a detailed security report to your clipboard to share with others.
- **💻 Modern UI/UX**: Sleek, dark-themed interface built specifically for security enthusiasts, styled with Tailwind CSS and Framer Motion.

## 🚀 Tech Stack

- **Framework**: [Next.js 15](https://nextjs.org/) (App Router)
- **Library**: [React 19](https://react.dev/)
- **Styling**: [Tailwind CSS v4](https://tailwindcss.com/)
- **Animations**: [Motion](https://motion.dev/)
- **Icons**: [Lucide React](https://lucide.dev/)
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **AI Integration**: [@google/genai](https://www.npmjs.com/package/@google/genai)

## ⚙️ Getting Started

Follow these steps to set up the project locally on your machine.

### Prerequisites

- **Node.js**: Ensure you have Node.js installed (v18+ recommended).
- **npm**: Package manager (comes with Node.js).

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Sahil-Kumar-Chaudhary/Phishing-url-checker.git
   cd Phishing-url-checker
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Set up Environment Variables:**

   Rename `.env.example` to `.env.local`.
   ```bash
   cp .env.example .env.local
   ```
   Open `.env.local` and add your required keys:
   ```env
   GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
   APP_URL="http://localhost:3000"
   ```

4. **Run the development server:**

   ```bash
   npm run dev
   ```

5. **Open in Browser:**

   Navigate to [http://localhost:3000](http://localhost:3000) to view the application.

## 📁 Project Structure

```text
├── app/
│   ├── globals.css      # Global Tailwind CSS styles
│   ├── layout.tsx       # Root layout component
│   └── page.tsx         # Main application page (PhishGuard UI & Logic)
├── hooks/               # Custom React hooks
├── lib/                 # Utility functions and shared logic
├── public/              # Static assets
├── .env.example         # Environment variables template
├── package.json         # Project dependencies and scripts
└── tsconfig.json        # TypeScript configuration
```

## 🔎 How It Works

1. **Input URL**: The user pastes a suspicious link into the main search bar.
2. **Analysis Process**: 
   - The app parses the URL and runs it through comprehensive heuristic checks.
   - It validates the protocol, domain structure, and length.
   - It cross-references the URL payload against a hardcoded list of suspicious keywords.
3. **Risk Calculation**: Based on the infractions found, a risk score is aggregated (capped at 100).
4. **Detailed Report**: The user receives a detailed breakdown with a `Safe`, `Suspicious`, or `Phishing` status, along with corresponding threat findings.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/Sahil-Kumar-Chaudhary/Phishing-url-checker/issues).

## 📄 License

This project is open-source and available under the MIT License.
