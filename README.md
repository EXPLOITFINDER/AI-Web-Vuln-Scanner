# 🔍 Advanced AI-Powered Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.7+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Selenium](https://img.shields.io/badge/Testing-Selenium-yellowgreen?logo=selenium)

An intelligent web vulnerability scanner combining AI analysis with dynamic crawling and fuzzing techniques.

## 🚀 Features

- **AI-Powered Validation** (OpenAI GPT-3.5-turbo integration)
- **Smart Dynamic Crawling** (Selenium WebDriver)
- **OWASP Top 10 Coverage**:
  - XSS, SQLi, RCE, SSRF, Path Traversal
  - Command Injection, Security Misconfigurations
- **WAF Evasion Techniques**:
  - Multiple encoding schemes
  - Dynamic payload generation
- **Comprehensive Reporting**:
  - JSON/HTML output
  - OWASP risk scoring

## 📦 Installation

### Prerequisites
- Python 3.7+
- Chrome/Chromium browser
- OpenAI API key

```bash
# Clone repository
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner

# Install dependencies
pip install -r requirements.txt

# Set OpenAI API key
echo "OPENAI_API_KEY=your_api_key_here" > .env



python scanner.py -u https://example.com -d ./payloads/ -m 3

{
  "timestamp": "2023-11-15T14:30:00",
  "vulnerabilities": [
    {
      "type": "Reflected XSS",
      "owasp_score": 7.4,
      "confidence": "High"
    }
  ]
}

