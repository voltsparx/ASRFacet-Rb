# ASRFacet-Rb
**ASRFacet-Rb** is a Ruby 3.2+ attack surface reconnaissance toolkit designed for **authorized security testing**. <br>
It integrates passive discovery, active validation, web fingerprinting, lightweight vulnerability insights, relationship mapping, change tracking, and event-driven asset correlation into a unified, offline-capable pipeline.

<p align="center">
  <img src="https://raw.githubusercontent.com/voltsparx/ASRFacet-Rb/refs/heads/main/docs/images/illustration/asrfacet-rb-logo.png" alt="ASRFacet-Rb Logo" width="700">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-0A66C2?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/ruby-%3E%3D%203.2-red?style=for-the-badge&logo=ruby&logoColor=white" alt="Ruby >= 3.2">
  <img src="https://img.shields.io/badge/tests-0%2F165%20passing-2E8B57?style=for-the-badge" alt="Tests Passing">
  <img src="https://img.shields.io/badge/status-development-4C956C?style=for-the-badge" alt="Status Stable">
  <img src="https://img.shields.io/badge/license-Proprietary-8B0000?style=for-the-badge" alt="License">
</p>

---

## 🚀 Features

- Passive subdomain collection across multiple sources  
- Recursive DNS, certificate, WHOIS, ASN, HTTP, and crawling analysis  
- Lightweight vulnerability signals and intelligent noise filtering  
- Knowledge graph pivoting and correlation analysis  
- Persistent recon memory with monitoring and change tracking  
- JavaScript endpoint mining and asset scoring  
- Multiple output formats: CLI, JSON, TXT, and offline HTML  

---

## ⚙️ Installation

~~~
bundle install
bundle exec ruby bin/asrfacet --help
~~~

**Compatibility shim:**
~~~
bundle exec ruby bin/asrfacet-rb --help
~~~

---

## 🧪 Usage

~~~
bundle exec ruby bin/asrfacet scan example.com
bundle exec ruby bin/asrfacet passive example.com
bundle exec ruby bin/asrfacet ports 127.0.0.1 --ports top100
bundle exec ruby bin/asrfacet interactive
~~~

---

## 🧩 Configuration

User configuration is loaded from:

~~~
~/.asrfacet_rb/config.yml
~~~

and deep-merged with:

~~~
config/default.yml
~~~

---

## 📦 Output Formats

- `cli`
- `json`
- `txt`
- `html`

---

## ⚖️ Legal Disclaimer

ASRFacet-Rb is intended strictly for **authorized security testing**.

Only use this tool on systems you own or have **explicit written permission** to test. Unauthorized scanning may be illegal in your jurisdiction.

The author assumes no liability for misuse.

---

## 📜 License

Proprietary custom license. See <a href="https://raw.githubusercontent.com/voltsparx/ASRFacet-Rb/refs/heads/main/LICENSE">`LICENSE`</a>.
