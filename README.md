# Reflection Detector

A Burp Suite extension for automated reflection detection and XSS triage.

---

> [!WARNING]
**This project is for educational purposes only. Use it only for Targets that you have Permissions to test.**

---

> [!IMPORTANT]
> **This extension identifies potential XSS injection points (e.g., parameters and inputs), but results are heuristic-based and may include false positives or miss certain cases.
>
> It does not detect XSS vectors that rely on URI schemes such as `javascript:` or other non-standard execution contexts.**

---

### Payload Used 
- ```"><{-+(.;:)\'/}>'```

So if you see this, know that this is from the extension!!

---

## 🚀 Features

- 🔍 Detects reflection across:
  - URL parameters
  - POST body
  - JSON body

- 🧠 Context-aware detection:
  - HTML
  - Attribute
  - Script
  - JSON
  - Other

- ⚡ Multi-threaded scanning

- 🎯 Smart filtering:
  - Domain filter
  - Reflected (Yes/No)
  - Status code
  - Parameter type
  - Context

- 🔎 Search functionality across all columns

- ❌ JSON reflections marked as **Not Reflected** (to reduce false positives)

- 🧹 Non-editable table for clean triage

---

## ⚙️ Setup

### 1. Requirements

- Burp Suite (Community or Professional)
- Jython standalone (for Python support in Burp)

---

### 2. Configure Python in Burp

1. Open **Burp Suite**
2. Go to **Extensions → Options**
3. Set:
   - **Python Environment → Location of Jython standalone JAR file**
4. Select your downloaded `jython-standalone.jar`

---

### 3. Install the Extension

1. Go to **Extensions → Installed**
2. Click **Add**
3. Configure:
   - Extension type: **Python**
   - Extension file: `reflection.py`
4. Click **Next**

---

### 4. Verify Installation

- A new tab named **"Reflection Detector"** should appear
- Start intercepting traffic via **Proxy** or send requests via **Repeater**

---

## 🛠 Usage

1. Enable:
   - ✅ Proxy (for live traffic)
   - ✅ Repeater (for manual testing)

2. The extension will:
   - Extract parameters
   - Inject payloads
   - Detect reflection

3. Use filters to:
   - Focus on `Reflected = Yes`
   - Filter by `Context (HTML / SCRIPT / ATTRIBUTE)`

---

## 🧠 Understanding Results

| Context     | Meaning |
|------------|--------|
| HTML       | Reflected in page content |
| ATTRIBUTE  | Inside HTML attribute |
| SCRIPT     | Inside `<script>` block |
| JSON       | Reflected in API response (not exploitable) |
| NONE       | No reflection |

---

## ⚠️ Notes

- JSON reflections are intentionally marked as **Not Reflected**
- This tool detects **reflection only**, not full XSS exploitation
- Always manually validate execution

---

### Usage Image
<img width="1903" height="730" alt="image" src="https://github.com/user-attachments/assets/644a47d9-6484-4619-8694-14bb348f5668" />

---

## 🔧 Future Improvements

- Custom payload support
- DOM-based reflection detection
- Export functionality
- Advanced context classification

---

## 👨‍💻 Author

**Jolicious**
