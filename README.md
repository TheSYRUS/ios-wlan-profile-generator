# iOS-WLAN-Profile-Generator

Ein GUI-Tool (Tkinter) zur Generierung von `.mobileconfig`-WLAN-Profilen für iOS-Geräte.  
Unterstützt **Deutsch** und **Englisch** (umschaltbar in der App).

---

## 🇩🇪 Deutsch

### 🔐 Motivation & Hintergrund
iOS speichert bekannte WLANs inkl. Klartext-Passwort im Einstellungsmenü („Bekannte Netzwerke“).  
Dadurch besteht ein **Risiko der Passwortweitergabe** durch Nutzer.  

Mit dem **iOS-WLAN-Profile-Generator** wird ein `.mobileconfig`-Profil erstellt:  
- ✅ Keine manuelle Eingabe von SSID/Passwort auf dem Gerät erforderlich  
- ✅ Passwort bleibt für Dritte unsichtbar  
- ✅ Verbindung nur für Geräte möglich, die das Profil importieren  
- ✅ Andere Nutzer können ausschließlich das Gastnetzwerk verwenden  

---

### ✨ Features
- 🌐 **SSID / Passwort Eingabe**
- ⚙️ **Optionen**: AutoJoin, Hidden, Private-WLAN-Adresse ausschalten, IP-Tracking nicht beschränken
- 🛠️ **DNS & Proxy Konfiguration**
- 👀 **XML-Vorschau** des generierten `.mobileconfig`
- 💾 **Export** als `.mobileconfig`
- 🌍 **Sprachumschaltung**: DE / EN



---
---
---
---



# iOS-WLAN-Profile-Generator

A GUI tool (Tkinter) for generating `.mobileconfig` Wi-Fi profiles for iOS devices.  
Supports **German** and **English** (switchable within the app).

---

## 🔐 Motivation & Background
iOS stores known Wi-Fi networks including the **cleartext password** in the settings menu (“Known Networks”).  
This creates a **risk of password disclosure** by users.  

With the **iOS-WLAN-Profile-Generator**, a `.mobileconfig` profile can be created:  
- ✅ No manual entry of SSID/password on the device required  
- ✅ Password remains invisible to third parties  
- ✅ Connection only possible for devices that import & install the profile  
- ✅ All other users can use the guest Wi-Fi  

---

## ✨ Features
- 🌐 **SSID / Password input**
- ⚙️ **Options**: AutoJoin, Hidden, Disable Private Wi-Fi Address, Do not restrict IP tracking
- 🛠️ **DNS & Proxy configuration**
- 👀 **XML preview** of the generated `.mobileconfig`
- 💾 **Export** as `.mobileconfig`
- 🌍 **Language switch**: DE / EN

---
cd ios-wlan-profile-generator
python iOS-WLAN-Profile-Generator.py
