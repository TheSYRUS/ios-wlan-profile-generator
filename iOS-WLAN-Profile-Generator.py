#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iOS-WLAN-Profile-Generator (Single-SSID, Modern Layout)
Tkinter GUI to build iOS `.mobileconfig` Wi-Fi profiles (DE/EN).
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import uuid, plistlib

# ------------------ Translations ------------------
STRINGS = {
    "de": {
        "title": "iOS-WLAN-Profile-Generator",
        "lang": "Sprache:",
        "section_input": "📶 Netzwerkeingabe",
        "section_opts": "⚙️ Optionen",
        "section_export": "📤 Export",
        "footer": "ℹ️ Profile müssen manuell auf iOS importiert werden. Automatische Ferninstallation nur via MDM.",
        "ssid": "📶 SSID",
        "password": "🔑 Passwort",
        "enc": "🔐 Verschlüsselung",
        "dns": "🌐 DNS-Server (Komma)",
        "proxy_mode": "🌍 Proxy",
        "proxy_val": "🔗 PAC URL / Host:Port",
        "autojoin": "✅ Automatisch verbinden",
        "hidden": "👁️ Verstecktes WLAN",
        "disable_mac": "🛡️ MAC Random AUS",
        "disable_priv": "🔒 Private Adresse AUS",
        "profile_name": "📝 Profil-Name",
        "removal_pw": "🔑 Entfernen-Passwort",
        "reset": "♻️ Formular zurücksetzen",
        "preview": "👀 Vorschau",
        "save": "💾 Speichern (.mobileconfig)",
        "show_pw": "👁️",
        "err_ssid_empty": "SSID darf nicht leer sein.",
        "saved_prefix": "Datei gespeichert: ",
        "preview_title": "Vorschau (.mobileconfig XML)"
    },
    "en": {
        "title": "iOS Wi-Fi Profile Generator",
        "lang": "Language:",
        "section_input": "📶 Network Input",
        "section_opts": "⚙️ Options",
        "section_export": "📤 Export",
        "footer": "ℹ️ Profiles must be installed manually on iOS. Remote auto-install requires MDM.",
        "ssid": "📶 SSID",
        "password": "🔑 Password",
        "enc": "🔐 Encryption",
        "dns": "🌐 DNS servers (comma)",
        "proxy_mode": "🌍 Proxy",
        "proxy_val": "🔗 PAC URL / Host:Port",
        "autojoin": "✅ Auto-Join",
        "hidden": "👁️ Hidden Network",
        "disable_mac": "🛡️ Disable MAC Randomization",
        "disable_priv": "🔒 Disable Private Address",
        "profile_name": "📝 Profile Name",
        "removal_pw": "🔑 Removal Password",
        "reset": "♻️ Reset Form",
        "preview": "👀 Preview",
        "save": "💾 Save (.mobileconfig)",
        "show_pw": "👁️",
        "err_ssid_empty": "SSID must not be empty.",
        "saved_prefix": "File saved: ",
        "preview_title": "Preview (.mobileconfig XML)"
    }
}
LANG = "de"
def t(key): return STRINGS[LANG][key]

# ------------------ Builders ------------------
def make_wifi_dict(ssid, password, auto_join, hidden, encryption="WPA2",
                   disable_mac_random=False, disable_private_addr=False,
                   proxy_type="none", proxy_val="", dns_servers=None):
    d = {
        "AutoJoin": bool(auto_join),
        "EncryptionType": encryption,
        "HIDDEN_NETWORK": bool(hidden),
        "Password": password,
        "PayloadDescription": f"WLAN für {ssid}",
        "PayloadDisplayName": f"{ssid} WLAN",
        "PayloadIdentifier": f"com.{ssid.lower()}.wifi",
        "PayloadType": "com.apple.wifi.managed",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1,
        "SSID_STR": ssid,
        "DisableAssociationMACRandomization": bool(disable_mac_random),
        "DisablePrivateAddress": bool(disable_private_addr)
    }
    if dns_servers:
        d["DNSServer"] = dns_servers
    if proxy_type == "pac" and proxy_val:
        d["ProxyPACURL"] = proxy_val
        d["ProxyType"] = "Auto"
    elif proxy_type == "manual" and proxy_val and ":" in proxy_val:
        host, port = proxy_val.split(":", 1)
        try:
            d["HTTPProxy"] = {"HTTPEnable": 1, "HTTPProxy": host, "HTTPPort": int(port)}
            d["ProxyType"] = "Manual"
        except ValueError:
            pass
    return d

def build_mobileconfig(network, profile_name, removal_pw=None):
    top = {
        "PayloadContent": [network],
        "PayloadDisplayName": profile_name or "WLAN Profil",
        "PayloadIdentifier": f"com.generated.wifi.{uuid.uuid4().hex[:8]}",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1
    }
    if removal_pw:
        top["RemovalPassword"] = removal_pw
    return top

# ------------------ GUI App ------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(t("title"))
        self.geometry("900x600")

        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        style.configure("TButton", font=("Segoe UI", 11), padding=8)
        style.configure("TLabel", font=("Segoe UI", 11))
        style.configure("TCheckbutton", font=("Segoe UI", 11))

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        self.title_lbl = ttk.Label(header, text=t("title"), font=("Segoe UI", 16, "bold"))
        self.title_lbl.pack(side="left")
        self.lang_lbl = ttk.Label(header, text=t("lang"))
        self.lang_lbl.pack(side="right", padx=(0, 6))
        self.lang_var = tk.StringVar(value=LANG)
        ttk.OptionMenu(header, self.lang_var, LANG, "de", "en", command=self.set_lang).pack(side="right")

        # Input
        self.frm_input = ttk.LabelFrame(self, text=t("section_input"), padding=12)
        self.frm_input.pack(fill="x", padx=10, pady=8)

        r = 0
        self.lbl_ssid = ttk.Label(self.frm_input, text=t("ssid"))
        self.lbl_ssid.grid(row=r, column=0, sticky="e", padx=6, pady=6)
        self.ssid_var = tk.StringVar()
        self.ent_ssid = ttk.Entry(self.frm_input, textvariable=self.ssid_var, width=32)
        self.ent_ssid.grid(row=r, column=1, sticky="w", padx=6, pady=6)

        self.lbl_password = ttk.Label(self.frm_input, text=t("password"))
        self.lbl_password.grid(row=r, column=2, sticky="e", padx=6, pady=6)
        self.pw_var = tk.StringVar()
        self.ent_pw = ttk.Entry(self.frm_input, textvariable=self.pw_var, show="*", width=32)
        self.ent_pw.grid(row=r, column=3, sticky="w", padx=6, pady=6)
        self.btn_pw_toggle = ttk.Button(self.frm_input, text=t("show_pw"), width=3, command=self.toggle_pw)
        self.btn_pw_toggle.grid(row=r, column=4, sticky="w")

        r += 1
        self.lbl_enc = ttk.Label(self.frm_input, text=t("enc"))
        self.lbl_enc.grid(row=r, column=0, sticky="e", padx=6, pady=6)
        self.enc_var = tk.StringVar(value="WPA2")
        self.cmb_enc = ttk.Combobox(self.frm_input, textvariable=self.enc_var,
                                    values=["WPA2", "WPA3", "WEP", "None"], width=14, state="readonly")
        self.cmb_enc.grid(row=r, column=1, sticky="w", padx=6, pady=6)

        self.lbl_dns = ttk.Label(self.frm_input, text=t("dns"))
        self.lbl_dns.grid(row=r, column=2, sticky="e", padx=6, pady=6)
        self.dns_var = tk.StringVar()
        self.ent_dns = ttk.Entry(self.frm_input, textvariable=self.dns_var, width=32)
        self.ent_dns.grid(row=r, column=3, sticky="w", padx=6, pady=6)

        r += 1
        self.lbl_proxy_mode = ttk.Label(self.frm_input, text=t("proxy_mode"))
        self.lbl_proxy_mode.grid(row=r, column=0, sticky="e", padx=6, pady=6)
        self.proxy_mode = tk.StringVar(value="none")
        self.cmb_proxy = ttk.Combobox(self.frm_input, textvariable=self.proxy_mode,
                                      values=["none", "pac", "manual"], width=14, state="readonly")
        self.cmb_proxy.grid(row=r, column=1, sticky="w", padx=6, pady=6)

        self.lbl_proxy_val = ttk.Label(self.frm_input, text=t("proxy_val"))
        self.lbl_proxy_val.grid(row=r, column=2, sticky="e", padx=6, pady=6)
        self.proxy_val = tk.StringVar()
        self.ent_proxy_val = ttk.Entry(self.frm_input, textvariable=self.proxy_val, width=32)
        self.ent_proxy_val.grid(row=r, column=3, sticky="w", padx=6, pady=6)

        # Options
        self.opt = ttk.LabelFrame(self, text=t("section_opts"), padding=12)
        self.opt.pack(fill="x", padx=10, pady=8)
        self.autojoin_var = tk.BooleanVar(value=True)
        self.chk_autojoin = ttk.Checkbutton(self.opt, text=t("autojoin"), variable=self.autojoin_var)
        self.chk_autojoin.grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.hidden_var = tk.BooleanVar(value=False)
        self.chk_hidden = ttk.Checkbutton(self.opt, text=t("hidden"), variable=self.hidden_var)
        self.chk_hidden.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.disable_mac_var = tk.BooleanVar(value=True)
        self.chk_disable_mac = ttk.Checkbutton(self.opt, text=t("disable_mac"), variable=self.disable_mac_var)
        self.chk_disable_mac.grid(row=1, column=0, sticky="w", padx=6, pady=6)
        self.disable_priv_var = tk.BooleanVar(value=True)
        self.chk_disable_priv = ttk.Checkbutton(self.opt, text=t("disable_priv"), variable=self.disable_priv_var)
        self.chk_disable_priv.grid(row=1, column=1, sticky="w", padx=6, pady=6)

        # Export
        self.exp = ttk.LabelFrame(self, text=t("section_export"), padding=12)
        self.exp.pack(fill="x", padx=10, pady=8)
        self.lbl_profile_name = ttk.Label(self.exp, text=t("profile_name"))
        self.lbl_profile_name.grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.profile_name_var = tk.StringVar()
        self.ent_profile = ttk.Entry(self.exp, textvariable=self.profile_name_var, width=30)
        self.ent_profile.grid(row=0, column=1, sticky="w", padx=6, pady=6)

        self.lbl_removal_pw = ttk.Label(self.exp, text=t("removal_pw"))
        self.lbl_removal_pw.grid(row=0, column=2, sticky="e", padx=6, pady=6)
        self.removal_pw_var = tk.StringVar()
        self.ent_removal_pw = ttk.Entry(self.exp, textvariable=self.removal_pw_var, show="*", width=30)
        self.ent_removal_pw.grid(row=0, column=3, sticky="w", padx=6, pady=6)

        # Buttons row
        btns = ttk.Frame(self.exp)
        btns.grid(row=1, column=0, columnspan=4, pady=12)
        self.btn_preview = ttk.Button(btns, text=t("preview"), command=self.preview_mobileconfig, width=18)
        self.btn_preview.pack(side="left", padx=10)
        self.btn_reset = ttk.Button(btns, text=t("reset"), command=self.reset_form, width=25)
        self.btn_reset.pack(side="left", padx=10)
        self.btn_save = ttk.Button(btns, text=t("save"), command=self.save_mobileconfig, width=22)
        self.btn_save.pack(side="left", padx=10)

        # Footer
        self.footer_lbl = ttk.Label(self, text=t("footer"), foreground="#555")
        self.footer_lbl.pack(side="bottom", pady=(0, 6))

    def set_lang(self, lang):
        global LANG
        LANG = lang
        # Window + header
        self.title(t("title"))
        self.title_lbl.config(text=t("title"))
        self.lang_lbl.config(text=t("lang"))
        # Frames
        self.frm_input.config(text=t("section_input"))
        self.opt.config(text=t("section_opts"))
        self.exp.config(text=t("section_export"))
        # Input labels/buttons
        self.lbl_ssid.config(text=t("ssid"))
        self.lbl_password.config(text=t("password"))
        self.lbl_enc.config(text=t("enc"))
        self.lbl_dns.config(text=t("dns"))
        self.lbl_proxy_mode.config(text=t("proxy_mode"))
        self.lbl_proxy_val.config(text=t("proxy_val"))
        self.btn_pw_toggle.config(text=t("show_pw"))
        # Options labels
        self.chk_autojoin.config(text=t("autojoin"))
        self.chk_hidden.config(text=t("hidden"))
        self.chk_disable_mac.config(text=t("disable_mac"))
        self.chk_disable_priv.config(text=t("disable_priv"))
        # Export labels/buttons
        self.lbl_profile_name.config(text=t("profile_name"))
        self.lbl_removal_pw.config(text=t("removal_pw"))
        self.btn_preview.config(text=t("preview"))
        self.btn_reset.config(text=t("reset"))
        self.btn_save.config(text=t("save"))
        # Footer
        self.footer_lbl.config(text=t("footer"))

    def toggle_pw(self):
        self.ent_pw.config(show="" if self.ent_pw.cget("show") == "*" else "*")

    def reset_form(self):
        self.ssid_var.set("")
        self.pw_var.set("")
        self.dns_var.set("")
        self.proxy_mode.set("none")
        self.proxy_val.set("")
        self.autojoin_var.set(True)
        self.hidden_var.set(False)
        self.disable_mac_var.set(True)
        self.disable_priv_var.set(True)
        self.enc_var.set("WPA2")
        self.profile_name_var.set("")
        self.removal_pw_var.set("")

    def _dns_list(self):
        raw = (self.dns_var.get() or "").strip()
        return [s.strip() for s in raw.split(",") if s.strip()] or None

    def preview_mobileconfig(self):
        ssid = self.ssid_var.get().strip()
        if not ssid:
            messagebox.showerror("Error", t("err_ssid_empty"))
            return
        net = make_wifi_dict(ssid, self.pw_var.get(), self.autojoin_var.get(), self.hidden_var.get(),
                             self.enc_var.get(), self.disable_mac_var.get(), self.disable_priv_var.get(),
                             self.proxy_mode.get(), self.proxy_val.get().strip(), self._dns_list())
        top = build_mobileconfig(net, self.profile_name_var.get(), self.removal_pw_var.get())
        xml = plistlib.dumps(top, fmt=plistlib.FMT_XML).decode("utf-8", "ignore")
        win = tk.Toplevel(self)
        win.title(t("preview_title"))
        txt = tk.Text(win, wrap="none", width=110, height=30)
        txt.insert("1.0", xml)
        txt.pack(fill="both", expand=True)

    def save_mobileconfig(self):
        ssid = self.ssid_var.get().strip()
        if not ssid:
            messagebox.showerror("Error", t("err_ssid_empty"))
            return
        net = make_wifi_dict(ssid, self.pw_var.get(), self.autojoin_var.get(), self.hidden_var.get(),
                             self.enc_var.get(), self.disable_mac_var.get(), self.disable_priv_var.get(),
                             self.proxy_mode.get(), self.proxy_val.get().strip(), self._dns_list())
        top = build_mobileconfig(net, self.profile_name_var.get(), self.removal_pw_var.get())
        path = filedialog.asksaveasfilename(defaultextension=".mobileconfig",
                                            filetypes=[("MobileConfig", "*.mobileconfig"), ("All files", "*.*")])
        if not path: return
        with open(path, "wb") as f: plistlib.dump(top, f)
        messagebox.showinfo("OK", t("saved_prefix") + path)

if __name__ == "__main__":
    App().mainloop()
