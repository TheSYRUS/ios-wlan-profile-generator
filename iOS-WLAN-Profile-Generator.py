#!/usr/bin/env python3
"""
iOS-WLAN-Profile-Generator
Ein einfacher Windows-GUI-Generator (Tkinter) um iOS .mobileconfig WLAN-Profile zu erzeugen.
Jetzt mit Sprach-Switch (DE/EN) direkt in der App.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import uuid
import plistlib

# ------------------ Sprach-Strings ------------------
STRINGS = {
    "de": {
        "title": "iOS-WLAN-Profile-Generator",
        "form_title": "WLAN-Einstellungen (Netzwerk hinzufügen)",
        "ssid": "SSID:",
        "password": "Passwort:",
        "autojoin": "Automatisch verbinden (AutoJoin)",
        "hidden": "Verstecktes WLAN",
        "disable_mac": "Private WLAN-Adresse ausschalten",
        "disable_privateaddr": "IP-Tracking nicht beschränken",
        "enc": "Verschlüsselung:",
        "dns": "DNS-Server (Komma getrennt):",
        "proxy": "Proxy:",
        "proxy_val": "PAC URL oder Host:Port:",
        "btn_add": "Netzwerk zur Liste hinzufügen",
        "btn_reset": "Form zurücksetzen",
        "list_title": "Netzwerk-Liste (wird in Profil eingebunden)",
        "btn_remove": "Entfernen",
        "btn_edit": "Bearbeiten",
        "btn_preview": "Vorschau erzeugen",
        "profile_name": "Profil-Name:",
        "btn_save": "Speichern (.mobileconfig)"
    },
    "en": {
        "title": "iOS Wi-Fi Profile Generator",
        "form_title": "Wi-Fi Settings (Add Network)",
        "ssid": "SSID:",
        "password": "Password:",
        "autojoin": "Auto-Join",
        "hidden": "Hidden Network",
        "disable_mac": "Disable Private Wi-Fi Address",
        "disable_privateaddr": "Do not restrict IP tracking",
        "enc": "Encryption:",
        "dns": "DNS servers (comma separated):",
        "proxy": "Proxy:",
        "proxy_val": "PAC URL or Host:Port:",
        "btn_add": "Add Network",
        "btn_reset": "Reset Form",
        "list_title": "Network List (to be included in profile)",
        "btn_remove": "Remove",
        "btn_edit": "Edit",
        "btn_preview": "Preview",
        "profile_name": "Profile Name:",
        "btn_save": "Save (.mobileconfig)"
    }
}
LANG = "de"
def t(key): return STRINGS[LANG][key]

# ------------------ Hilfsfunktionen ------------------
def make_wifi_dict(ssid, password, auto_join, hidden, encryption="WPA2",
                   disable_mac_random=False, disable_private_addr=False,
                   proxy_type=None, proxy_url=None, dns_servers=None):
    d = {
        "AutoJoin": auto_join,
        "EncryptionType": encryption,
        "HIDDEN_NETWORK": hidden,
        "Password": password,
        "PayloadDescription": f"WLAN Konfiguration für {ssid}",
        "PayloadDisplayName": f"{ssid} WLAN",
        "PayloadIdentifier": f"com.{ssid.lower()}.wifi",
        "PayloadType": "com.apple.wifi.managed",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1,
        "SSID_STR": ssid
    }
    if disable_mac_random:
        d["DisableAssociationMACRandomization"] = True
    if disable_private_addr:
        d["DisablePrivateAddress"] = True
    if proxy_type and proxy_type != "none":
        if proxy_type == "pac" and proxy_url:
            d["ProxyPACURL"] = proxy_url
            d["ProxyType"] = "Auto"
        elif proxy_type == "manual" and proxy_url:
            hostport = proxy_url.split(":", 1)
            if len(hostport) == 2:
                d["HTTPProxy"] = {
                    "HTTPEnable": 1,
                    "HTTPProxy": hostport[0],
                    "HTTPPort": int(hostport[1])
                }
                d["ProxyType"] = "Manual"
    if dns_servers:
        d["DNSServer"] = dns_servers
    return d

def build_mobileconfig(networks, profile_name="WLAN Profil"):
    top = {
        "PayloadContent": networks,
        "PayloadDisplayName": profile_name,
        "PayloadIdentifier": f"com.generated.wifi.profile.{uuid.uuid4().hex[:8]}",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1
    }
    return top

# ------------------ GUI ------------------
class MobileConfigApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(t("title"))
        self.geometry("780x520")
        self.resizable(True, True)

        # Sprachwahl Dropdown
        self.lang_var = tk.StringVar(value=LANG)
        lang_menu = ttk.OptionMenu(self, self.lang_var, LANG, "de", "en", command=self.set_lang)
        lang_menu.pack(anchor="ne", padx=10, pady=5)

        # Left: form
        self.frm = ttk.LabelFrame(self, text=t("form_title"))
        self.frm.pack(fill="both", expand=False, padx=10, pady=8)

        row = 0
        self.lbl_ssid = ttk.Label(self.frm, text=t("ssid"))
        self.lbl_ssid.grid(row=row, column=0, sticky="e", padx=4, pady=4)
        self.ssid_var = tk.StringVar(value="")
        ttk.Entry(self.frm, textvariable=self.ssid_var, width=30).grid(row=row, column=1, sticky="w", padx=4, pady=4)

        self.lbl_pw = ttk.Label(self.frm, text=t("password"))
        self.lbl_pw.grid(row=row, column=2, sticky="e", padx=4, pady=4)
        self.pw_var = tk.StringVar(value="")
        ttk.Entry(self.frm, textvariable=self.pw_var, width=30, show="*").grid(row=row, column=3, sticky="w", padx=4, pady=4)
        row += 1

        self.chk_autojoin = ttk.Checkbutton(self.frm, text=t("autojoin"))
        self.autojoin_var = tk.BooleanVar(value=True)
        self.chk_autojoin.config(variable=self.autojoin_var)
        self.chk_autojoin.grid(row=row, column=0, columnspan=2, sticky="w", padx=4, pady=4)

        self.chk_hidden = ttk.Checkbutton(self.frm, text=t("hidden"))
        self.hidden_var = tk.BooleanVar(value=False)
        self.chk_hidden.config(variable=self.hidden_var)
        self.chk_hidden.grid(row=row, column=2, columnspan=2, sticky="w", padx=4, pady=4)
        row += 1

        self.chk_disable_mac = ttk.Checkbutton(self.frm, text=t("disable_mac"))
        self.disable_mac_var = tk.BooleanVar(value=True)
        self.chk_disable_mac.config(variable=self.disable_mac_var)
        self.chk_disable_mac.grid(row=row, column=0, columnspan=2, sticky="w", padx=4, pady=4)

        self.chk_disable_priv = ttk.Checkbutton(self.frm, text=t("disable_privateaddr"))
        self.disable_privateaddr_var = tk.BooleanVar(value=True)
        self.chk_disable_priv.config(variable=self.disable_privateaddr_var)
        self.chk_disable_priv.grid(row=row, column=2, columnspan=2, sticky="w", padx=4, pady=4)
        row += 1

        self.lbl_enc = ttk.Label(self.frm, text=t("enc"))
        self.lbl_enc.grid(row=row, column=0, sticky="e", padx=4, pady=4)
        self.enc_var = tk.StringVar(value="WPA2")
        ttk.Combobox(self.frm, textvariable=self.enc_var, values=["WPA2", "WPA3", "WEP", "None"], width=12).grid(row=row, column=1, sticky="w", padx=4, pady=4)

        self.lbl_dns = ttk.Label(self.frm, text=t("dns"))
        self.lbl_dns.grid(row=row, column=2, sticky="e", padx=4, pady=4)
        self.dns_var = tk.StringVar(value="")
        ttk.Entry(self.frm, textvariable=self.dns_var, width=30).grid(row=row, column=3, sticky="w", padx=4, pady=4)
        row += 1

        self.lbl_proxy = ttk.Label(self.frm, text=t("proxy"))
        self.lbl_proxy.grid(row=row, column=0, sticky="e", padx=4, pady=4)
        self.proxy_type_var = tk.StringVar(value="none")
        ttk.Combobox(self.frm, textvariable=self.proxy_type_var, values=["none", "pac", "manual"], width=12).grid(row=row, column=1, sticky="w", padx=4, pady=4)
        self.lbl_proxy_val = ttk.Label(self.frm, text=t("proxy_val"))
        self.lbl_proxy_val.grid(row=row, column=2, sticky="e", padx=4, pady=4)
        self.proxy_val_var = tk.StringVar(value="")
        ttk.Entry(self.frm, textvariable=self.proxy_val_var, width=30).grid(row=row, column=3, sticky="w", padx=4, pady=4)
        row += 1

        # Buttons
        self.btn_add = ttk.Button(self.frm, text=t("btn_add"), command=self.add_network)
        self.btn_add.grid(row=row, column=0, padx=4, pady=4)
        self.btn_reset = ttk.Button(self.frm, text=t("btn_reset"), command=self.reset_form)
        self.btn_reset.grid(row=row, column=1, padx=4, pady=4)

        # Right: list
        self.list_frame = ttk.LabelFrame(self, text=t("list_title"))
        self.list_frame.pack(fill="both", expand=True, padx=10, pady=8)
        self.networks = []
        self.listbox = tk.Listbox(self.list_frame, height=8)
        self.listbox.pack(fill="both", side="left", expand=True, padx=4, pady=4)
        sb = ttk.Scrollbar(self.list_frame, command=self.listbox.yview)
        sb.pack(side="left", fill="y")
        self.listbox.config(yscrollcommand=sb.set)

        right_buttons = ttk.Frame(self.list_frame)
        right_buttons.pack(side="left", fill="y", padx=6)
        self.btn_remove = ttk.Button(right_buttons, text=t("btn_remove"), command=self.remove_selected)
        self.btn_remove.pack(fill="x", pady=4)
        self.btn_edit = ttk.Button(right_buttons, text=t("btn_edit"), command=self.edit_selected)
        self.btn_edit.pack(fill="x", pady=4)
        self.btn_preview = ttk.Button(right_buttons, text=t("btn_preview"), command=self.preview_mobileconfig)
        self.btn_preview.pack(fill="x", pady=4)

        # Bottom
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", expand=False, padx=10, pady=8)
        self.lbl_profile_name = ttk.Label(bottom, text=t("profile_name"))
        self.lbl_profile_name.pack(side="left", padx=4)
        self.profile_name_var = tk.StringVar(value="")
        ttk.Entry(bottom, textvariable=self.profile_name_var, width=30).pack(side="left", padx=4)
        self.btn_save = ttk.Button(bottom, text=t("btn_save"), command=self.save_mobileconfig)
        self.btn_save.pack(side="right", padx=4)

    # ---------- Sprachumschaltung ----------
    def set_lang(self, lang):
        global LANG
        LANG = lang
        self.title(t("title"))
        self.frm.config(text=t("form_title"))
        self.lbl_ssid.config(text=t("ssid"))
        self.lbl_pw.config(text=t("password"))
        self.chk_autojoin.config(text=t("autojoin"))
        self.chk_hidden.config(text=t("hidden"))
        self.chk_disable_mac.config(text=t("disable_mac"))
        self.chk_disable_priv.config(text=t("disable_privateaddr"))
        self.lbl_enc.config(text=t("enc"))
        self.lbl_dns.config(text=t("dns"))
        self.lbl_proxy.config(text=t("proxy"))
        self.lbl_proxy_val.config(text=t("proxy_val"))
        self.btn_add.config(text=t("btn_add"))
        self.btn_reset.config(text=t("btn_reset"))
        self.list_frame.config(text=t("list_title"))
        self.btn_remove.config(text=t("btn_remove"))
        self.btn_edit.config(text=t("btn_edit"))
        self.btn_preview.config(text=t("btn_preview"))
        self.lbl_profile_name.config(text=t("profile_name"))
        self.btn_save.config(text=t("btn_save"))

    # ---------- Netzwerkfunktionen ----------
    def reset_form(self):
        self.ssid_var.set("")
        self.pw_var.set("")
        self.autojoin_var.set(False)
        self.hidden_var.set(False)
        self.disable_mac_var.set(False)
        self.disable_privateaddr_var.set(False)
        self.enc_var.set("WPA2")
        self.dns_var.set("")
        self.proxy_type_var.set("none")
        self.proxy_val_var.set("")

    def add_network(self):
        ssid = self.ssid_var.get().strip()
        if not ssid:
            messagebox.showerror("Fehler", "SSID darf nicht leer sein.")
            return
        pw = self.pw_var.get()
        dns = [s.strip() for s in self.dns_var.get().split(",") if s.strip()] or None
        net = make_wifi_dict(
            ssid=ssid,
            password=pw,
            auto_join=self.autojoin_var.get(),
            hidden=self.hidden_var.get(),
            encryption=self.enc_var.get(),
            disable_mac_random=self.disable_mac_var.get(),
            disable_private_addr=self.disable_privateaddr_var.get(),
            proxy_type=self.proxy_type_var.get(),
            proxy_url=self.proxy_val_var.get().strip(),
            dns_servers=dns
        )
        self.networks.append(net)
        self.listbox.insert("end", f"{ssid} (AutoJoin={'ja' if net['AutoJoin'] else 'nein'})")

    def remove_selected(self):
        sel = self.listbox.curselection()
        if not sel: return
        idx = sel[0]
        self.listbox.delete(idx)
        del self.networks[idx]

    def edit_selected(self):
        sel = self.listbox.curselection()
        if not sel: return
        idx = sel[0]
        net = self.networks[idx]
        self.ssid_var.set(net.get("SSID_STR", ""))
        self.pw_var.set(net.get("Password", ""))
        self.autojoin_var.set(net.get("AutoJoin", False))
        self.hidden_var.set(net.get("HIDDEN_NETWORK", False))
        self.disable_mac_var.set(net.get("DisableAssociationMACRandomization", False))
        self.disable_privateaddr_var.set(net.get("DisablePrivateAddress", False))
        self.enc_var.set(net.get("EncryptionType", "WPA2"))
        self.dns_var.set(",".join(net.get("DNSServer", [])) if net.get("DNSServer") else "")
        self.listbox.delete(idx)
        del self.networks[idx]

    def preview_mobileconfig(self):
        if not self.networks:
            messagebox.showwarning("Keine Netzwerke", "Bitte erst Netzwerke hinzufügen.")
            return
        top = build_mobileconfig(self.networks, profile_name=self.profile_name_var.get())
        xml = plistlib.dumps(top, fmt=plistlib.FMT_XML).decode()
        win = tk.Toplevel(self)
        win.title("Vorschau")
        txt = tk.Text(win, wrap="none", width=100, height=30)
        txt.insert("1.0", xml)
        txt.pack(fill="both", expand=True)

    def save_mobileconfig(self):
        if not self.networks:
            messagebox.showwarning("Keine Netzwerke", "Bitte erst Netzwerke hinzufügen.")
            return
        top = build_mobileconfig(self.networks, profile_name=self.profile_name_var.get())
        path = filedialog.asksaveasfilename(defaultextension=".mobileconfig",
                                            filetypes=[("MobileConfig", "*.mobileconfig")])
        if not path: return
        with open(path, "wb") as f:
            plistlib.dump(top, f)
        messagebox.showinfo("Gespeichert", f"Datei gespeichert: {path}")

if __name__ == "__main__":
    app = MobileConfigApp()
    app.mainloop()
