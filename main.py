'''
password generator and vault application using Tkinter and cryptography.
created by Somodo47


'''

import base64
import csv
import json
import os
import secrets
import string
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VAULT_FILE = Path(__file__).with_name("vault.json")
INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000


def random_password(
    number,
    include_symbols=False,
    lowercase=True,
    uppercase=True,
    numbers=True,
):
    chars = ""
    if lowercase:
        chars += string.ascii_lowercase
    if uppercase:
        chars += string.ascii_uppercase
    if numbers:
        chars += string.digits
    if include_symbols:
        chars += string.punctuation
    if not chars:
        raise ValueError("Select at least one character type.")
    return "".join(secrets.choice(chars) for _ in range(number))


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def save_vault(entries, master_password):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    encrypted_entries = Fernet(key).encrypt(json.dumps(entries).encode())
    vault_data = {
        "salt": base64.b64encode(salt).decode(),
        "data": encrypted_entries.decode(),
    }
    VAULT_FILE.write_text(json.dumps(vault_data), encoding="utf-8")


def load_vault(master_password):
    vault_data = json.loads(VAULT_FILE.read_text(encoding="utf-8"))
    salt = base64.b64decode(vault_data["salt"])
    key = derive_key(master_password, salt)
    decrypted_entries = Fernet(key).decrypt(vault_data["data"].encode())
    entries = json.loads(decrypted_entries.decode())
    for entry in entries:
        entry.setdefault("service", "")
        entry.setdefault("notes", "")
        entry.setdefault("password_changed_at", None)
    return entries


def password_strength_score(password):
    return sum(
        [
            len(password) >= 12,
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(character in string.punctuation for character in password),
        ]
    )


def vault_health(entries):
    now = datetime.now(timezone.utc)
    password_counts = Counter(entry["password"] for entry in entries)
    service_counts = Counter(
        entry["service"].strip().casefold() for entry in entries if entry["service"].strip()
    )
    reused = sum(1 for count in password_counts.values() if count > 1)
    weak = sum(1 for entry in entries if password_strength_score(entry["password"]) < 4)
    old = 0
    unknown_age = 0
    for entry in entries:
        timestamp = entry.get("password_changed_at")
        if not timestamp:
            unknown_age += 1
            continue
        try:
            changed = datetime.fromisoformat(timestamp)
            if (now - changed).days >= 180:
                old += 1
        except ValueError:
            unknown_age += 1
    missing_notes = sum(1 for entry in entries if not entry["notes"].strip())
    missing_services = sum(1 for entry in entries if not entry["service"].strip())
    duplicate_services = sum(1 for count in service_counts.values() if count > 1)
    issues = (
        reused + weak + old + missing_notes + missing_services + duplicate_services
    )
    score = max(0, 100 - min(100, issues * 8)) if entries else 100
    return {
        "score": score,
        "total": len(entries),
        "reused": reused,
        "weak": weak,
        "old": old,
        "unknown_age": unknown_age,
        "missing_notes": missing_notes,
        "missing_services": missing_services,
        "duplicate_services": duplicate_services,
    }


def import_browser_csv(file_path):
    imported_entries = []
    try:
        with open(file_path, "r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                normalized = {
                    (key or "").strip().casefold().replace(" ", "_"): (value or "").strip()
                    for key, value in row.items()
                }
                service = normalized.get("name") or normalized.get("url") or normalized.get("origin")
                username = normalized.get("username") or normalized.get("login")
                password = normalized.get("password")
                notes = normalized.get("notes", "")
                if service and username and password:
                    imported_entries.append(
                        {
                            "service": service,
                            "username": username,
                            "password": password,
                            "notes": notes,
                            "password_changed_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="utf-16", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                normalized = {
                    (key or "").strip().casefold().replace(" ", "_"): (value or "").strip()
                    for key, value in row.items()
                }
                service = normalized.get("name") or normalized.get("url") or normalized.get("origin")
                username = normalized.get("username") or normalized.get("login")
                password = normalized.get("password")
                if service and username and password:
                    imported_entries.append(
                        {
                            "service": service,
                            "username": username,
                            "password": password,
                            "notes": normalized.get("notes", ""),
                            "password_changed_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
    return imported_entries


def unlock_vault(root, simpledialog, messagebox):
    if not VAULT_FILE.exists():
        while True:
            master_password = simpledialog.askstring(
                "Create vault", "Create a master password:", show="*", parent=root
            )
            if master_password is None:
                return None, None
            if not master_password:
                messagebox.showerror("Invalid password", "The master password cannot be empty.", parent=root)
                continue
            confirmation = simpledialog.askstring(
                "Create vault", "Confirm the master password:", show="*", parent=root
            )
            if master_password == confirmation:
                return [], master_password
            messagebox.showerror("Passwords do not match", "Try again.", parent=root)

    while True:
        master_password = simpledialog.askstring(
            "Unlock vault", "Enter your master password:", show="*", parent=root
        )
        if master_password is None:
            return None, None
        try:
            return load_vault(master_password), master_password
        except (InvalidToken, KeyError, ValueError, json.JSONDecodeError):
            messagebox.showerror("Unlock failed", "The master password is incorrect.", parent=root)


def generate_password():
    try:
        length = int(length_var.get())
        if length < 1:
            raise ValueError
    except ValueError:
        status_var.set("Enter a positive whole number.")
        return

    try:
        password_var.set(
            random_password(
                length,
                symbols_var.get(),
                lowercase_var.get(),
                uppercase_var.get(),
                numbers_var.get(),
            )
        )
    except ValueError as error:
        status_var.set(str(error))
        return
    status_var.set("Password generated.")


def copy_password():
    password = password_var.get()
    if not password:
        status_var.set("Generate or select a password first.")
        return

    window.clipboard_clear()
    window.clipboard_append(password)
    window.update()
    status_var.set("Password copied to clipboard.")


def save_entry():
    service = service_var.get().strip()
    username = username_var.get().strip()
    password = password_var.get()
    notes = notes_var.get("1.0", "end-1c").strip()
    if not service or not username or not password:
        status_var.set("Enter a service, username, and password first.")
        return
    selection = entries_list.curselection()
    current_entry = filtered_entries[selection[0]] if selection else None
    if any(
        entry is not current_entry
        and entry["username"].casefold() == username.casefold()
        and entry["service"].casefold() == service.casefold()
        for entry in entries
    ):
        status_var.set("That username is already saved for this service.")
        return

    new_entry = {
        "service": service,
        "username": username,
        "password": password,
        "notes": notes,
        "password_changed_at": datetime.now(timezone.utc).isoformat(),
    }
    if current_entry:
        current_entry.update(new_entry)
        status_var.set("Credential updated.")
    else:
        entries.append(new_entry)
        status_var.set("Credential saved in the encrypted vault.")
    save_vault(entries, master_password)
    refresh_entries()
    clear_fields(False)


def import_browser_credentials():
    file_path = filedialog.askopenfilename(
        title="Import browser passwords",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        parent=window,
    )
    if not file_path:
        return
    try:
        imported_entries = import_browser_csv(file_path)
    except (OSError, csv.Error, UnicodeError) as error:
        messagebox.showerror("Import failed", f"Could not read the file:\n{error}", parent=window)
        return

    existing_keys = {
        (entry["service"].casefold(), entry["username"].casefold())
        for entry in entries
    }
    added = 0
    skipped = 0
    for entry in imported_entries:
        key = (entry["service"].casefold(), entry["username"].casefold())
        if key in existing_keys:
            skipped += 1
            continue
        entries.append(entry)
        existing_keys.add(key)
        added += 1

    if added:
        save_vault(entries, master_password)
        refresh_entries()
    status_var.set(f"Imported {added} credential(s); skipped {skipped} duplicate(s).")
    if not imported_entries:
        messagebox.showwarning(
            "Nothing imported",
            "No complete service, username, and password rows were found.",
            parent=window,
        )


def select_entry(event=None):
    selection = entries_list.curselection()
    if not selection:
        return
    entry = filtered_entries[selection[0]]
    service_var.set(entry["service"])
    username_var.set(entry["username"])
    password_var.set(entry["password"])
    notes_var.delete("1.0", "end")
    notes_var.insert("1.0", entry["notes"])
    status_var.set("Credential loaded.")


def delete_entry():
    selection = entries_list.curselection()
    if not selection:
        status_var.set("Select a credential to delete.")
        return
    if not messagebox.askyesno(
        "Delete credential", "Delete the selected credential?", parent=window
    ):
        return
    entries.remove(filtered_entries[selection[0]])
    save_vault(entries, master_password)
    refresh_entries()
    clear_fields(False)
    status_var.set("Credential deleted.")


def refresh_entries():
    global filtered_entries
    search_text = search_var.get().casefold()
    filtered_entries = [
        entry
        for entry in entries
        if search_text in " ".join(
            [entry["service"], entry["username"], entry["notes"]]
        ).casefold()
    ]
    filtered_entries.sort(key=lambda entry: (entry["service"].casefold(), entry["username"].casefold()))
    entries_list.delete(0, "end")
    for entry in filtered_entries:
        entries_list.insert("end", f"{entry['service']} - {entry['username']}")


def update_strength(*args):
    password = password_var.get()
    score = password_strength_score(password)
    labels = ["", "Very weak", "Weak", "Medium", "Strong", "Very strong"]
    strength_var.set(f"Strength: {labels[score]}")


def toggle_password_visibility():
    password_entry.configure(show="" if show_password_var.get() else "*")


def clear_fields(update_status=True):
    service_var.set("")
    username_var.set("")
    password_var.set("")
    notes_var.delete("1.0", "end")
    entries_list.selection_clear(0, "end")
    if update_status:
        status_var.set("Fields cleared.")


def lock_vault():
    global entries, master_password
    window.withdraw()
    clear_fields(False)
    entries, master_password = unlock_vault(window, simpledialog, messagebox)
    if entries is None:
        window.destroy()
        return
    refresh_entries()
    status_var.set("Vault unlocked.")
    reset_inactivity_timer()


def reset_inactivity_timer(event=None):
    global inactivity_job
    if inactivity_job:
        window.after_cancel(inactivity_job)
    inactivity_job = window.after(INACTIVITY_TIMEOUT_MS, lock_vault)


def update_length_label(*args):
    length_label_var.set(f"Length: {length_var.get()}")


def apply_theme():
    dark = dark_theme_var.get()
    colors = {
        "background": "#202124" if dark else "#f4f6f8",
        "foreground": "#f1f3f4" if dark else "#202124",
        "field": "#303134" if dark else "#ffffff",
        "select": "#5f6368" if dark else "#dbeafe",
    }
    window.configure(bg=colors["background"])
    style.configure("TFrame", background=colors["background"])
    style.configure("TLabel", background=colors["background"], foreground=colors["foreground"])
    style.configure("TCheckbutton", background=colors["background"], foreground=colors["foreground"])
    style.configure("TEntry", fieldbackground=colors["field"], foreground=colors["foreground"])
    entries_list.configure(
        bg=colors["field"],
        fg=colors["foreground"],
        selectbackground=colors["select"],
        selectforeground=colors["foreground"],
    )
    notes_var.configure(
        bg=colors["field"], fg=colors["foreground"], insertbackground=colors["foreground"]
    )


def show_welcome_screen():
    welcome = tk.Toplevel(window)
    welcome.title("Welcome")
    welcome.resizable(False, False)
    welcome.transient(window)
    welcome.grab_set()
    content = ttk.Frame(welcome, padding=28)
    content.pack(fill="both", expand=True)
    ttk.Label(content, text="Welcome to your password vault", font=("Segoe UI", 16, "bold")).pack(
        pady=(0, 12)
    )
    ttk.Label(
        content,
        text="Generate secure passwords and store your credentials\nin an encrypted local vault.",
        justify="center",
    ).pack(pady=(0, 18))
    ttk.Button(
        content,
        text="Get started",
        command=lambda: (welcome.grab_release(), welcome.destroy()),
    ).pack()
    welcome.protocol(
        "WM_DELETE_WINDOW", lambda: (welcome.grab_release(), welcome.destroy())
    )
    window.wait_window(welcome)


def show_vault_health():
    health = vault_health(entries)
    report = tk.Toplevel(window)
    report.title("Vault health")
    report.resizable(False, False)
    report.transient(window)
    content = ttk.Frame(report, padding=24)
    content.pack(fill="both", expand=True)
    ttk.Label(content, text=f"Vault health score: {health['score']}/100", font=("Segoe UI", 16, "bold")).pack(
        pady=(0, 14)
    )
    lines = [
        f"Accounts analyzed: {health['total']}",
        f"Reused passwords: {health['reused']}",
        f"Weak passwords: {health['weak']}",
        f"Passwords older than 180 days: {health['old']}",
        f"Password ages unknown: {health['unknown_age']}",
        f"Accounts without notes: {health['missing_notes']}",
        f"Accounts without service names: {health['missing_services']}",
        f"Services with multiple accounts: {health['duplicate_services']}",
    ]
    ttk.Label(content, text="\n".join(lines), justify="left").pack(anchor="w", pady=(0, 14))
    ttk.Label(
        content,
        text="This analysis runs locally. Password values are never shown in this report.",
        wraplength=320,
    ).pack(anchor="w", pady=(0, 14))
    ttk.Button(content, text="Close", command=report.destroy).pack()


if __name__ == "__main__":
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk

    first_run = not VAULT_FILE.exists()
    window = tk.Tk()
    window.withdraw()
    entries, master_password = unlock_vault(window, simpledialog, messagebox)
    if entries is None:
        window.destroy()
        raise SystemExit

    window.title("Password Generator and Vault")
    window.geometry("560x760")
    window.resizable(False, False)
    window.deiconify()

    length_var = tk.IntVar(value=16)
    length_label_var = tk.StringVar()
    lowercase_var = tk.BooleanVar(value=True)
    uppercase_var = tk.BooleanVar(value=True)
    numbers_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    service_var = tk.StringVar()
    username_var = tk.StringVar()
    password_var = tk.StringVar()
    show_password_var = tk.BooleanVar(value=False)
    strength_var = tk.StringVar(value="Strength: ")
    search_var = tk.StringVar()
    status_var = tk.StringVar(value="Generate a password or enter credentials to save.")
    dark_theme_var = tk.BooleanVar(value=False)
    filtered_entries = []
    inactivity_job = None

    style = ttk.Style(window)
    frame = ttk.Frame(window, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Password Generator", font=("Segoe UI", 18, "bold")).pack(
        pady=(0, 16)
    )

    length_frame = ttk.Frame(frame)
    length_frame.pack(fill="x", pady=(0, 10))
    ttk.Label(length_frame, textvariable=length_label_var).pack(side="left")
    ttk.Scale(
        length_frame, from_=4, to=64, variable=length_var, command=update_length_label
    ).pack(side="right", fill="x", expand=True, padx=(16, 0))
    character_types = ttk.Frame(frame)
    character_types.pack(fill="x", pady=(0, 10))
    ttk.Checkbutton(character_types, text="Lowercase", variable=lowercase_var).pack(side="left")
    ttk.Checkbutton(character_types, text="Uppercase", variable=uppercase_var).pack(side="left")
    ttk.Checkbutton(character_types, text="Numbers", variable=numbers_var).pack(side="left")
    ttk.Checkbutton(character_types, text="Symbols", variable=symbols_var).pack(side="left")

    ttk.Label(frame, text="Service or website:").pack(anchor="w")
    ttk.Entry(frame, textvariable=service_var).pack(fill="x", pady=(2, 10))

    ttk.Label(frame, text="Username:").pack(anchor="w")
    ttk.Entry(frame, textvariable=username_var).pack(fill="x", pady=(2, 10))

    ttk.Label(frame, text="Password:").pack(anchor="w")
    password_entry = ttk.Entry(frame, textvariable=password_var, show="*")
    password_entry.pack(fill="x", pady=(2, 2))
    ttk.Checkbutton(
        frame,
        text="Show password",
        variable=show_password_var,
        command=toggle_password_visibility,
    ).pack(anchor="w")
    ttk.Label(frame, textvariable=strength_var).pack(anchor="w", pady=(2, 10))

    buttons = ttk.Frame(frame)
    buttons.pack(pady=(0, 16))
    ttk.Button(buttons, text="Generate", command=generate_password).pack(side="left", padx=3)
    ttk.Button(buttons, text="Copy", command=copy_password).pack(side="left", padx=3)
    ttk.Button(buttons, text="Save to vault", command=save_entry).pack(side="left", padx=3)
    ttk.Button(buttons, text="Import browser CSV", command=import_browser_credentials).pack(
        side="left", padx=3
    )
    ttk.Button(buttons, text="Clear", command=clear_fields).pack(side="left", padx=3)

    ttk.Label(frame, text="Notes:").pack(anchor="w")
    notes_var = tk.Text(frame, height=3, wrap="word")
    notes_var.pack(fill="x", pady=(2, 10))

    ttk.Label(frame, text="Saved credentials:").pack(anchor="w")
    ttk.Label(frame, text="Search:").pack(anchor="w")
    search_entry = ttk.Entry(frame, textvariable=search_var)
    search_entry.pack(fill="x", pady=(4, 4))
    entries_list = tk.Listbox(frame, height=8)
    entries_list.pack(fill="x", pady=(0, 8))
    entries_list.bind("<<ListboxSelect>>", select_entry)
    ttk.Button(frame, text="Delete selected", command=delete_entry).pack()
    ttk.Button(frame, text="Vault health", command=show_vault_health).pack(pady=(6, 0))
    ttk.Button(frame, text="Lock vault now", command=lock_vault).pack(pady=(6, 0))
    ttk.Checkbutton(
        frame, text="Dark theme", variable=dark_theme_var, command=apply_theme
    ).pack(pady=(6, 0))
    ttk.Label(frame, textvariable=status_var).pack(pady=(14, 0))

    length_var.trace_add("write", update_length_label)
    password_var.trace_add("write", update_strength)
    search_var.trace_add("write", lambda *args: refresh_entries())
    refresh_entries()
    window.bind("<Return>", lambda event: generate_password())
    window.bind_all("<Any-KeyPress>", reset_inactivity_timer)
    window.bind_all("<Any-Button>", reset_inactivity_timer)
    window.bind_all("<Motion>", reset_inactivity_timer)
    window.bind("<Control-g>", lambda event: generate_password())
    window.bind("<Control-Shift-C>", lambda event: copy_password())
    window.bind("<Control-s>", lambda event: save_entry())
    window.bind("<Control-l>", lambda event: clear_fields())
    window.bind("<Control-f>", lambda event: search_entry.focus_set())
    window.bind("<Control-Shift-L>", lambda event: lock_vault())
    window.bind("<Escape>", lambda event: clear_fields())
    update_length_label()
    apply_theme()
    if first_run:
        show_welcome_screen()
    reset_inactivity_timer()
    window.mainloop()
