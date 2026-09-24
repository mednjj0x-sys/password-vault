# Password Generator and Vault

A desktop password generator and encrypted credential vault built with Python, Tkinter, and `cryptography`.

## Features

- Generate secure passwords with `secrets`
- Choose password length from 4 to 64 characters
- Choose lowercase letters, uppercase letters, numbers, and symbols independently
- Password strength indicator
- Show or hide the current password
- Copy passwords to the clipboard
- Import password exports from Chrome, Edge, Firefox, Brave, and other browsers using CSV
- Save service, username, password, and notes
- Edit existing credentials
- Prevent duplicate usernames for the same service
- Search credentials by service, username, or notes
- Sort saved credentials alphabetically
- Confirm before deleting credentials
- Light and dark themes
- Automatically lock the vault after 5 minutes of inactivity
- Local vault-health dashboard with a score
- Detect reused, weak, and older passwords
- Detect missing notes, missing service names, and repeated services
- Track password age for saved and imported credentials
- Encrypted local vault storage using Fernet and PBKDF2-HMAC-SHA256

## Requirements

- Python 3.10 or newer
- Tkinter
- `cryptography`

Tkinter is included with most Python installations. Install the encryption dependency with:

```powershell
python -m pip install cryptography
```

## Run the Application

From the project directory, run:

```powershell
python main.py
```

On first launch, create a master password. On later launches, use that password to unlock the vault.

## Import Browser Passwords

1. Export passwords from your browser as a CSV file.
2. Unlock this application.
3. Click **Import browser CSV** and select the exported file.

The importer supports common Chromium and Firefox export columns, including `name`, `url`, `origin`, `username`, `login`, `password`, and `notes`. Incomplete rows are ignored, and credentials with the same service and username are skipped as duplicates.

Delete the browser export CSV after importing it because it contains unencrypted passwords.

## Vault Health

Click **Vault health** to run a local security review. The report checks for reused passwords, weak passwords, passwords older than 180 days, missing notes or service names, and services with multiple accounts. New and imported credentials receive a password-change timestamp; credentials created by older versions of the application show an unknown age until they are updated.

The score is an at-a-glance guide, not a formal security guarantee. Password values are not displayed in the report.

## Keyboard Shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+G` | Generate a password |
| `Ctrl+Shift+C` | Copy the current password |
| `Ctrl+S` | Save or update a credential |
| `Ctrl+L` | Clear the fields |
| `Ctrl+F` | Focus the search field |
| `Ctrl+Shift+L` | Lock the vault |
| `Escape` | Clear the fields |

## Vault Storage

The application stores the encrypted vault in `vault.json` beside `main.py`. Credential data is encrypted before it is written to disk.

Keep the master password safe. It cannot be recovered if forgotten. Do not share `vault.json` or your master password with anyone.

## Project Structure

```text
password generator/
├── main.py
├── README.md
└── vault.json       # Created automatically after the vault is saved
```
