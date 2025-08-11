# au_enc - Personal Password Manager

A simple command-line password manager that gives you complete control over your passwords and credentials.

## Features

- 🔐 **Local storage**: All data is stored locally in encrypted `.auenc` files
- 🔒 **Strong encryption**: Uses AES-256-GCM encryption with Argon2id key derivation
- 🛡️ **Master password protection**: Each vault is protected by a master password
- 📁 **Multiple vaults**: Create separate vault files for different purposes
- 💻 **Interactive CLI**: User-friendly command-line interface

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
4. Customize the `.env` file with your preferred settings (see Configuration section)

## Security Notes

- The `.env` file contains sensitive configuration and should never be committed to version control
- Vault files (`.auenc`) are encrypted but should be kept secure
- Use strong master passwords for your vaults
- Consider backing up your vault files securely

## License

ISC
