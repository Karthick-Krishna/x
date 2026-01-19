# SecureVault 🔒

SecureVault is a local-only, offline-first secure file protection application designed for Android (via PWA/Web capabilities). It protects PDF, image, audio, and video files using client-side AES-256-GCM encryption.

## 🛡️ Security Architecture

### 1. Encryption Engine
- **Algorithm**: AES-256-GCM (Galois/Counter Mode).
- **Key Generation**: Unique keys generated per file using `window.crypto.subtle`.
- **Key Storage**: Keys are never stored in plaintext. They are wrapped (encrypted) using:
  - **User Password**: Derived via PBKDF2 (SHA-256, 100k iterations).
  - **Device Key**: A unique device-bound key (simulated via secure local storage) to allow strict persistent access.

### 2. Access Control Modes
- **Persistent Access**: Unlocks permanently on the device after the first password entry. Uses the Device Key to unwrap encryption keys seamlessly.
- **Always Ask**: Requires the user's password for every viewing session. Keys are only unwrapped in memory.
- **View Once (Self-Destruct)**: 
  - File decrypts *once* for viewing.
  - Upon closing the viewer or app termination, the file record and its keys are permanently deleted from the database.
  - **Crash Guard**: If the app crashes while viewing a self-destruct file, the app detects this on the next launch and completes the deletion.

### 3. Privacy & Anti-Tamper
- **In-Memory Decryption**: Files are decrypted directly into memory (`Blob` URLs) and never written to disk in decrypted form.
- **Memory Clearing**: `URL.revokeObjectURL` and DOM clearing are used to minimize memory footprint after viewing.
- **Privacy Curtain**: The app obscures content immediately when the window loses focus or goes to the background.
- **Context Protection**: Right-click context menus are disabled to discourage casual saving.

## 🚀 Getting Started

### Prerequisites
- Node.js installed.
- Modern Browser (Chrome/Edge/Firefox) supporting Web Crypto API.

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

3. Open `http://localhost:5173` in your browser.

## 📂 Project Structure

- **src/crypto.js**: Core cryptographic primitives (Encrypt, Decrypt, Key Wrap/Unwrap, PBKDF2).
- **src/db.js**: IndexedDB wrapper for binary storage.
- **src/main.js**: Main application logic, state management, and security event handling.
- **src/style.css**: Dark-mode, privacy-focused UI styling.

## ⚠️ Important Notes
- This is a local-only application. If you clear your browser data (IndexedDB), **all secured files will be lost** as there is no cloud backup.
- "View Once" is destructive. Once opened, the file is gone forever.
