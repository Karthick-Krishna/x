// src/crypto.js

export class SecureCrypto {
    constructor() {
        this.algo = { name: 'AES-GCM', length: 256 };
    }

    // Generate a random IV
    static generateIV() {
        return window.crypto.getRandomValues(new Uint8Array(12));
    }

    // Generate a random Salt
    static generateSalt() {
        return window.crypto.getRandomValues(new Uint8Array(16));
    }

    // Generate a new AES key for file encryption
    static async generateKey() {
        return window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    // Derive a key from a password
    static async deriveKeyFromPassword(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256',
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true, // Exportable to wrap other keys? Actually usually false for derived keys but we need to use it.
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    // Encrypt data (Blob/Buffer) -> { iv, ciphertext }
    static async encryptData(key, data) {
        const iv = this.generateIV();
        // data must be ArrayBuffer
        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
        return { iv, ciphertext: encrypted };
    }

    // Decrypt data -> ArrayBuffer
    static async decryptData(key, iv, ciphertext) {
        return window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            ciphertext
        );
    }

    // Export key to raw format (for storage if needed, but better to wrap)
    static async exportKey(key) {
        return window.crypto.subtle.exportKey('raw', key);
    }

    // Import raw key
    static async importKey(raw) {
        return window.crypto.subtle.importKey(
            'raw',
            raw,
            { name: 'AES-GCM' },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    // Wrap a key (Target) with another key (Wrapper)
    static async wrapKey(targetKey, wrappingKey) {
        const iv = this.generateIV();
        const wrapped = await window.crypto.subtle.wrapKey(
            'raw',
            targetKey,
            wrappingKey,
            { name: 'AES-GCM', iv: iv }
        );
        return { iv, wrappedData: wrapped };
    }

    // Unwrap a key
    static async unwrapKey(wrappedData, wrappingKey, iv) {
        return window.crypto.subtle.unwrapKey(
            'raw',
            wrappedData,
            wrappingKey,
            { name: 'AES-GCM', iv: iv },
            { name: 'AES-GCM' },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // Helper: Get or Create Device Key (Stored in LocalStorage for persistence simulation)
    // In a real app, this would be in Secure Keystore.
    static async getDeviceKey() {
        const stored = localStorage.getItem('sv_device_key');
        let rawKey;
        if (stored) {
            // Decode base64
            const binary = atob(stored);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            rawKey = bytes.buffer;
        } else {
            // Generate new
            const key = await this.generateKey();
            rawKey = await this.exportKey(key);
            // Store as base64
            const bytes = new Uint8Array(rawKey);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
            localStorage.setItem('sv_device_key', btoa(binary));
        }
        return this.importKey(rawKey);
    }
}
