// src/db.js
const DB_NAME = 'SecureVaultDB';
const DB_VERSION = 1;
const STORE_NAME = 'files';

function openDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            }
        };

        request.onsuccess = (e) => resolve(e.target.result);
        request.onerror = (e) => reject(e.target.error);
    });
}

export const DB = {
    async saveFile(fileData) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            const request = store.put(fileData);

            request.onsuccess = () => resolve(fileData.id);
            request.onerror = () => reject(request.error);
        });
    },

    async getAllFiles() {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const request = store.openCursor();
            const files = [];

            request.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    // Destructure to exclude heavy content from memory listing
                    const { content, ...meta } = cursor.value;
                    files.push(meta);
                    cursor.continue();
                } else {
                    resolve(files);
                }
            };
            request.onerror = () => reject(request.error);
        });
    },

    async getFile(id) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const request = store.get(id);

            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    },

    async deleteFile(id) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            const request = store.delete(id);

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    async updateFile(fileData) {
        // Currently just overwrites using saveFile (put)
        return this.saveFile(fileData);
    }
};
