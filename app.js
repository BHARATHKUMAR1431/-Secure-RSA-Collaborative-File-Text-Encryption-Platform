// RSA Encryption Application with Key Import/Export
class RSAEncryptionApp {
    constructor() {
        this.currentUser = null;
        this.publicKey = null;
        this.privateKey = null;
        this.keySource = null; // 'generated' or 'imported'
        this.users = [
            {username: "admin", password: "password123", id: 1},
            {username: "user1", password: "pass456", id: 2}
        ];
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.showLoginSection();
    }

    bindEvents() {
        // Login/Logout - Fixed form submission handling
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        // Key Management
        const generateKeysBtn = document.getElementById('generateKeysBtn');
        if (generateKeysBtn) {
            generateKeysBtn.addEventListener('click', () => this.generateKeyPair());
        }
        
        const importPublicKeyBtn = document.getElementById('importPublicKeyBtn');
        if (importPublicKeyBtn) {
            importPublicKeyBtn.addEventListener('click', () => this.importPublicKey());
        }
        
        const importPrivateKeyBtn = document.getElementById('importPrivateKeyBtn');
        if (importPrivateKeyBtn) {
            importPrivateKeyBtn.addEventListener('click', () => this.importPrivateKey());
        }
        
        const clearKeysBtn = document.getElementById('clearKeysBtn');
        if (clearKeysBtn) {
            clearKeysBtn.addEventListener('click', () => this.clearKeys());
        }
        
        // Key Export
        const exportKeysBtn = document.getElementById('exportKeysBtn');
        if (exportKeysBtn) {
            exportKeysBtn.addEventListener('click', () => this.exportKeys());
        }
        
        const exportPublicKeyBtn = document.getElementById('exportPublicKeyBtn');
        if (exportPublicKeyBtn) {
            exportPublicKeyBtn.addEventListener('click', () => this.exportPublicKey());
        }
        
        const exportPrivateKeyBtn = document.getElementById('exportPrivateKeyBtn');
        if (exportPrivateKeyBtn) {
            exportPrivateKeyBtn.addEventListener('click', () => this.exportPrivateKey());
        }

        // File inputs
        const publicKeyFileInput = document.getElementById('publicKeyFileInput');
        if (publicKeyFileInput) {
            publicKeyFileInput.addEventListener('change', (e) => this.handlePublicKeyFile(e));
        }
        
        const privateKeyFileInput = document.getElementById('privateKeyFileInput');
        if (privateKeyFileInput) {
            privateKeyFileInput.addEventListener('change', (e) => this.handlePrivateKeyFile(e));
        }

        // Encryption/Decryption
        const encryptTextBtn = document.getElementById('encryptTextBtn');
        if (encryptTextBtn) {
            encryptTextBtn.addEventListener('click', () => this.encryptText());
        }
        
        const decryptTextBtn = document.getElementById('decryptTextBtn');
        if (decryptTextBtn) {
            decryptTextBtn.addEventListener('click', () => this.decryptText());
        }
        
        const encryptFileBtn = document.getElementById('encryptFileBtn');
        if (encryptFileBtn) {
            encryptFileBtn.addEventListener('click', () => this.encryptFile());
        }
        
        const decryptFileBtn = document.getElementById('decryptFileBtn');
        if (decryptFileBtn) {
            decryptFileBtn.addEventListener('click', () => this.decryptFile());
        }

        // Utility
        const copyEncryptedBtn = document.getElementById('copyEncryptedBtn');
        if (copyEncryptedBtn) {
            copyEncryptedBtn.addEventListener('click', () => this.copyToClipboard('encryptedText'));
        }
        
        const clearLogBtn = document.getElementById('clearLogBtn');
        if (clearLogBtn) {
            clearLogBtn.addEventListener('click', () => this.clearActivityLog());
        }

        // File inputs
        const fileToEncrypt = document.getElementById('fileToEncrypt');
        if (fileToEncrypt) {
            fileToEncrypt.addEventListener('change', (e) => this.handleFileSelection(e, 'encrypt'));
        }
        
        const fileToDecrypt = document.getElementById('fileToDecrypt');
        if (fileToDecrypt) {
            fileToDecrypt.addEventListener('change', (e) => this.handleFileSelection(e, 'decrypt'));
        }
    }

    showLoginSection() {
        const loginSection = document.getElementById('loginSection');
        const mainApp = document.getElementById('mainApp');
        
        if (loginSection) loginSection.classList.remove('hidden');
        if (mainApp) mainApp.classList.add('hidden');
    }

    showMainApp() {
        const loginSection = document.getElementById('loginSection');
        const mainApp = document.getElementById('mainApp');
        const currentUserSpan = document.getElementById('currentUser');
        
        if (loginSection) loginSection.classList.add('hidden');
        if (mainApp) mainApp.classList.remove('hidden');
        if (currentUserSpan) currentUserSpan.textContent = this.currentUser.username;
        
        this.updateKeyStatus();
    }

    handleLogin(e) {
        e.preventDefault();
        console.log('Login form submitted'); // Debug log
        
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');
        
        if (!usernameInput || !passwordInput) {
            console.error('Username or password input not found');
            return;
        }
        
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        
        console.log('Login attempt:', {username, password}); // Debug log

        const user = this.users.find(u => u.username === username && u.password === password);
        
        if (user) {
            this.currentUser = user;
            this.showMainApp();
            this.logActivity('User logged in successfully');
            this.showNotification('Login successful', 'Welcome back!', 'success');
            
            // Clear the form
            usernameInput.value = '';
            passwordInput.value = '';
        } else {
            console.log('Invalid credentials'); // Debug log
            this.showNotification('Login failed', 'Invalid username or password', 'error');
        }
    }

    handleLogout() {
        this.currentUser = null;
        this.publicKey = null;
        this.privateKey = null;
        this.keySource = null;
        
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.reset();
        }
        
        this.showLoginSection();
        this.logActivity('User logged out');
    }

    async generateKeyPair() {
        try {
            this.showLoading('generateKeysBtn');
            
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );

            this.publicKey = keyPair.publicKey;
            this.privateKey = keyPair.privateKey;
            this.keySource = 'generated';
            
            this.updateKeyStatus();
            this.logActivity('New RSA key pair generated successfully');
            this.showNotification('Keys Generated', 'New RSA key pair generated successfully', 'success');
            
        } catch (error) {
            console.error('Key generation error:', error);
            this.showNotification('Generation Failed', 'Failed to generate key pair: ' + error.message, 'error');
        } finally {
            this.hideLoading('generateKeysBtn');
        }
    }

    importPublicKey() {
        const fileInput = document.getElementById('publicKeyFileInput');
        if (fileInput) {
            fileInput.click();
        }
    }

    importPrivateKey() {
        const fileInput = document.getElementById('privateKeyFileInput');
        if (fileInput) {
            fileInput.click();
        }
    }

    async handlePublicKeyFile(e) {
        const file = e.target.files[0];
        if (!file) return;

        try {
            const pemContent = await this.readFileAsText(file);
            const publicKey = await this.importPEMKey(pemContent, 'public');
            
            this.publicKey = publicKey;
            if (!this.privateKey) {
                this.keySource = 'imported';
            }
            
            this.updateKeyStatus();
            this.logActivity(`Public key imported from ${file.name}`);
            this.showNotification('Import Successful', 'Public key imported successfully', 'success');
            
        } catch (error) {
            console.error('Public key import error:', error);
            this.showNotification('Import Failed', 'Failed to import public key: ' + error.message, 'error');
        }
        
        // Reset file input
        e.target.value = '';
    }

    async handlePrivateKeyFile(e) {
        const file = e.target.files[0];
        if (!file) return;

        try {
            const pemContent = await this.readFileAsText(file);
            const privateKey = await this.importPEMKey(pemContent, 'private');
            
            this.privateKey = privateKey;
            if (!this.publicKey) {
                this.keySource = 'imported';
            }
            
            this.updateKeyStatus();
            this.logActivity(`Private key imported from ${file.name}`);
            this.showNotification('Import Successful', 'Private key imported successfully', 'success');
            
        } catch (error) {
            console.error('Private key import error:', error);
            this.showNotification('Import Failed', 'Failed to import private key: ' + error.message, 'error');
        }
        
        // Reset file input
        e.target.value = '';
    }

    async importPEMKey(pemContent, keyType) {
        // Remove PEM headers and decode base64
        const pemHeader = keyType === 'public' ? '-----BEGIN PUBLIC KEY-----' : '-----BEGIN PRIVATE KEY-----';
        const pemFooter = keyType === 'public' ? '-----END PUBLIC KEY-----' : '-----END PRIVATE KEY-----';
        
        const pemBody = pemContent
            .replace(pemHeader, '')
            .replace(pemFooter, '')
            .replace(/\s/g, '');
        
        const binaryDer = this.base64ToArrayBuffer(pemBody);
        
        const keyUsage = keyType === 'public' ? ['encrypt'] : ['decrypt'];
        const keyFormat = 'spki'; // For public keys
        const privateKeyFormat = 'pkcs8'; // For private keys
        
        return await window.crypto.subtle.importKey(
            keyType === 'public' ? keyFormat : privateKeyFormat,
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            keyUsage
        );
    }

    clearKeys() {
        if (this.publicKey || this.privateKey) {
            const confirmed = confirm('Are you sure you want to clear all keys? This action cannot be undone.');
            if (confirmed) {
                this.publicKey = null;
                this.privateKey = null;
                this.keySource = null;
                this.updateKeyStatus();
                this.logActivity('All keys cleared');
                this.showNotification('Keys Cleared', 'All keys have been cleared', 'info');
            }
        }
    }

    async exportKeys() {
        if (!this.publicKey && !this.privateKey) {
            this.showNotification('No Keys', 'No keys available to export', 'warning');
            return;
        }

        try {
            const exports = [];
            
            if (this.publicKey) {
                const publicKeyPEM = await this.exportKeyToPEM(this.publicKey, 'public');
                exports.push({name: 'public_key.pem', content: publicKeyPEM});
            }
            
            if (this.privateKey) {
                const privateKeyPEM = await this.exportKeyToPEM(this.privateKey, 'private');
                exports.push({name: 'private_key.pem', content: privateKeyPEM});
            }

            exports.forEach(({name, content}) => {
                this.downloadFile(content, name, 'text/plain');
            });
            
            this.logActivity(`Exported ${exports.length} key(s)`);
            this.showNotification('Export Successful', `Exported ${exports.length} key file(s)`, 'success');
            
        } catch (error) {
            console.error('Key export error:', error);
            this.showNotification('Export Failed', 'Failed to export keys: ' + error.message, 'error');
        }
    }

    async exportPublicKey() {
        if (!this.publicKey) {
            this.showNotification('No Public Key', 'No public key available to export', 'warning');
            return;
        }

        try {
            const publicKeyPEM = await this.exportKeyToPEM(this.publicKey, 'public');
            this.downloadFile(publicKeyPEM, 'public_key.pem', 'text/plain');
            this.logActivity('Public key exported');
            this.showNotification('Export Successful', 'Public key exported successfully', 'success');
        } catch (error) {
            console.error('Public key export error:', error);
            this.showNotification('Export Failed', 'Failed to export public key: ' + error.message, 'error');
        }
    }

    async exportPrivateKey() {
        if (!this.privateKey) {
            this.showNotification('No Private Key', 'No private key available to export', 'warning');
            return;
        }

        // Show security warning
        const confirmed = confirm('⚠️ Security Warning!\n\nExporting private keys is dangerous and should only be done when necessary for sharing decryption capabilities.\n\nNever share private keys unless absolutely required!\n\nContinue with export?');
        
        if (!confirmed) return;

        try {
            const privateKeyPEM = await this.exportKeyToPEM(this.privateKey, 'private');
            this.downloadFile(privateKeyPEM, 'private_key.pem', 'text/plain');
            this.logActivity('⚠️ Private key exported');
            this.showNotification('Export Successful', 'Private key exported (handle with care!)', 'warning');
        } catch (error) {
            console.error('Private key export error:', error);
            this.showNotification('Export Failed', 'Failed to export private key: ' + error.message, 'error');
        }
    }

    async exportKeyToPEM(key, keyType) {
        const exported = await window.crypto.subtle.exportKey(
            keyType === 'public' ? 'spki' : 'pkcs8',
            key
        );
        
        const exportedAsBase64 = this.arrayBufferToBase64(exported);
        const pemHeader = keyType === 'public' ? '-----BEGIN PUBLIC KEY-----' : '-----BEGIN PRIVATE KEY-----';
        const pemFooter = keyType === 'public' ? '-----END PUBLIC KEY-----' : '-----END PRIVATE KEY-----';
        
        // Format base64 with line breaks
        const pemBody = exportedAsBase64.match(/.{1,64}/g).join('\n');
        
        return `${pemHeader}\n${pemBody}\n${pemFooter}`;
    }

    async encryptText() {
        const plaintextElement = document.getElementById('plaintext');
        if (!plaintextElement) return;
        
        const plaintext = plaintextElement.value.trim();
        
        if (!plaintext) {
            this.showNotification('No Text', 'Please enter text to encrypt', 'warning');
            return;
        }
        
        if (!this.publicKey) {
            this.showNotification('No Public Key', 'Please generate keys or import a public key first', 'error');
            return;
        }

        try {
            this.showLoading('encryptTextBtn');
            
            const encodedText = new TextEncoder().encode(plaintext);
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                this.publicKey,
                encodedText
            );

            const encryptedBase64 = this.arrayBufferToBase64(encrypted);
            const encryptedTextElement = document.getElementById('encryptedText');
            const copyBtn = document.getElementById('copyEncryptedBtn');
            
            if (encryptedTextElement) {
                encryptedTextElement.value = encryptedBase64;
            }
            
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            
            this.logActivity(`Text encrypted (${plaintext.length} characters)`);
            this.showNotification('Encryption Successful', 'Text encrypted successfully', 'success');
            
        } catch (error) {
            console.error('Encryption error:', error);
            this.showNotification('Encryption Failed', 'Failed to encrypt text: ' + error.message, 'error');
        } finally {
            this.hideLoading('encryptTextBtn');
        }
    }

    async decryptText() {
        const ciphertextElement = document.getElementById('ciphertext');
        if (!ciphertextElement) return;
        
        const ciphertext = ciphertextElement.value.trim();
        
        if (!ciphertext) {
            this.showNotification('No Ciphertext', 'Please enter encrypted text to decrypt', 'warning');
            return;
        }
        
        if (!this.privateKey) {
            this.showNotification('No Private Key', 'Please generate keys or import a private key first', 'error');
            return;
        }

        try {
            this.showLoading('decryptTextBtn');
            
            const encryptedData = this.base64ToArrayBuffer(ciphertext);
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                this.privateKey,
                encryptedData
            );

            const decryptedText = new TextDecoder().decode(decrypted);
            const decryptedTextElement = document.getElementById('decryptedText');
            
            if (decryptedTextElement) {
                decryptedTextElement.value = decryptedText;
            }
            
            this.logActivity(`Text decrypted (${decryptedText.length} characters)`);
            this.showNotification('Decryption Successful', 'Text decrypted successfully', 'success');
            
        } catch (error) {
            console.error('Decryption error:', error);
            this.showNotification('Decryption Failed', 'Failed to decrypt text. Please check the encrypted text and ensure you have the correct private key.', 'error');
        } finally {
            this.hideLoading('decryptTextBtn');
        }
    }

    async encryptFile() {
        const fileInput = document.getElementById('fileToEncrypt');
        if (!fileInput) return;
        
        const file = fileInput.files[0];
        
        if (!file) {
            this.showNotification('No File', 'Please select a file to encrypt', 'warning');
            return;
        }
        
        if (!this.publicKey) {
            this.showNotification('No Public Key', 'Please generate keys or import a public key first', 'error');
            return;
        }

        try {
            this.showLoading('encryptFileBtn');
            
            const fileContent = await this.readFileAsArrayBuffer(file);
            
            // For large files, we would need to implement hybrid encryption
            // For demo purposes, limiting file size for direct RSA encryption
            if (fileContent.byteLength > 190) { // RSA-OAEP with SHA-256 can encrypt up to 190 bytes
                throw new Error('File too large for direct RSA encryption. Use hybrid encryption for larger files.');
            }
            
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                this.publicKey,
                fileContent
            );

            const encryptedBase64 = this.arrayBufferToBase64(encrypted);
            const encryptedFileName = `${file.name}.encrypted`;
            
            // Store for download
            this.encryptedFileData = {
                content: encryptedBase64,
                name: encryptedFileName
            };
            
            const resultElement = document.getElementById('encryptedFileResult');
            const downloadBtn = document.getElementById('downloadEncryptedBtn');
            
            if (resultElement) {
                resultElement.classList.remove('hidden');
            }
            
            if (downloadBtn) {
                downloadBtn.onclick = () => {
                    this.downloadFile(encryptedBase64, encryptedFileName, 'text/plain');
                };
            }
            
            this.logActivity(`File encrypted: ${file.name} (${file.size} bytes)`);
            this.showNotification('File Encrypted', 'File encrypted successfully', 'success');
            
        } catch (error) {
            console.error('File encryption error:', error);
            this.showNotification('Encryption Failed', 'Failed to encrypt file: ' + error.message, 'error');
        } finally {
            this.hideLoading('encryptFileBtn');
        }
    }

    async decryptFile() {
        const fileInput = document.getElementById('fileToDecrypt');
        if (!fileInput) return;
        
        const file = fileInput.files[0];
        
        if (!file) {
            this.showNotification('No File', 'Please select an encrypted file to decrypt', 'warning');
            return;
        }
        
        if (!this.privateKey) {
            this.showNotification('No Private Key', 'Please generate keys or import a private key first', 'error');
            return;
        }

        try {
            this.showLoading('decryptFileBtn');
            
            const encryptedContent = await this.readFileAsText(file);
            const encryptedData = this.base64ToArrayBuffer(encryptedContent.trim());
            
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                this.privateKey,
                encryptedData
            );

            const originalFileName = file.name.replace('.encrypted', '');
            
            // Store for download
            this.decryptedFileData = {
                content: decrypted,
                name: originalFileName
            };
            
            const resultElement = document.getElementById('decryptedFileResult');
            const downloadBtn = document.getElementById('downloadDecryptedBtn');
            
            if (resultElement) {
                resultElement.classList.remove('hidden');
            }
            
            if (downloadBtn) {
                downloadBtn.onclick = () => {
                    this.downloadFile(decrypted, originalFileName, 'application/octet-stream');
                };
            }
            
            this.logActivity(`File decrypted: ${originalFileName}`);
            this.showNotification('File Decrypted', 'File decrypted successfully', 'success');
            
        } catch (error) {
            console.error('File decryption error:', error);
            this.showNotification('Decryption Failed', 'Failed to decrypt file. Please check the file and ensure you have the correct private key.', 'error');
        } finally {
            this.hideLoading('decryptFileBtn');
        }
    }

    updateKeyStatus() {
        const statusElement = document.getElementById('keyStatus');
        const sourceElement = document.getElementById('keySource');
        const exportButtons = ['exportKeysBtn', 'exportPublicKeyBtn', 'exportPrivateKeyBtn'];
        
        if (!statusElement || !sourceElement) return;
        
        if (this.publicKey || this.privateKey) {
            let statusText = 'Keys Ready';
            let statusClass = 'status--ready';
            
            if (this.keySource === 'imported') {
                statusText = 'Keys Imported';
                statusClass = 'status--imported';
            }
            
            statusElement.textContent = statusText;
            statusElement.className = `status ${statusClass}`;
            
            const keyTypes = [];
            if (this.publicKey) keyTypes.push('Public');
            if (this.privateKey) keyTypes.push('Private');
            
            sourceElement.innerHTML = `<span class="key-source-badge key-source-badge--${this.keySource}">${keyTypes.join(' + ')} (${this.keySource})</span>`;
            
            // Enable export buttons
            exportButtons.forEach(btnId => {
                const btn = document.getElementById(btnId);
                if (btn) btn.disabled = false;
            });
            
        } else {
            statusElement.textContent = 'No Keys';
            statusElement.className = 'status status--info';
            sourceElement.textContent = '-';
            
            // Disable export buttons
            exportButtons.forEach(btnId => {
                const btn = document.getElementById(btnId);
                if (btn) btn.disabled = true;
            });
        }
    }

    // Utility Methods
    async readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsText(file);
        });
    }

    async readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsArrayBuffer(file);
        });
    }

    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    downloadFile(content, filename, mimeType) {
        const blob = content instanceof ArrayBuffer ? new Blob([content], {type: mimeType}) : new Blob([content], {type: mimeType});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const text = element.value;
        
        if (!text) {
            this.showNotification('Nothing to Copy', 'No text available to copy', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(text);
            const copyBtn = document.getElementById('copyEncryptedBtn');
            
            if (copyBtn) {
                const originalText = copyBtn.textContent;
                
                copyBtn.textContent = 'Copied!';
                copyBtn.classList.add('copy-success');
                
                setTimeout(() => {
                    copyBtn.textContent = originalText;
                    copyBtn.classList.remove('copy-success');
                }, 2000);
            }
            
            this.showNotification('Copied', 'Text copied to clipboard', 'success');
        } catch (error) {
            console.error('Copy error:', error);
            this.showNotification('Copy Failed', 'Failed to copy to clipboard', 'error');
        }
    }

    logActivity(message) {
        const logElement = document.getElementById('activityLog');
        if (!logElement) return;
        
        const timestamp = new Date().toLocaleTimeString();
        
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.innerHTML = `
            <span class="log-message">${message}</span>
            <span class="log-timestamp">${timestamp}</span>
        `;
        
        logElement.insertBefore(logEntry, logElement.firstChild);
        
        // Keep only last 50 entries
        while (logElement.children.length > 50) {
            logElement.removeChild(logElement.lastChild);
        }
    }

    clearActivityLog() {
        const logElement = document.getElementById('activityLog');
        if (logElement) {
            logElement.innerHTML = '<div class="log-empty">Activity log cleared</div>';
            this.logActivity('Activity log cleared');
        }
    }

    showNotification(title, message, type = 'info') {
        const container = document.getElementById('notifications');
        if (!container) return;
        
        const notification = document.createElement('div');
        notification.className = `notification notification--${type}`;
        
        notification.innerHTML = `
            <button class="notification__close">&times;</button>
            <div class="notification__title">${title}</div>
            <div class="notification__message">${message}</div>
        `;
        
        container.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
        
        // Close button
        const closeBtn = notification.querySelector('.notification__close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            });
        }
    }

    showLoading(buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.classList.add('loading');
            button.disabled = true;
        }
    }

    hideLoading(buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.classList.remove('loading');
            button.disabled = false;
        }
    }

    handleFileSelection(e, operation) {
        const file = e.target.files[0];
        if (file && operation === 'encrypt') {
            const resultElement = document.getElementById('encryptedFileResult');
            if (resultElement) {
                resultElement.classList.add('hidden');
            }
        } else if (file && operation === 'decrypt') {
            const resultElement = document.getElementById('decryptedFileResult');
            if (resultElement) {
                resultElement.classList.add('hidden');
            }
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.rsaApp = new RSAEncryptionApp();
});