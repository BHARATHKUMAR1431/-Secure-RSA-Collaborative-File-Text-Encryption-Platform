# 🔐 Secure RSA Collaborative File/Text Encryption Platform

A **single-page web app (SPA)** that implements full RSA cryptography + a user authentication system, supporting both **file and text encryption/decryption**, with activity auditing and downloadable keys.  
Built purely with **HTML**, **CSS**, and **JavaScript**, no external dependencies. Ideal for learning and demonstration in cybersecurity.

---

## 📦 Features

### 🛡️ Authentication System  
- User **login / registration**  
- JWT-style session persistence stored in `localStorage`  
- Redirect to login when not authenticated  
- Predefined sample users:  
  - `admin / password123`  
  - `user1 / pass456`  

### 🧮 RSA Cryptography  
- RSA-2048 key pair generation via the **Web Crypto API**  
- Export public/private keys in `.pem` format  
- Text encryption & decryption  
- File encryption & decryption (any file type & size)  
- Base64 encoding/decoding for safe transport  

### 🖥️ UI / UX  
- Responsive, modern design  
- Tabbed dashboard: Key Generation, Encrypt, Decrypt, Log  
- Drag & drop file upload  
- Download encrypted / decrypted files  
- Activity log with timestamps  
- Notifications (success / error)  

### 🧾 Security & Auditing  
- Logs of all operations (key gen, encrypt, decrypt)  
- Timestamps for auditing  
- Input validation, sanitization, and error handling  
- All crypto operations run **locally in browser**  

---
1. Clone or download the repo:  
   ```bash
   git clone https://github.com/BHARATHKUMAR1431/Secure-RSA-Collaborative-File-Text-Encryption-Platform.git
   ```




