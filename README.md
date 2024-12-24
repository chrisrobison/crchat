# 🚀 CR Chat: Real-time WebSocket Chat

A modern, secure WebSocket and WebWorker based chat application with support for rich media sharing, user profiles, and real-time updates.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D%2016.0.0-brightgreen)
![WebSocket](https://img.shields.io/badge/WebSocket-Enabled-brightgreen)

## ✨ Features

- **🔐 Secure WebSocket Communication**
  - SSL/TLS encryption
  - Secure message handling
  - Automatic reconnection with exponential backoff

- **👥 User Management**
  - User profiles with avatars
  - Real-time online user list
  - Join/leave notifications

- **💬 Rich Message Support**
  - Text messages
  - Image sharing with paste support
  - File uploads with mime-type detection
  - Embedded video player for video files
  - Message history persistence

- **🎨 Modern UI**
  - Dark theme
  - Responsive design
  - Clean, minimalist interface
  - Real-time typing indicators
  - Message timestamps
  - User avatars

## 🛠️ Technical Stack

- **Backend**
  - Node.js
  - Express
  - ws (WebSocket library)
  - multer (file uploads)

- **Frontend**
  - Vanilla JavaScript
  - WebSocket API
  - Web Workers
  - CSS3 with custom properties

## 📋 Prerequisites

- Node.js >= 16.0.0
- SSL/TLS certificates (Let's Encrypt recommended)
- Modern web browser with WebSocket support

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/websocket-chat.git
cd websocket-chat
```

2. Install dependencies:
```bash
npm install
```

3. Set up SSL certificates:
```bash
# Using Let's Encrypt
certbot certonly --webroot -w /var/www/html -d yourdomain.com
```

4. Create required directories:
```bash
mkdir uploads
chmod 755 uploads
```

5. Configure the application:
```javascript
// Update certPath in server.js
const certPath = '/etc/letsencrypt/live/yourdomain.com';
```

6. Start the server:
```bash
node server.js
```

## 🔧 Configuration

### SSL/TLS Certificates
The application requires valid SSL/TLS certificates. Update the `certPath` in `server.js`:

```javascript
const certPath = '/path/to/your/certificates';
const credentials = {
    cert: fs.readFileSync(path.join(certPath, 'fullchain.pem')),
    key: fs.readFileSync(path.join(certPath, 'privkey.pem')),
    ca: fs.readFileSync(path.join(certPath, 'chain.pem'))
};
```

### Port Configuration
Default port is 3210. Change it using the PORT environment variable:
```bash
PORT=8080 node server.js
```

## 💻 Usage

1. Access the chat application through your browser: `https://yourdomain.com:3000`
2. Enter your username when prompted
3. Start chatting!

### Sharing Files
- **Images**: Paste directly from clipboard
- **Files**: Paste any file to upload and share
- **Videos**: Paste video files for embedded playback

## 🔒 Security Features

- SSL/TLS encryption for all communications
- Secure WebSocket connection (WSS)
- File upload validation and sanitization
- Automatic connection recovery
- Input sanitization

## 📝 API Documentation

### WebSocket Messages

Messages follow this format:
```javascript
{
    type: 'chat|system|users|join',
    content: String|Object,
    timestamp: ISOString,
    username?: String,
    messageType?: 'text|image|file'
}
```

### REST Endpoints

- `GET /health` - Server health check
- `GET /api/chat/history` - Get chat history
- `POST /upload` - File upload endpoint

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a pull request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Node.js community
- ws WebSocket library
- All contributors

## 📞 Support

For support, email support@yourdomain.com or open an issue in the GitHub repository.

---
Made with ❤️ by [Your Name]
