// Web Worker for handling WebSocket connection
const workerCode = `
    let ws;
    let reconnectAttempts = 0;
    const MAX_RECONNECT_DELAY = 5000;

    function connect(url) {
        ws = new WebSocket(url);

        ws.onopen = () => {
            reconnectAttempts = 0;
            postMessage({ type: 'connected' });
        };

        ws.onmessage = (event) => {
            postMessage({ type: 'message', data: JSON.parse(event.data) });
        };

        ws.onclose = () => {
            postMessage({ type: 'disconnected' });
            const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), MAX_RECONNECT_DELAY);
            reconnectAttempts++;
            setTimeout(() => connect(url), delay);
        };
    }

    self.onmessage = (event) => {
        const { type, data } = event.data;

        switch(type) {
            case 'connect':
                connect(data.url);
                break;
            case 'send':
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify(data.message));
                }
                break;
        }
    };
`;

(function() {
    const $ = str => document.querySelector(str);
    const $$ = str => document.querySelectorAll(str);

    const app = {
        data: {
            messages: [],
            users: [],
            username: '',
            connected: false
        },
        state: {
            loaded: false,
            identified: false
        },
        worker: null,
        async init() {
            // Try to restore username from localStorage
            let savedUsername = localStorage.getItem('chatUsername') || profile.Login;
            if (savedUsername) {
                app.data.username = savedUsername;
                app.data.me = savedUsername;
                $('#usernameModal').style.display = 'none';
            }

            // Create Web Worker from blob
            const blob = new Blob([workerCode], { type: 'application/javascript' });
            const workerUrl = URL.createObjectURL(blob);
            app.worker = new Worker(workerUrl);

            app.worker.onmessage = (event) => {
                const { type, data } = event.data;
                switch(type) {
                    case 'connected':
                        app.data.connected = true;
                        app.updateConnectionStatus('Connected');
                        // Re-identify if we have a username
                        if (app.data.username && !app.state.identified) {
                            app.identify();
                        }
                        break;
                    case 'disconnected':
                        app.data.connected = false;
                        app.state.identified = false;
                        app.updateConnectionStatus('Disconnected - Reconnecting...');
                        break;
                    case 'message':
                        app.receiveMessage(data);
                        break;
                }
            };

            $('#sendButton').addEventListener('click', () => app.sendMessage());
            $('#messageInput').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') app.sendMessage();
            });
            $('#joinButton').addEventListener('click', () => app.join());
            document.addEventListener('paste', (e) => app.handlePaste(e));

            // Initial connection
            app.connect();
            app.join(app.data.username);
            app.state.loaded = true;
        },
        async handlePaste(e) {
            const items = (e.clipboardData || e.originalEvent.clipboardData).items;
            
            for (const item of items) {
                // Skip text content
                if (item.type.startsWith('text/')) continue;
                
                e.preventDefault();
                $('#pasteIndicator').style.display = 'block';
                
                try {
                    const blob = item.getAsFile();
                    if (!blob) continue;
                    
                    if (item.type.startsWith('image/')) {
                        // Handle images as before
                        if (item.type === 'image/gif') {
                            await app.processAndSendFile(blob);
                        } else {
                            app.processImage(blob);
                        }
                    } else {
                        // Handle other file types
                        await app.processAndSendFile(blob);
                    }
                } catch (error) {
                    console.error('Error processing pasted content:', error);
                } finally {
                    $('#pasteIndicator').style.display = 'none';
                }
            }
        },

        async processAndSendFile(blob) {
            try {
                const formData = new FormData();
                formData.append('file', blob);
                
                const response = await fetch('https://cdr2.com/crchat/upload?user='+app.data.username, {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) throw new Error('Upload failed');
                
                const fileInfo = await response.json();
                
                // Send message with file information
                if (app.data.connected && app.state.identified) {
                    let messageContent;
                    
                    if (fileInfo.mimetype.startsWith('video/')) {
                        messageContent = `
                            <video controls width="100%" muted loop autoplay>
                                <source src="${fileInfo.url}" type="${fileInfo.mimetype}">
                                Your browser does not support the video tag.
                            </video>
                        `;
                    } else if (fileInfo.mimetype.startsWith('image/')) {
                        messageContent = `
                            <div class="chat-image">
                                <img src="${fileInfo.url}" class="chat-image" alt="${fileInfo.filename}">
                            </div>
                        `;
                    } else {
                        const iconUrl = `/img/mimetypes/${fileInfo.mimetype.replace('/', '-')}.png`;
                        messageContent = `
                            <div class="file-attachment">
                                <img src="${iconUrl}" class="file-icon" alt="${fileInfo.mimetype}">
                                <a href="${fileInfo.url}" target="_blank">${fileInfo.filename}</a>
                                <span class="file-size">(${app.formatFileSize(fileInfo.size)})</span>
                            </div>
                        `;
                    }
                    
                    const messageData = {
                        type: 'chat',
                        messageType: 'file',
                        username: app.data.username,
                        content: messageContent,
                        fileInfo: {
                            url: fileInfo.url,
                            mimetype: fileInfo.mimetype,
                            size: fileInfo.size
                        },
                        timestamp: new Date().toISOString()
                    };
                    
                    app.worker.postMessage({
                        type: 'send',
                        data: { message: messageData }
                    });
                }
            } catch (error) {
                console.error('Error uploading file:', error);
            }
        },

        formatFileSize(bytes) {
            const units = ['B', 'KB', 'MB', 'GB'];
            let size = bytes;
            let unitIndex = 0;
            
            while (size >= 1024 && unitIndex < units.length - 1) {
                size /= 1024;
                unitIndex++;
            }
            
            return `${size.toFixed(1)} ${units[unitIndex]}`;
        },
        processImage(blob) {
            // Check for GIF
            if (blob.type === 'image/gif') {
                // For GIFs, use FileReader directly to preserve animation
                const reader = new FileReader();
                reader.onload = (e) => {
                    const base64Data = e.target.result; // This will be the full animated GIF
                    app.sendImage(base64Data);
                    $('#pasteIndicator').style.display = 'none';
                };
                reader.readAsDataURL(blob);
                return;
            }

            // For non-GIF images, continue with canvas processing
            const img = new Image();
            const url = URL.createObjectURL(blob);

            img.onload = () => {
                // Create canvas
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');

                // Calculate dimensions (optionally resize large images)
                let width = img.width;
                let height = img.height;
                const maxDimension = 1200;

                if (width > maxDimension || height > maxDimension) {
                    if (width > height) {
                        height = (height / width) * maxDimension;
                        width = maxDimension;
                    } else {
                        width = (width / height) * maxDimension;
                        height = maxDimension;
                    }
                }

                // Set canvas size and draw image
                canvas.width = width;
                canvas.height = height;
                ctx.drawImage(img, 0, 0, width, height);

                // Convert to base64
                const base64Data = canvas.toDataURL('image/jpeg', 0.85);

                // Clean up
                URL.revokeObjectURL(url);

                // Send the image
                app.sendImage(base64Data);

                // Hide processing indicator
                $('#pasteIndicator').style.display = 'none';
            };

            img.src = url;
        },
        sendImage(base64Data) {
            if (app.data.connected && app.state.identified) {
                const messageData = {
                    type: 'chat',
                    messageType: 'image',
                    username: app.data.username,
                    content: base64Data,
                    timestamp: new Date().toISOString()
                };

                app.worker.postMessage({
                    type: 'send',
                    data: { message: messageData }
                });
            }
        },
        async getUserProfile(user) {
            if (app.data.users[user]) return app.data.users[user];
            let resp = await fetch(`/portal/api.php?type=loginProfile&user=${user}`);
            let profile = await resp.json();

            if (profile.status && profile.status==="error") {
                if (profile.redirect) {
                    document.location.href = profile.redirect + '?url=/chat/';
                }
            } else {
                app.data.users[user] = profile;
            }
            return profile;
        },
       connect() {
            app.worker.postMessage({
                type: 'connect',
                data: { url: 'wss://cdr2.com:3210' }
            });
        },
        updateConnectionStatus(status) {
            const statusDiv = $('#connectionStatus');
            statusDiv.textContent = '';
            statusDiv.className = 'connection-status ' +
                (status === 'Connected' ? 'connected' : 'disconnected');
        },
        identify() {
            app.worker.postMessage({
                type: 'send',
                data: {
                    message: {
                        type: 'join',
                        username: app.data.username,
                        timestamp: new Date().toISOString()
                    }
                }
            });
            app.state.identified = true;
        },
        join(user) {
            let username;
            if (user) {
                username = user;
            } else {
                username = $('#usernameInput').value.trim();
            }
            if (username) {
                app.data.username = username;
                localStorage.setItem('chatUsername', username);
                $('#usernameModal').style.display = 'none';

                if (app.data.connected) {
                    app.identify();
                }
            }
        },
        sendTyping() {
            const input = $("#messageInput");
            if (input.value.trim() && app.data.connected && app.state.identified) {
                const messageData = {
                    type: 'status',
                    username: app.data.username,
                    content: 'typing',
                    timesteamp: new Date().toISOString()
                };
                app.worker.postMessage({
                    type: 'send',
                    data: { message: messageData }
                });
            }
        },
        sendMessage() {
            const input = $('#messageInput');
            const message = input.value.trim();

            if (message && app.data.connected && app.state.identified) {
                const messageData = {
                    type: 'chat',
                    username: app.data.username,
                    content: message,
                    timestamp: new Date().toISOString()
                };

                app.worker.postMessage({
                    type: 'send',
                    data: { message: messageData }
                });

                input.value = '';
            }
        },
        updateUserList(users) {
            const usersList = $('#usersList');
            usersList.innerHTML = '';
            let seen = [];

            users.sort().forEach(async username => {
                if (!seen[username]) {
                    const userDiv = document.createElement('div');
                    userDiv.className = 'user-item';

                    // Get or fetch user profile
                    if (!app.data.users[username]) {
                        app.data.users[username] = await app.getUserProfile(username);
                    }
                    const profile = app.data.users[username];

                    userDiv.innerHTML = `
                        ${profile.Picture ? `<img class="profilepic" src="${profile.Picture}">` : ''}
                        <span class="username">${username}</span>
                    `;

                    usersList.appendChild(userDiv);
                    seen[username] = 1;
                }
            });
        },
        async receiveMessage(message, historical=false) {
            if (message.type === 'users') {
                app.updateUserList(message.content);
            } else if (message.type === 'history') {
                // Load historical messages
                message.content.sort((a, b) => {
                    const atime = new Date(a.timestamp);
                    const btime = new Date(b.timestamp);
                    if ( atime > btime) {
                        return 1;
                    } else if ( atime < btime) {
                        return -1;
                    } else {
                        return 0;
                    }
                });
                for (let i=0; i<message.content.length; i++) {
                    await app.receiveMessage(message.content[i], true);
                }
            } else if (message.type === 'system') {
                if (!historical) {
                    if ((message.messageType === "status") && (message.content === 'typing')) {
                        app.showTyping(message.username);
                    } else {
                        await app.displayMessage(message, 'system');
                        app.data.messages.push(message);
                    }
                }
            } else {
                await app.displayMessage(message);
                app.data.messages.push(message);
            }
        },
        async showTyping(user) {
            const fakemsg = {
                username: user,
                content: `<span class="jumping-dots">
                              <span class="dot-1"></span>
                              <span class="dot-2"></span>
                              <span class="dot-3"></span>
                          </span>`,
                timestamp: new Date().toISOString()
            };

            if (!$(`.typing.${user}`)) {
                await app.displayMessage(fakemsg, `typing ${user}`);
            }
        },
        async displayMessage(message, msgtype) {
            const messagesDiv = $('#messages');

            let tpl = `
    <div class="message-user">
        <div class="message-avatar">%%Picture%%</div>
        <div class="message-user">%%Login%%</div>
    </div>
    <div class="message%%mine%%">
        <div class="message-content">%%Message%%</div>
    </div>
    <div class="message-timestamp">%%ShowDate%%</div>`;
            if (!app.data.users[message.username]) {
                app.data.users[message.username] = await app.getUserProfile(message.username);
            }

            let msg = message;
            msg.Picture = (app.data.users[message.username].Picture) ? `<img class="profilepic" width="32" src="${app.data.users[message.username].Picture}">` : '';
            msg.Login = message.username;
            msg.mine = (message.username == app.data.me.Login) ? ' mine' : '';
            msg.Message = message.content;

            if (message.messageType === 'image') {
                msg.Message = `
                    <img src="${message.content}" alt="Shared image">
                `;
            }
            let msgdate = new Date(message.timestamp);
            msg.ShowDate =  app.cleanDate(msgdate);

            let html = tpl.replace(/%%(.+?)%%/g, function(m, p1) {
                if (msg[p1]) {
                    return msg[p1];
                } else {
                    return '';
                }
            });
            const messageWrap = document.createElement('div');

            let msgclass = ['message-wrap'];
            if (msg.mine) msgclass.push(msg.mine.trim());
            if (msgtype) msgclass.push(msgtype.trim());

            messageWrap.className = msgclass.join(' ');
            messageWrap.innerHTML = html;

            if ($(`.typing.${message.username}`)) {
                $(`.typing.${message.username}`).parentNode.removeChild($(`.typing.${message.username}`));
            }
            messagesDiv.appendChild(messageWrap);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        },
        cleanDate(when) {
            // Grab current date to compare against
            let now = new Date();
            let out = when.toISOString();

            let ampm = ['am', 'pm'], yr, mo, hr, hour, min, day, xm;
            let diff = now.getTime() - when.getTime();

            // First check for messges within the past day
            if (diff < 86400000) {
                hr = when.getHours();
                min = when.getMinutes();
                hour = hr % 12;
                xm = ampm[Math.floor(hr / 12)];
                if (min < 10) {
                    min = '0' + min;
                }
                out = `${hour}:${min}${xm}`;
            } else if (diff < 604800000) {
                // Now the past week
                let days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
                day = days[when.getDay()];
                hr = when.getHours();
                min = when.getMinutes();
                hour = hr % 12;
                xm = ampm[Math.floor(hr / 12)];
                if (min < 10) {
                    min = '0' + min;
                }
                out = `${day}. ${hour}:${min}${xm}`;
            } else {
                // otherwise just give the entire date and time
                mo = when.getMonth() + 1;
                day = when.getDate();
                yr = when.getFullYear();
                hr = when.getHours();
                min = when.getMinutes();
                hour = hr % 12;
                xm = ampm[Math.floor(hr / 12)];
                if (min < 10) {
                    min = '0' + min;
                }
                if (day < 10) day = '0' + day;

                out = `${mo}/${day}/${yr} ${hour}:${min}${xm}`;

            }
            return out;
        }
    };

    window.app = app;
    app.init();
})();

