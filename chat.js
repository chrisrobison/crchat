// Web Worker for handling WebSocket connection
const workerCode = `
    let ws;
    let reconnectAttempts = 0;
    let pingInterval;
    const MAX_RECONNECT_DELAY = 5000;
    
    function connect(url, cookie, headers) {
        console.log('Worker attempting connection');
        console.log('Using cookie:', cookie);
        
        ws = new WebSocket(url);

        ws.onopen = () => {
            console.log('WebSocket connection opened');
            reconnectAttempts = 0;
            postMessage({ type: 'connected' });
        };

        ws.onmessage = (event) => {
            try {
                console.log('Raw message received:', event.data);
                const data = JSON.parse(event.data);
                console.log('Parsed message:', data);
                postMessage({ type: 'message', data });
            } catch (error) {
                console.error('Error processing message:', error);
            }
        };

        ws.onclose = (event) => {
            console.log('WebSocket connection closed:', event);
            postMessage({ type: 'disconnected' });
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            postMessage({ type: 'error', data: error });
        };
    }

    self.onmessage = (event) => {
        const { type, data } = event.data;
        console.log('Worker received message:', type, data);

        switch(type) {
            case 'connect':
                connect(data.url, data.cookie, data.headers);
                break;
            case 'send':
                if (ws && ws.readyState === WebSocket.OPEN) {
                    console.log('Sending message:', data.message);
                    ws.send(JSON.stringify(data.message));
                } else {
                    console.error('WebSocket not ready. State:', ws?.readyState);
                }
                break;
        }
    };
`;
(function() {
    const $ = str => document.querySelector(str);
    const $$ = str => document.querySelectorAll(str);
    
    const authFetch = async (url, options = {}) => {
        const loginState = app.loadLoginState();
        
        // Initialize headers with existing ones or empty object
        const headers = {
            ...options.headers,
            'Content-Type': 'application/json'
        };

        if (loginState?.token) {
            headers['Authorization'] = `Bearer ${loginState.token}`;
            console.log('Adding Authorization header:', headers['Authorization'].substring(0, 20) + '...');
        } else {
            console.log('No token available for request');
        }

        const fetchOptions = {
            ...options,
            headers,
            credentials: 'include'
        };

        console.log('Fetch request:', {
            url,
            method: fetchOptions.method || 'GET',
            headers: Object.keys(fetchOptions.headers)
        });

        return fetch(url, fetchOptions);
    };

   
    const app = {
        config: {
            verifyLogin: false,
            server: "cdr2.com",
            port: 3210
        },
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
            try {
                // Initialize the worker first
                await app.initializeWorker();
                console.log('Worker initialized');

                if (app.config.verifyLogin) {
                    let resp = await fetch("/portal/api.php?type=loginProfile");
                    let profile = await resp.json();
                    console.log('Profile:', profile);

                    if (profile.status && profile.status === "error") {
                        if (profile.redirect) {
                            document.location.href = profile.redirect + "?url=/chat/index.html";
                        }
                    }
                    app.data.users[profile.Login] = profile;
                    app.data.me = profile;
                    app.data.Login = profile.Login;

                    $('#usernameModal').style.display = 'none';
                } else {
                    let savedUsername = localStorage.getItem('chatUsername');
                    if (savedUsername) {
                        app.data.username = savedUsername;
                    }
                }

                const savedLogin = app.loadLoginState();
                if (savedLogin) {
                    try {
                        // Verify the session is still valid with the server
                        const response = await authFetch(`https://${app.config.server}:${app.config.port}/api/profile`, {
                            credentials: 'include'
                        });
                        const result = await response.json();

                        if (result.status === 'success') {
                            app.data.me = result.data.profile;
                            app.data.username = savedLogin.username;

                            $('#usernameModal').style.display = 'none';
                            // Now we can safely connect
                            app.connect();
                            app.join(savedLogin.username);
                        } else {
                            app.clearLoginState();
                            $('#usernameModal').style.display = 'flex';
                            $('#usernameInput').focus();
                        }
                    } catch (error) {
                        console.error('Error verifying login state:', error);
                        app.clearLoginState();
                        $('#usernameModal').style.display = 'flex';
                        $('#usernameInput').focus();
                    }
                } else {
                    $('#usernameModal').style.display = 'flex';
                    $('#usernameInput').focus();
                }

                $('#sendButton').addEventListener('click', () => app.sendMessage());
                $('#messageInput').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') app.sendMessage();
                });
                $('#joinButton').addEventListener('click', (e) => { app.login(e) });
                document.addEventListener('paste', (e) => app.handlePaste(e));

                app.state.loaded = true;
            } catch (error) {
                console.error('Error during initialization:', error);
            }
        },

        async initializeWorker() {
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

            // Clean up the URL
            URL.revokeObjectURL(workerUrl);
        },
         
        async getSimpleProfile(user) {
            let resp = await fetch("https://dharristours.simpsf.com/portal/api.php?type=loginProfile");
            let profile = await resp.json();
            console.log(`profile`);
            console.dir(profile);
            
            if (profile.LoginID) {
                app.data.users[profile.Login] = profile;
            }
            
            return profile;
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

                // Get the authentication token
                const loginState = app.loadLoginState();
                const token = loginState?.token;

                if (!token) {
                    throw new Error('Not authenticated');
                }

                console.log('Uploading file...');
                
                const response = await fetch(`https://${app.config.server}:${app.config.port}/api/upload`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    credentials: 'include',
                    body: formData
                });

                // Log response headers for debugging
                console.log('Response headers:', {
                    cors: response.headers.get('Access-Control-Allow-Origin'),
                    contentType: response.headers.get('Content-Type')
                });

                const result = await response.json();
                console.log('Upload response:', result);

                if (!response.ok) {
                    throw new Error(result.message || 'Upload failed');
                }

                if (result.status === 'error') {
                    throw new Error(result.message || 'Upload failed');
                }

                console.log('File upload successful:', result);

                // Send message with file information
                if (app.data.connected) {
                    let messageContent;
                    const fileInfo = result.data;

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
        $('#pasteIndicator').style.display = 'none';
        alert('Failed to upload file: ' + error.message);
    }
}
,

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
            if (!user) {
                console.error("getUserProfile called without a user");
                return null;
            }
            let resp = await fetch(`https://${app.config.server}:${app.config.port}/api/userprofile?user=${user}`);
            let profile = await resp.json();

            if (profile.status && profile.status === "error") {
                if (profile.redirect) {
                    document.location.href = profile.redirect + '?url=/chat/';
                }
            } else {
                app.data.users[user] = profile;
            }
            return profile;
        },
        async validateToken() {
            const loginState = app.loadLoginState();
            if (!loginState?.token) return false;

            try {
                const response = await authFetch(`https://${app.config.server}:${app.config.port}/api/profile`);
                const result = await response.json();

                if (result.status === 'success') {
                    // Update stored profile data
                    app.data.me = result.data.profile;
                    return true;
                }
                
                return false;
            } catch (error) {
                console.error('Token validation error:', error);
                return false;
            }
        },
        connect() {
            if (!app.worker) {
                console.error('Worker not initialized');
                return;
            }

            console.log('Connect function called');
            const loginState = app.loadLoginState();
            console.log('Login state:', loginState);
            
            const token = loginState?.token;
            if (!token) {
                console.error('No authentication token found');
                return;
            }

            app.worker.postMessage({
                type: 'connect',
                data: { 
                    url: `wss://${app.config.server}:${app.config.port}`,
                    cookie: `auth_token=${token}`,
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                }
            });
            
            console.log('Connection message sent to worker');
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
async login(evt) {
    evt.preventDefault();
    const username = $("#usernameInput").value.trim();
    const password = $("#passwordInput").value.trim();

    if (!username || !password) {
        alert('Please enter both username and password');
        return false;
    }

    try {
        console.log('Attempting login...');
        const response = await authFetch(`https://${app.config.server}:${app.config.port}/api/login`, {
            method: 'POST',
            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        const result = await response.json();
        console.log('Login response:', result);

        if (result.status === 'success') {
            console.log('Login successful');
            app.data.me = result.data.profile;
            app.data.username = username;

            // Save login state with token
            app.saveLoginState({
                username: username,
                token: result.data.token,
                profile: result.data.profile
            });

            $('#usernameModal').style.display = 'none';

            // Wait a moment for cookie to be set
            await new Promise(resolve => setTimeout(resolve, 100));
            
            app.connect();
            app.join(username);
        } else {
            console.log('Login failed:', result.message);
            alert(result.message || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed: ' + (error.message || 'Unknown error'));
    }

    return false;
},
        async logout() {
            try {
                // Call logout endpoint if you have one
                await fetch(`https://${app.config.server}:${app.config.port}/api/logout`, {
                    method: 'POST',
                    credentials: 'include'
                });
            } catch (error) {
                console.error('Logout error:', error);
            }

            // Clear local storage and reset state
            app.clearLoginState();
            app.data.me = null;
            app.data.username = '';
            app.data.connected = false;
            app.state.identified = false;

            // Disconnect WebSocket
            if (app.worker) {
                app.worker.terminate();
                app.worker = null;
            }

            // Show login modal
            $('#usernameModal').style.display = 'flex';
        },
        join(user) {
            let username;
            if (user && typeof(user)==="string") {
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
        showLogin(evt) {
            if (evt) evt.preventDefault();

            $(".username-modal").style.display = "flex";
            $(".registration-modal").style.display = "none";
            return false;
        },
        showRegistration(evt) {
            if (evt) evt.preventDefault();

            $(".username-modal").style.display = "none";
            $(".registration-modal").style.display = "flex";
            return false;
        },
        async register(evt) {
            if (evt) evt.preventDefault();
            
            const form = $("#registrationForm");
            const formData = new FormData(form);
            const data = {};
            
            // Convert FormData to plain object
            formData.forEach((value, key) => {
                data[key] = value;
            });
            try {
                const resp = await fetch(`https://${app.config.server}:${app.config.port}/api/register`, {
                    method: "POST",
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include',
                    body: JSON.stringify(data)
                });

                const result = await resp.json();
                console.log('Registration response:', result);  // Debug log

                if (result.status === 'success') {
                    $(".registration-modal").style.display = "none";
                    alert("Account created. You may now login.");
                    $(".username-modal").style.display = "flex";
                } else {
                    alert(result.message || 'Registration failed');
                }
            } catch (error) {
                console.error('Registration error:', error);
                alert('Registration failed: ' + (error.message || 'Unknown error'));
            }
            return false;
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

            if (message && app.data.connected) {
                console.log('Preparing to send message');
                const messageData = {
                    type: 'chat',
                    username: app.data.username,
                    content: message,
                    timestamp: new Date().toISOString()
                };

                console.log('Sending message to worker:', messageData);
                app.worker.postMessage({
                    type: 'send',
                    data: { message: messageData }
                });

                input.value = '';
            } else {
                console.log('Message not sent. Connected:', app.data.connected);
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
                    
                    if (username) {
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
                }
            });
        },
        async receiveMessage(message, historical=false) {
            if (message.type === 'system' && message.content === 'Please log in to join the chat.') {
                // Show the login modal again
                $('#usernameModal').style.display = 'flex';
                return;
            }
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
            if (message.username && !app.data.users[message.username]) {
                app.data.users[message.username] = await app.getUserProfile(message.username);
            }

            let msg = message;
            if (msg.type != 'system') {
                msg.Picture = (app.data.users[message.username].Picture) ? `<img class="profilepic" width="32" src="${app.data.users[message.username].Picture}">` : '<img class="profilepic" width="32" src="nopic.svg">';
                msg.Login = message.username;
                msg.mine = (message.username == app.data.username) ? ' mine' : '';
            }
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
        },
        saveLoginState(userData) {
            const loginState = {
                username: userData.username,
                token: userData.token,
                timestamp: new Date().getTime(),
                profile: {
                    id: userData.profile.id,
                    Login: userData.profile.Login,
                    Picture: userData.profile.Picture
                }
            };

            // Save to localStorage
            localStorage.setItem('chatLoginState', JSON.stringify(loginState));
            console.log('Login state saved:', loginState);
        },
        loadLoginState() {
            try {
                const savedState = localStorage.getItem('chatLoginState');
                if (!savedState) {
                    console.log('No saved login state found');
                    return null;
                }

                const loginState = JSON.parse(savedState);
                const now = new Date().getTime();
                
                // Check if saved state is within 30 days
                if (now - loginState.timestamp > 30 * 24 * 60 * 60 * 1000) {
                    console.log('Login state expired');
                    //localStorage.removeItem('chatLoginState');
                    return null;
                }

                console.log('Loaded login state:', loginState);
                return loginState;
            } catch (error) {
                console.error('Error loading login state:', error);
//                localStorage.removeItem('chatLoginState');
                return null;
            }
        },
async validateLoginState() {
    console.log('Validating login state...');
    const loginState = this.loadLoginState();
    
    if (!loginState?.token) {
        console.log('No token found in login state');
        return false;
    }

    try {
        // Use authFetch instead of direct fetch
        const response = await authFetch(`https://${app.config.server}:${app.config.port}/api/profile`);
        const result = await response.json();
        console.log('Profile validation result:', result);

        if (result.status === 'success') {
            app.data.me = result.data.profile;
            app.data.username = loginState.username;
            return true;
        }
        
        console.log('Login state validation failed');
        this.clearLoginState();
        return false;
    } catch (error) {
        console.error('Error validating login state:', error);
        this.clearLoginState();
        return false;
    }
},


        clearLoginState() {
            //localStorage.removeItem('chatLoginState');
        }

    };

    window.app = app;
    app.init();
})();

