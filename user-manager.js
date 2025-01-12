const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

class UserManager {
    constructor(basePath = '/home/cdr/domains/cdr2.com/www/crchat') {
        this.basePath = basePath;
        this.usersFile = path.join(basePath, 'users.jsonl');
        this.usersDir = path.join(basePath, 'users');
        this.userCache = new Map();
    }

    async initialize() {
        // Ensure directories exist
        await fs.mkdir(this.usersDir, { recursive: true });
        
        // Load existing users into cache
        try {
            const content = await fs.readFile(this.usersFile, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());
            for (const line of lines) {
                const user = JSON.parse(line);
                this.userCache.set(user.username, user);
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                throw error;
            }
            // If file doesn't exist, create it
            await fs.writeFile(this.usersFile, '', 'utf8');
        }
    }

    async createUser(data) {
        // Validate inputs
        console.log("creating user");
        console.dir(data);
        if (!data.username || !data.password || !data.email) {
            throw new Error('Missing required fields');
        }
        if (this.userCache.has(data.username)) {
            throw new Error('Username already exists');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(data.password, 10);

        // Create user object
        const user = {
            id: uuidv4(),
            username: data.username,
            email: data.email,
            password: hashedPassword,
            location: data.location,
            phone: data.phone,
            firstName: data.firstName,
            lastName: data.lastName,
            created: new Date().toISOString(),
            lastLogin: null,
            status: 'active'
        };

        // Create user directory
        const userDir = path.join(this.usersDir, user.id);
        console.log(`userDir: ${userDir}`);
        await fs.mkdir(userDir, { recursive: true });
        await fs.mkdir(path.join(userDir, 'uploads'), { recursive: true });

        // Create profile.json
        const profile = {
            theme: 'default',
            notifications: true,
            status: 'online',
            avatar: null,
            customSettings: {}
        };
        await fs.writeFile(
            path.join(userDir, 'profile.json'),
            JSON.stringify(profile, null, 2),
            'utf8'
        );

        // Add to users.jsonl
        await fs.appendFile(
            this.usersFile,
            JSON.stringify(user) + '\n',
            'utf8'
        );

        // Add to cache
        this.userCache.set(data.username, user);

        // Return user object (without password)
        const { password: _, ...userWithoutPassword } = user;
        return userWithoutPassword;
    }

    async validateUser(username, password) {
        const user = this.userCache.get(username);
        if (!user) {
            return false;
        }
        return bcrypt.compare(password, user.password);
    }

    async getUserProfile(userId) {
        const user = this.userCache.get(userId);
        try {
            const profilePath = path.join(this.usersDir, user.id, 'profile.json');
            const profile = await fs.readFile(profilePath, 'utf8');
            return {...user, profile: JSON.parse(profile) };
        } catch (error) {
            throw new Error('Profile not found');
        }
    }

    async updateUserProfile(userId, updates) {
        const profilePath = path.join(this.usersDir, userId, 'profile.json');
        const currentProfile = await this.getUserProfile(userId);
        const updatedProfile = { ...currentProfile, ...updates };
        await fs.writeFile(
            profilePath,
            JSON.stringify(updatedProfile, null, 2),
            'utf8'
        );
        return updatedProfile;
    }

    getUserUploadPath(userId) {
        return path.join(this.usersDir, userId, 'uploads');
    }

    async getAllUsers() {
        return Array.from(this.userCache.values()).map(user => {
            const { password, ...userWithoutPassword } = user;
            return userWithoutPassword;
        });
    }
}

module.exports = UserManager;
