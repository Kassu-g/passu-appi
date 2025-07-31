"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// src/server.ts
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const path_1 = __importDefault(require("path"));
const users = [];
const app = (0, express_1.default)();
app.use(express_1.default.json());
function validateToken(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth)
        return res.status(401).json({ message: 'No token provided' });
    const token = auth.split(' ')[1];
    try {
        const payload = jsonwebtoken_1.default.verify(token, process.env.SECRET);
        req.user = payload;
        next();
    }
    catch {
        return res.status(401).json({ message: 'Invalid token' });
    }
}
app.post('/api/user/register', async (req, res) => {
    const { email, password } = req.body;
    if (users.some(u => u.email === email)) {
        return res.status(403).json({ message: 'Email already used' });
    }
    const hash = await bcryptjs_1.default.hash(password, 10);
    const user = { email, password: hash };
    users.push(user);
    res.json(user);
});
app.get('/api/user/list', (_, res) => {
    res.json(users);
});
app.post('/api/user/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user || !(await bcryptjs_1.default.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jsonwebtoken_1.default.sign({ email }, process.env.SECRET, { expiresIn: '1h' });
    res.json({ token });
});
app.get('/api/private', validateToken, (_, res) => {
    res.json({ message: 'This is protected secure route!' });
});
app.use(express_1.default.static(path_1.default.join(__dirname, '..', 'public')));
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
