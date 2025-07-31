require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();
const PORT = 3000;
app.use(express.json());
const users = [];

function validateToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ message: 'No token provided' });
  const [, token] = auth.split(' ');
  try {
    const payload = jwt.verify(token, process.env.SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

app.post('/api/user/register', async (req, res) => {
  const { email, password } = req.body;
  if (users.find(u => u.email === email)) {
    return res.status(403).json({ message: 'Email already in use' });
  }
  const hash = await bcrypt.hash(password, 10);
  const user = { email, password: hash };
  users.push(user);
  res.json(user);
});

app.get('/api/user/list', (req, res) => {
  res.json(users);
});

app.post('/api/user/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ email: user.email }, process.env.SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/api/private', validateToken, (req, res) => {
  res.json({ message: 'This is protected secure route!' });
});


app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));