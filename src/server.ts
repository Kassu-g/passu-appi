// src/server.ts
import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';

interface User { email: string; password: string; }
const users: User[] = [];

const app = express();
app.use(express.json());
function validateToken(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'No token provided' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.SECRET as string) as { email: string };
    (req as any).user = payload;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

app.post('/api/user/register', async (req: Request, res: Response) => {
  const { email, password } = req.body as { email: string; password: string };
  if (users.some(u => u.email === email)) {
    return res.status(403).json({ message: 'Email already used' });
  }
  const hash = await bcrypt.hash(password, 10);
  const user: User = { email, password: hash };
  users.push(user);
  res.json(user);
});

app.get('/api/user/list', (_: Request, res: Response) => {
  res.json(users);
});

app.post('/api/user/login', async (req: Request, res: Response) => {
  const { email, password } = req.body as { email: string; password: string };
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ email }, process.env.SECRET as string, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/api/private', validateToken, (_: Request, res: Response) => {
  res.json({ message: 'This is protected secure route!' });
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
