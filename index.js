const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

app.use(express.json());

// Middleware to handle blacklisted tokens
let blacklistedTokens = new Set();
function blacklistToken(token) {
  blacklistedTokens.add(token);
}
function isTokenBlacklisted(token) {
  return blacklistedTokens.has(token);
}

// Clean up blacklisted tokens every 24 hours
setInterval(() => {
  blacklistedTokens.clear();
}, 24 * 60 * 60 * 1000); // 24 hours

app.use((req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token && isTokenBlacklisted(token)) {
    return res.status(403).send('Token is blacklisted');
  }
  next();
});

const SECRET_KEY = 'your_secret_key'; // Replace with your actual secret key

// Middleware to protect routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Authentication APIs

app.post('/login', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Basic ')) return res.status(400).send('Missing Basic Auth');

  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [email, password] = credentials.split(':');

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).send('Invalid credentials');

  const token = jwt.sign({ userId: user.id, companyId: user.company_id }, SECRET_KEY);
  res.json({ token });
});

app.post('/logout', authenticateToken, (req, res) => {
  blacklistToken(req.token);
  res.json({ message: 'Logged out' });
});

// Company APIs.
app.post('/company', async (req, res) => {
  const { name, currency, language } = req.body;

  const company = await prisma.company.create({
    data: { name, currency, language },
  });

  res.json(company);
});

app.get('/company', authenticateToken, async (req, res) => {
  const { companyId } = req.user;

  const company = await prisma.company.findUnique({
    where: { id: parseInt(companyId) },
  });

  if (!company) return res.status(404).send('Company not found');

  res.json(company);
});

app.put('/company', async (req, res) => {
  const { companyId } = req.user;
  const { name, currency, language } = req.body;

  const company = await prisma.company.update({
    where: { id: parseInt(companyId) },
    data: { name, currency, language },
  });

  res.json(company);
});

// User APIs.
app.put('/change-password/:user_id', authenticateToken, async (req, res) => {
  const { newPassword } = req.body;
  const { user_id } = req.params;
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: { id: parseInt(user_id) },
    data: { password: hashedPassword },
  });

  res.json({ message: 'Password updated' });
});

app.post('/user', async (req, res) => {
  const { name, email, password } = req.body;
  const companyId = 1
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: { name, email, password: hashedPassword, company_id: companyId },
  });

  res.json(user);
});

app.delete('/user/:user_id', authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { companyId } = req.user;
  await prisma.user.delete({
    where: {
      id: parseInt(user_id),
      company_id: companyId
    }
  });
  res.json({ message: 'User deleted' });
});

// Category APIs.
app.get('/categories', authenticateToken, async (req, res) => {
  const { companyId } = req.user;
  const categories = await prisma.category.findMany({
    where: { company_id: companyId },
  });
  res.json(categories);
});

app.post('/category', authenticateToken, async (req, res) => {
  const { name } = req.body;
  const { companyId } = req.user;

  const category = await prisma.category.create({
    data: { name, company_id: companyId, active: true },
  });

  res.json(category);
});

app.put('/category/:category_id', authenticateToken, async (req, res) => {
  const { category_id } = req.params;
  const { name, active } = req.body;
  const { companyId } = req.user;

  const category = await prisma.category.update({
    where: { id: parseInt(category_id) },
    data: { name, company_id: companyId, active },
  });

  res.json(category);
});

// Transaction APIs.
app.get('/transactions/:month/:year', authenticateToken, async (req, res) => {
  const { month, year } = req.params;
  const { companyId } = req.user;
  const startDate = new Date(year, month - 1, 1);
  const endDate = new Date(year, month, 0);
  const transactions = await prisma.transaction.findMany({
    where: { company_id: companyId, date: { gte: startDate, lte: endDate } },
  });
  res.json(transactions);
});

app.post('/transaction', authenticateToken, async (req, res) => {
  const { description, category_id, value, type } = req.body;
  const { companyId } = req.user;

  const transaction = await prisma.transaction.create({
    data: {
      description,
      category_id,
      value,
      type,
      company_id: companyId,
      created_by: req.user.userId,
    },
  });

  res.json(transaction);
});

app.delete('/transaction/:transaction_id', authenticateToken, async (req, res) => {
  const { transaction_id } = req.params;

  await prisma.transaction.delete({ where: { id: parseInt(transaction_id) } });

  res.json({ message: 'Transaction deleted' });
});

app.put('/transaction/:transaction_id', authenticateToken, async (req, res) => {
  const { transaction_id } = req.params;
  const { description, category_id, value, type } = req.body;

  const transaction = await prisma.transaction.update({
    where: { id: parseInt(transaction_id) },
    data: { description, category_id, value, type },
  });

  res.json(transaction);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
