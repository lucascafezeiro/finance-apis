const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

app.use(express.json());

app.use(cors());

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

app.get('/users', authenticateToken, async (req, res) => {
  const { companyId } = req.user;
  const users = await prisma.user.findMany({
    where: { company_id: companyId },
  });
  // Don't return password in the response
  users.forEach(user => {
    delete user.password;
  });
  res.json(users);
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
app.get('/category/:category_id', authenticateToken, async (req, res) => {
  const { category_id } = req.params;
  const { companyId } = req.user;

  const category = await prisma.category.findUnique({
    where: { id: parseInt(category_id) },
    include: { transactions: true },
  });

  if (!category || category.company_id !== companyId) {
    return res.status(404).send('Category not found');
  }

  res.json(category);
});

app.get('/categories', authenticateToken, async (req, res) => {
  const { companyId } = req.user;
  const categories = await prisma.category.findMany({
    where: { company_id: companyId },
  });
  res.json(categories);
});

app.get('/categories/:type', authenticateToken, async (req, res) => {
  const { type } = req.params;
  const { companyId } = req.user;
  const categories = await prisma.category.findMany({
    where: { type, company_id: companyId },
  });
  res.json(categories);
});

app.post('/category', authenticateToken, async (req, res) => {
  const { name, type } = req.body;
  const { companyId } = req.user;

  const category = await prisma.category.create({
    data: { name, type, company_id: companyId, active: true },
  });

  res.json(category);
});

app.put('/category/:category_id', authenticateToken, async (req, res) => {
  const { category_id } = req.params;
  const { name, type, active } = req.body;
  const { companyId } = req.user;

  const category = await prisma.category.update({
    where: { id: parseInt(category_id) },
    data: { name, type, company_id: companyId, active: active || true },
  });

  res.json(category);
});

// Transaction APIs.
app.get('/transactions/:year/:month', authenticateToken, async (req, res) => {
  const includeCategories = req.query.include_categories === 'true';
  const { month, year } = req.params;
  const { companyId } = req.user;
  const startDate = new Date(year, month - 1, 1);
  const endDate = new Date(year, month, 0);
  const transactions = await prisma.transaction.findMany({
    where: { company_id: companyId, date: { gte: startDate, lte: endDate } },
    include: includeCategories ? { category: true } : undefined,
  });
  res.json(transactions);
});

app.get('/transactions/:year', authenticateToken, async (req, res) => {
  const includeCategories = req.query.include_categories === 'true';
  const { year } = req.params;
  const { companyId } = req.user;
  const startDate = new Date(year, 0, 1);
  const endDate = new Date(year, 11, 31);
  const transactions = await prisma.transaction.findMany({
    where: { company_id: companyId, date: { gte: startDate, lte: endDate } },
    include: includeCategories ? { category: true } : undefined,
  });
  res.json(transactions);
});

app.post('/transaction', authenticateToken, async (req, res) => {
  const { date, description, category_id, value, type } = req.body;
  const { companyId } = req.user;

  const transaction = await prisma.transaction.create({
    data: {
      date,
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
  const { date, description, category_id, value, type } = req.body;
  const { companyId } = req.user;

  const transaction = await prisma.transaction.update({
    where: { id: parseInt(transaction_id) },
    data: { 
      date,
      description,
      category_id,
      value,
      type,
      company_id: companyId,
    },
  });

  res.json(transaction);
});

async function getDashboardData(req, res, period) {
  const { year, month } = req.params;
  const { companyId } = req.user;

  const startDate = period === 'month'
    ? new Date(year, month - 1, 1)
    : new Date(year, 0, 1);

  const endDate = period === 'month'
    ? new Date(year, month, 0, 23, 59, 59, 999)
    : new Date(year, 11, 31, 23, 59, 59, 999);

  const transactions = await prisma.transaction.findMany({
    where: {
      company_id: companyId,
      date: { gte: startDate, lte: endDate },
    },
  });

  const totals = {
    credits: transactions.filter(t => t.type === 'credit').reduce((sum, t) => sum + t.value, 0),
    debits: transactions.filter(t => t.type === 'debit').reduce((sum, t) => sum + t.value, 0),
    investments: transactions.filter(t => t.type === 'investment').reduce((sum, t) => sum + t.value, 0),
  };

  const monthlyData = Array.from({ length: 12 }, (_, i) => {
    const monthTransactions = transactions.filter(t => new Date(t.date).getMonth() === i);
    return {
      name: new Date(2000, i).toLocaleString('default', { month: 'short' }),
      credits: monthTransactions.filter(t => t.type === 'credit').reduce((sum, t) => sum + t.value, 0),
      debits: monthTransactions.filter(t => t.type === 'debit').reduce((sum, t) => sum + t.value, 0),
      investments: monthTransactions.filter(t => t.type === 'investment').reduce((sum, t) => sum + t.value, 0),
    };
  });

  const categoryData = {
    credit: [],
    debit: [],
    investment: [],
  };

  for (const t of transactions) {
    categoryData[t.type].push({
      category: t.category_id,
      value: t.value,
    });
  }

  res.json({ totals, monthlyData, categoryData, transactions });
}

app.get('/dashboard/:year/:month', authenticateToken, async (req, res) => {
  return getDashboardData(req, res, 'month');
});

app.get('/dashboard/:year', authenticateToken, async (req, res) => {
  return getDashboardData(req, res, 'year');
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
