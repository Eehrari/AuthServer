const express = require('express');
const rateLimit = require('express-rate-limit');
const basicAuth = require('express-basic-auth');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT =  3002;

// Sample data
const jsonData = require('./simpleData.json');

app.use(bodyParser.json());

// Constants
const JWT_SECRET = '0d36cdadbfc75e7929822a70a9566657ca4c0ec3893f94c11956b2ede04a9a53';
const usersFilePath = 'users.json';

// Load users data from file
let users = [];
if (fs.existsSync(usersFilePath)) {
  try {
    const usersData = fs.readFileSync(usersFilePath, 'utf8');
    users = JSON.parse(usersData);
  } catch (error) {
    console.error('Error reading or parsing users data:', error);
  }
}

// Function to write users to JSON file
function writeUsersToFile(users) {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
}

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  
  if (!authorizationHeader) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const [bearer, token] = authorizationHeader.split(' ');
  
  if (bearer !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Invalid authorization header' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("JWT verification error:", err);
      return res.status(403).json({ message: err.message });
    }

    req.user = decoded;
    next();
  });
};

// Rate limit middleware for /all route
const allRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1, // limit each IP to 1 request per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Middleware for basic authentication
const auth = basicAuth({
  users: users.reduce((acc, user) => {
    acc[user.username] = user.password;
    return acc;
  }, {}),
  challenge: true // Sends a Basic authentication challenge in the response headers
});

// Middleware function to check if the API key is valid
const apiKeyAuth = (req, res, next) => {
  const apiKey = req.headers['api-key'];
  if (!apiKey || !users.some(user => user.key === apiKey)) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
};

// Route to generate a new API key
app.post('/generate-api-key', (req, res) => {
  const apiKey = crypto.randomBytes(32).toString('hex');
  const apiKeyData = {
    key: apiKey,
    generatedAt: new Date().toISOString()
  };
  users.push(apiKeyData);
  writeUsersToFile(users);
  res.status(201).json({ apiKey, message: 'API key generated successfully' });
});

// Route to generate a bearer token
app.post('/generate-token', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const user = users.find(user => user.username === username && user.password === password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ username: user.username, password: user.password }, JWT_SECRET, { expiresIn: '5h' });
  users.push({ token, generatedAt: new Date().toISOString() });
  writeUsersToFile(users);

  res.json({ token });
});

// Route to register a new authenticated user
app.post('/registerUser', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username or password is missing' });
  }

  if (users.some(user => user.username === username)) {
    return res.status(400).json({ message: 'Username already exists' });
  }

  users.push({ username, password });
  writeUsersToFile(users);
  res.status(201).json({ message: 'User registered successfully' });
});

// Route handler to get data based on page parameter
const getDataHandler = (req, res, next) => {
  const { page } = req.query;
  const pageNumber = parseInt(page) || 1;
  const pageSize = 5;
  const startIndex = (pageNumber - 1) * pageSize;
  const endIndex = startIndex + pageSize;

  const responseData = {
    data: jsonData.data.slice(startIndex, endIndex)
  };

  res.json(responseData);
};

app.get('/getData', allRateLimit, getDataHandler);
app.get('/getDataWithAuth', auth, getDataHandler);
app.get('/getDataWithApiKey', apiKeyAuth, getDataHandler);
app.get('/getDataWithToken', verifyToken, getDataHandler);

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
