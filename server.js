const express = require('express');
const cors = require('cors'); // Import cors middleware
const mysql = require('mysql');
require('dotenv').config();
const bodyParser = require('body-parser'); // Import body-parser for parsing request bodies
const bcrypt = require('bcrypt'); // Import bcrypt for hashing passwords
const cookieParser = require ('cookie-parser');
const jwt = require('jsonwebtoken');
const verifyJWT = require('./middleware/verifyJWT');


const app = express();
const port = 3001;

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

// Middleware to parse JSON request bodies
app.use(bodyParser.json());
app.use(cookieParser());

// Create a MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'my_database',
  connectionLimit: 10
});

app.get('/', (req, res) => {
  return res.json("From The Backend Side");
})

app.post('/sign-up', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ 'message': 'Username, Email, and Passwore are Required'});
  // Hash the password
  const hashedPassword = bcrypt.hashSync(password, 10);
  // Check if username or email already exists
  pool.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, results) => {
    if (err) {
      console.error('Error checking for existing user:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (results.length > 0) {
      // Username or email already exists
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    // Insert user data into the database
    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    const values = [username, email, hashedPassword];
    pool.query(sql, values, (insertErr, insertResults) => {
      if (insertErr) {
        console.error('Error inserting user into database:', insertErr);
        return res.status(500).json({ error: 'Failed to register user' });
      }
      // User registered successfully
      return res.status(200).json({ message: 'User registered successfully' });
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const sql = 'SELECT * FROM users WHERE username = ?';
  pool.query(sql, [username], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = results[0];

    // Match the password
    bcrypt.compare(password, user.password, (bcryptErr, bcryptResult) => {
      if (bcryptErr || !bcryptResult) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Generate JWT token
      const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
      const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '1d' });

      // Update the refresh token in database
      const updateSql = 'UPDATE users SET refreshToken = ? WHERE id = ?'
      pool.query(updateSql, [refreshToken, user.id], (updateErr, updateResults) => {
        if (updateErr) {
          console.error('Error updating refresh token:', updateErr)
          return res.status(500).json({ error: 'Failed to update refresh token' });
        }
          res.cookie('jwt', refreshToken, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 });
          return res.status(200).json({ message: 'Login successful', accessToken });
      });
    });
  });
});

app.use ('/refresh', require('./routes/refresh'));
app.use ('/logout', require('./routes/logout'));


app.use(verifyJWT);


// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: err.message }); // Send error message in response
});
app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
