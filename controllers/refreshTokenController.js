const mysql = require('mysql');
require('dotenv').config();
const jwt = require('jsonwebtoken');

// Create a MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'my_database',
    connectionLimit: 10
});

const handleRefreshToken = (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) {
        return res.status(401).send("Refresh token not found");
    }

    const refreshToken = cookies.jwt;

    // Query the database to find the user associated with the refresh token
    const sql = 'SELECT * FROM users WHERE refreshToken = ?';
    pool.query(sql, [refreshToken], (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        const foundUser = results[0];

        if (!foundUser) {
            return res.status(403).send('Error 1'); // Forbidden
        }

        // Verify the refresh token
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            (err, decoded) => {
                if (err || foundUser.username !== decoded.username) {
                    return res.status(403).send('Error 2');
                }

                // Generate a new access token
                const accessToken = jwt.sign(
                    { username: foundUser.username },
                    process.env.ACCESS_TOKEN_SECRET,
                    { expiresIn: '1h' }
                );

                res.json({ accessToken });
            }
        );
    });
};

module.exports = { handleRefreshToken };