const mysql = require('mysql');
require('dotenv').config();

// Create a MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'my_database',
    connectionLimit: 10
});

const handleLogout = (req, res) => {
    // Retrieve the refresh token from cookies
    const refreshToken = req.cookies.jwt;

    // Check if the refresh token exists
    if (!refreshToken) {
        // If no refresh token found, return 204 (No Content)
        return res.sendStatus(204);
    }

    // Query the database to find the user associated with the refresh token
    const sql = 'SELECT * FROM users WHERE refreshToken = ?';
    pool.query(sql, [refreshToken], (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        const foundUser = results[0];

        if (!foundUser) {
            // If no user found with the refresh token, clear the cookie and return 204
            res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
            return res.sendStatus(204);
        }

        // Clear the refresh token from the user's record in the database
        const updateSql = 'UPDATE users SET refreshToken = ? WHERE id = ?';
        pool.query(updateSql, ['', foundUser.id], (updateErr, updateResults) => {
            if (updateErr) {
                console.error('Error updating user record:', updateErr);
                return res.status(500).json({ error: 'Internal server error' });
            }

            // Clear the JWT cookie from the client-side
            res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
            // Send 204 (No Content) response indicating successful logout
            res.sendStatus(204);
        });
    });
};

module.exports = { handleLogout };
