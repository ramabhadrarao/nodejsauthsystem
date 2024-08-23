const bcrypt = require('bcryptjs');

// Generate hashed password for 'password123'
bcrypt.hash('password123', 10, (err, hash) => {
    if (err) throw err;
    console.log(`Hashed password: ${hash}`);
});
