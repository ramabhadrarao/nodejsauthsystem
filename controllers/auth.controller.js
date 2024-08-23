const db = require('../config/db.config');
const bcrypt = require('bcryptjs');

// Render the login page
exports.getLogin = (req, res) => {
    res.render('login', { message: '' });
};

// Handle login POST request
exports.postLogin = (req, res) => {
    const { username, password } = req.body;

    // Find user by username
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            const user = results[0];

            // Compare password
            bcrypt.compare(password, user.password, (err, match) => {
                if (err) throw err;

                if (match) {
                    // Store user data in session
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    req.session.role = user.role;

                    // Redirect to respective dashboard
                    if (user.role === 'student') {
                        return res.redirect('/dashboard/student');
                    } else if (user.role === 'faculty') {
                        return res.redirect('/dashboard/faculty');
                    } else if (user.role === 'admin') {
                        return res.redirect('/dashboard/admin');
                    }
                } else {
                    res.render('login', { message: 'Invalid Credentials' });
                }
            });
        } else {
            res.render('login', { message: 'User not found' });
        }
    });
};

// Logout function
exports.logout = (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
};

// Dashboard for student
exports.getStudentDashboard = (req, res) => {
    if (req.session.role !== 'student') {
        return res.redirect('/login');
    }
    res.render('dashboard/student', { username: req.session.username });
};

// Dashboard for faculty
exports.getFacultyDashboard = (req, res) => {
    if (req.session.role !== 'faculty') {
        return res.redirect('/login');
    }
    res.render('dashboard/faculty', { username: req.session.username });
};

// Dashboard for admin
exports.getAdminDashboard = (req, res) => {
    if (req.session.role !== 'admin') {
        return res.redirect('/login');
    }
    res.render('dashboard/admin', { username: req.session.username });
};

exports.getChangePassword = (req, res) => {
    res.render('change-password', { role: req.session.role, message: '' });
};

exports.postChangePassword = (req, res) => {
    const { 'current-password': currentPassword, 'new-password': newPassword, 'confirm-password': confirmPassword } = req.body;
    const userId = req.session.userId;

    if (newPassword !== confirmPassword) {
        return res.render('change-password', { role: req.session.role, message: 'New passwords do not match.' });
    }

    // Fetch user from DB
    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            const user = results[0];

            // Compare current password
            bcrypt.compare(currentPassword, user.password, (err, match) => {
                if (err) throw err;

                if (match) {
                    // Hash the new password
                    bcrypt.hash(newPassword, 10, (err, hash) => {
                        if (err) throw err;

                        // Update the password in DB
                        db.query('UPDATE users SET password = ? WHERE id = ?', [hash, userId], (err, results) => {
                            if (err) throw err;
                            res.render('change-password', { role: req.session.role, message: 'Password successfully changed!' });
                        });
                    });
                } else {
                    res.render('change-password', { role: req.session.role, message: 'Current password is incorrect.' });
                }
            });
        }
    });
};
// Render the Manage Users page
exports.getManageUsers = (req, res) => {
    if (req.session.role !== 'admin') {
        return res.redirect('/login');
    }

    // Fetch all users from the database
    db.query('SELECT id, username, role FROM users', (err, results) => {
        if (err) throw err;
        res.render('admin/manage-users', { users: results, role: req.session.role });
    });
};

// Render Add User form
exports.getAddUser = (req, res) => {
    if (req.session.role !== 'admin') {
        return res.redirect('/login');
    }
    res.render('admin/add-user', { role: req.session.role, message: '' });
};

// Handle Add User form submission
exports.postAddUser = (req, res) => {
    const { username, password, role } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) throw err;

        // Insert new user into the database
        db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hash, role], (err, result) => {
            if (err) throw err;
            res.redirect('/admin/manage-users');
        });
    });
};

// Render Edit User form
exports.getEditUser = (req, res) => {
    const userId = req.params.id;

    // Fetch the user by ID
    db.query('SELECT id, username, role FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            res.render('admin/edit-user', { user: results[0], role: req.session.role, message: '' });
        } else {
            res.redirect('/admin/manage-users');
        }
    });
};

// Handle Edit User form submission
exports.postEditUser = (req, res) => {
    const userId = req.params.id;
    const { username, role } = req.body;

    // Update the user's username and role
    db.query('UPDATE users SET username = ?, role = ? WHERE id = ?', [username, role, userId], (err, result) => {
        if (err) throw err;
        res.redirect('/admin/manage-users');
    });
};

// Handle Delete User
exports.postDeleteUser = (req, res) => {
    const userId = req.params.id;

    // Delete the user from the database
    db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
        if (err) throw err;
        res.redirect('/admin/manage-users');
    });
};
