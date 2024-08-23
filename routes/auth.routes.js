const express = require('express');
const session = require('express-session');
const router = express.Router();
const authController = require('../controllers/auth.controller');

// Login routes
router.get('/login', authController.getLogin);
router.post('/login', authController.postLogin);

// Logout route
router.get('/logout', authController.logout);

// Dashboard routes
router.get('/dashboard/student', authController.getStudentDashboard);
router.get('/dashboard/faculty', authController.getFacultyDashboard);
router.get('/dashboard/admin', authController.getAdminDashboard);
// Change password routes
router.get('/change-password', authController.getChangePassword);
router.post('/change-password', authController.postChangePassword);
// Add routes for managing users (admin-only access)
router.get('/admin/manage-users', authController.getManageUsers);
router.get('/admin/add-user', authController.getAddUser);
router.post('/admin/add-user', authController.postAddUser);
router.get('/admin/edit-user/:id', authController.getEditUser);
router.post('/admin/edit-user/:id', authController.postEditUser);
router.post('/admin/delete-user/:id', authController.postDeleteUser);


module.exports = router;
