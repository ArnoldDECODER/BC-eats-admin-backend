/**
 * Database-authoritative role authorization.
 *
 * The role claim inside a JWT is informational only. Every protected request
 * loads the current role from MongoDB, so changing/removing a user's role in
 * MongoDB takes effect immediately without waiting for the JWT to expire.
 */
const mongoose = require('mongoose');
const User = require('../models/usersModel');

exports.requireRoles = (...allowedRoles) => async (req, res, next) => {
  try {
    if (!req.user?.userId || req.user?.guestId) {
      return res.status(401).json({ success: false, message: 'Registered account authentication required' });
    }

    if (!mongoose.isValidObjectId(req.user.userId)) {
      return res.status(401).json({ success: false, message: 'Invalid account identity' });
    }

    const user = await User.findById(req.user.userId).select('_id email role verified');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Account no longer exists' });
    }

    const currentRole = String(user.role || '').trim().toLowerCase();
    const permittedRoles = allowedRoles.map(role => String(role).trim().toLowerCase());
    if (!permittedRoles.includes(currentRole)) {
      return res.status(403).json({ success: false, message: 'Insufficient permissions' });
    }

    // Downstream controllers can use the fresh database record, not JWT role.
    req.currentUser = user;
    req.user.role = currentRole;
    next();
  } catch (error) {
    next(error);
  }
};

exports.requireAdmin = exports.requireRoles('admin');
