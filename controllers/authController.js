/**
 * Authentication controller.
 *
 * This controller handles HTTP requests for:
 * - normal email/password accounts
 * - Microsoft student login
 * - the public Microsoft configuration endpoint
 *
 * Guest sessions are handled by the dedicated guest controller.
 * This keeps each authentication flow focused on one responsibility.
 */

const User = require('../models/usersModel');
const { signupSchema, signinSchema } = require('../middlewares/validator');
const { doHash, doHashValidation } = require('../utils/hashing');
const { makeUserToken } = require('../utils/tokens');

function makeToken(user) {
  return makeUserToken(user);
}

function safeUser(user) {
  return {
    id: user._id,
    name: user.name,
    fullName: user.fullName,
    email: user.email,
    phone: user.phone,
    role: user.role,
    verified: user.verified
  };
}

function getMicrosoftConfiguration() {
  const clientId = String(process.env.MICROSOFT_CLIENT_ID || '').trim();
  const authority = String(process.env.MICROSOFT_AUTHORITY || '')
    .trim()
    .replace(/\/$/, '');

  return { clientId, authority };
}

function validateMicrosoftConfiguration(clientId, authority) {
  if (!clientId || !authority) {
    return 'Microsoft authentication is not configured. Set MICROSOFT_CLIENT_ID and MICROSOFT_AUTHORITY in the backend .env file.';
  }

  if (!/^https:\/\/login\.microsoftonline\.com\/common$/i.test(authority)) {
    return 'MICROSOFT_AUTHORITY must be https://login.microsoftonline.com/common';
  }

  return null;
}

exports.microsoftConfig = (req, res) => {
  const configuration = getMicrosoftConfiguration();
  const error = validateMicrosoftConfiguration(
    configuration.clientId,
    configuration.authority
  );

  if (error) {
    return res.status(500).json({
      success: false,
      message: error
    });
  }

  return res.json({
    success: true,
    data: configuration
  });
};

exports.signup = async (req, res, next) => {
  try {
    const { error, value } = signupSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const email = value.email.toLowerCase();
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Email already in use'
      });
    }

    const password = await doHash(value.password);
    const user = await User.create({
      ...value,
      email,
      password
    });

    const token = makeToken(user);

    return res.status(201).json({
      success: true,
      message: 'Account created',
      token,
      data: safeUser(user)
    });
  } catch (error) {
    return next(error);
  }
};

exports.signin = async (req, res, next) => {
  try {
    const { error, value } = signinSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const email = value.email.toLowerCase();
    const user = await User.findOne({ email }).select('+password');

    if (!user?.password) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const validPassword = await doHashValidation(value.password, user.password);

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const token = makeToken(user);

    res.cookie(
      'Authorization',
      `Bearer ${token}`,
      {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 8 * 60 * 60 * 1000
      }
    );

    return res.json({
      success: true,
      token,
      data: safeUser(user)
    });
  } catch (error) {
    return next(error);
  }
};

exports.loginWithMicrosoft = async (req, res, next) => {
  try {
    const microsoftUser = req.microsoftUser;

    if (!microsoftUser?.email) {
      return res.status(401).json({
        success: false,
        message: 'Microsoft authentication failed'
      });
    }

    const email = String(microsoftUser.email).trim().toLowerCase();
    const objectId = String(microsoftUser.oid || '').trim();

    // Prefer an existing immutable Microsoft object-ID link. If this is the
    // first login, fall back to the verified email and link the Microsoft ID.
    let user = objectId ? await User.findOne({ microsoftId: objectId }) : null;
    if (!user) user = await User.findOne({ email });

    // Do not create accounts or assign roles during Microsoft login. MongoDB
    // is the only source of admin permission: an existing record must already
    // have role='admin'.
    if (!user) {
      return res.status(403).json({
        success: false,
        message: 'No BC Eats account is registered for this Microsoft email. Contact an administrator.'
      });
    }
    if (String(user.role || '').trim().toLowerCase() !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'This account is not authorised to access the admin portal.'
      });
    }

    // Prevent silently linking an identity already assigned to another user.
    if (objectId && user.microsoftId && user.microsoftId !== objectId) {
      return res.status(403).json({
        success: false,
        message: 'This database account is linked to a different Microsoft identity. Contact an administrator.'
      });
    }

    if (objectId) user.microsoftId = objectId;
    if (microsoftUser.tenantId) user.tenantId = microsoftUser.tenantId;
    user.verified = true;
    await user.save();

    // Re-read role from MongoDB immediately before issuing the app JWT.
    const currentUser = await User.findById(user._id);
    if (!currentUser || String(currentUser.role || '').trim().toLowerCase() !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin access has been revoked.' });
    }
    const token = makeToken(currentUser);

    return res.json({
      success: true,
      message: 'Microsoft login successful',
      token,
      data: safeUser(currentUser)
    });
  } catch (error) {
    return next(error);
  }
};

exports.signout = (req, res) => {
  res.clearCookie('Authorization');

  return res.json({
    success: true,
    message: 'Logged out'
  });
};

exports.me = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    return res.json({
      success: true,
      data: user
    });
  } catch (error) {
    return next(error);
  }
};

exports.updateProfile = async (req, res, next) => {
  try {
    const allowedFields = [
      'name',
      'fullName',
      'phone',
      'avatarUrl',
      'profileImage',
      'deliveryAddress',
      'addresses',
      'language',
      'theme',
      'notificationSettings'
    ];

    const changes = {};

    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        changes[field] = req.body[field];
      }
    }

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      changes,
      {
        new: true,
        runValidators: true
      }
    ).select('-password');

    return res.json({
      success: true,
      message: 'Profile updated',
      data: user
    });
  } catch (error) {
    return next(error);
  }
};

exports.makeToken = makeToken;
