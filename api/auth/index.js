const authApi = require('./auth-api');
const admin = require('firebase-admin');
const cors = require('cors')({origin: true});

/**
 * Generic function to sign up an user
 * @returns a result code and a firebase id token in case of success, or the errors
 */
exports.signUpUser = (req, res) => {
  cors(req, res, () => {
    switch (req.params.provider) {
      case 'password':
        return authApi.signUpUserWithPassword(req, res);
      default:
        return res
          .status(500)
          .json({ error: `Signup type invalid : ${req.params.provider}` });
    }
  });
};

/**
 * Generic function to sign in an user
 * @returns a result code and a token in case of success, or the errors
 */
exports.logInUser = (req, res) => {
  cors(req, res, () => {
    switch (req.params.provider) {
      case 'password':
        return authApi.logInUserWithPassword(req, res);
      case 'facebook':
        return authApi.logInUserWithFacebook(req, res);
      case 'google':
        return authApi.logInUserWithGoogle(req, res);
      default:
        return res
          .status(500)
          .json({ error: `Login type invalid : ${req.params.provider}` });
    }
  });
};

/**
 * Sign out a user by revoking his refresh token
 * @returns a result code in case of success or the errors
 */
exports.signOutUser = (req, res) => {
  cors(req, res, () => {
    authApi.signOut(req, res)
  });
};
