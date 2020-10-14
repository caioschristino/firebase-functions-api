const express = require('express');
const { signUpUser, logInUser, signOutUser, generateToken } = require('../../api/auth');
const verifyAuth = require('../middlewares/verifyAuth');

const route = express.Router();

route.post('/token/connect', generateToken);
route.post('/signup/:provider', signUpUser);
route.post('/login/:provider', logInUser);
route.post('/signout/:uid', verifyAuth, signOutUser);

module.exports = route;
