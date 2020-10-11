const admin = require('firebase-admin');

const {
    validatePasswordSignupData,
    validatePasswordLoginData,
} = require('./validators');
const { createUserDocument } = require('../../util/database/users');
const { createProfileDocument } = require('../../util/database/profiles');

class AuthApi {
    /**
     * Create a user and profile document
     * @param {firebase.auth.UserCredential} data
     */
    createDocuments(data) {
        admin
            .firestore()
            .collection('profiles')
            .doc(data.uid)
            .set(createProfileDocument(data));
        admin
            .firestore()
            .collection('users')
            .doc(data.uid)
            .set(createUserDocument(data));
    }

    /**
     * Sign up a user giving in the request body an email, a password, and a confirm password.
     * 1) Validate the format of the email, the password, and the confirm password and check if
     * the passwords match
     * 2) Create the user and the documents associated (profile and user document)
     * @returns a result code, the uid, and a firebase id token in case of success, or the errors
     */
    signUpUserWithPassword(req, res) {
        const email = req.body.email;
        const password = req.body.password;
        const confirmPassword = req.body.confirm_password;
        const displayName = req.body.name;

        const { errors, valid } = validatePasswordSignupData(
            email,
            password,
            confirmPassword
        );

        if (!valid) {
            return res.status(400).json({ errors });
        }

        admin.auth().createUser({
            email: email,
            emailVerified: false,
            password: password,
            displayName: displayName,
            disabled: false

        }).then(function (userRecord) {
            authApi.createDocuments(userRecord)

            return res.status(201).json({
                result: 'auth/success-signup',
                data,
            });
        }).catch(function (error) {
            switch (error.code) {
                case 'auth/weak-password':
                case 'auth/email-already-in-use':
                    return res.status(403).json({ errors: { email: error.code } });
                default:
                    return res.status(500).json({ errors: { general: error.code } });
            }
        });
    }

    /**
     * When the user logged in, we update :
     * - the last login timestamp
     * - the boolean indicating if the user is new (older than one week)
     * @param {firebase.auth.UserCredential} data
     */
    updateUserData(data) {
        const {
            creationTime: createdAt,
            lastSignInTime: lastLoginAt,
        } = data.metadata;
        const newUserData = { 'metadata.lastLoginAt': Date.now() }; // nested object update
        // 604800000 ms = 1 week
        if (lastLoginAt > createdAt + 604800000) {
            Object.assign(newUserData, { isNew: false });
        }
        return admin
            .firestore()
            .collection('users')
            .doc(data.uid)
            .update(newUserData)
            .catch((err) => { });
    }

    /**
     * Log in a user with his email and password.
     * 1) Validate the format of the email, the password
     * 2) Update the last login timestamp in the user document and perhaps if he's always new
     * @returns a result code, the uid, and a firebase id token in case of success, or the errors
     */
    logInUserWithPassword(req, res) {
        const email = req.body.email;
        const password = req.body.password;

        const { errors, valid } = validatePasswordLoginData(email, password);

        if (!valid) {
            return res.status(400).json({ errors });
        }

        let uid;
        return admin
            .auth()
            .signInWithEmailAndPassword(email, password)
            .then((data) => {
                updateUserData(data);
                uid = data.uid;
                return data.getIdToken();
            })
            .then((token) => {
                console.log(`User ${email} logged in successfully with a password`);
                return res.status(200).json({ result: 'auth/success-login', uid, token });
            })
            .catch((err) => {
                switch (err.code) {
                    case 'auth/wrong-password':
                    case 'auth/invalid-email':
                    case 'auth/user-not-found':
                    case 'auth/user-disabled':
                    case 'auth/user-token-expired':
                    default:
                        return res.status(403).json({ error: err.code });
                }
            });
    }

    /**
     * Log in a user with a Facebook account. This could be also a signup.
     * 1) Check the Facebook access token in the body of the request
     * 2) Create the Firebase credential and sign in it
     * 3) In case of | signup : create the user and profile documents in firestone,
     *               | signin : update the last login timestamp in the user collection and if he's no longer new
     * @returns a result code, the uid, and a firebase id token in case of success, or the errors
     */
    logInUserWithFacebook(req, res) {
        const token = req.body.access_token;
        if (!token || token === '') {
            return res
                .status(400)
                .json({ error: 'auth/facebook/invalid-access-token' });
        }

        const credential = admin.auth.FacebookAuthProvider.credential(token);
        let isNew, email, uid;

        return admin
            .auth()
            .signInWithCredential(credential)
            .then((data) => {
                isNew = data.additionalUserInfo.isNewUser;
                if (isNew) {
                    authApi.createDocuments(data);
                } else {
                    authApi.updateUserData(data);
                }
                uid = data.user.uid;
                email = data.user.email;
                return data.user.getIdToken();
            })
            .then((token) => {
                console.log(
                    `User ${email} ` +
                    (isNew ? 'signed up' : 'logged in') +
                    ' successfully with Facebook'
                );
                return res.status(isNew ? 201 : 200).json({
                    result: isNew ? 'auth/success-signup' : 'auth/success-login',
                    uid,
                    token,
                });
            })
            .catch((err) => {
                switch (err.code) {
                    case 'auth/user-disabled':
                    case 'auth/account-exists-with-different-credential':
                    case 'auth/user-token-expired':
                    default:
                        return res.status(403).json({ error: err.code });
                }
            });
    }

    /**
     * Log in a user with a Google account. This could be also a signup.
     * 1) Check the Google id token in the body of the request
     * 2) Create the Firebase credential and sign in it
     * 3) In case of | signup : create the user and profile documents in firestone,
     *               | signin : update the last login timestamp in the user collection and if he's no longer new
     * @returns a result code and a firebase id token in case of success, or the errors
     */
    logInUserWithGoogle(req, res) {
        const token = req.body.id_token;
        if (!token || token === '') {
            return res.status(400).json({ error: 'auth/google/invalid-id-token' });
        }

        const credential = admin.auth.GoogleAuthProvider.credential(token);
        let isNew, email, uid;

        return admin
            .auth()
            .signInWithCredential(credential)
            .then((data) => {
                isNew = data.additionalUserInfo.isNewUser;
                if (isNew) {
                    authApi.createDocuments(data);
                } else {
                    authApi.updateUserData(data);
                }
                uid = data.uid;
                email = data.email;
                return data.getIdToken();
            })
            .then((token) => {
                console.log(
                    `User ${email} ` +
                    (isNew ? 'signed up' : 'logged in') +
                    ' successfully with Google'
                );
                return res.status(isNew ? 201 : 200).json({
                    result: isNew ? 'auth/success-signup' : 'auth/success-login',
                    uid,
                    token,
                });
            })
            .catch((err) => {
                switch (err.code) {
                    case 'auth/user-disabled':
                    case 'auth/user-token-expired':
                    default:
                        return res.status(403).json({ error: err.code });
                }
            });
    }

    signOut(req, res) {
        return admin
            .auth()
            .revokeRefreshTokens(req.params.uid)
            .then(() => {
                return admin.auth().getUser(req.params.uid);
            })
            .then((userRecord) => {
                console.log(`User ${userRecord.email} signed out successfully`);
                return res.status(200).json({ result: 'auth/success-signout' });
            })
            .catch((err) => {
                return res.status(500).json({ error: err.code });
            });
    }
}

var authApi = new AuthApi();

module.exports = authApi;
