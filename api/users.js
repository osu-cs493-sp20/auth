/*
 * API routes for 'users' collection.
 */

const router = require('express').Router();

const { validateAgainstSchema } = require('../lib/validation');
const {
  UserSchema,
  insertNewUser,
  getUserById,
  validateUser
} = require('../models/user');
const { generateAuthToken, requireAuthentication } = require('../lib/auth');

router.post('/', async (req, res) => {
  if (validateAgainstSchema(req.body, UserSchema)) {
    try {
      const id = await insertNewUser(req.body);
      res.status(201).send({
        _id: id
      });
    } catch (err) {
      console.error("  -- Error:", err);
      res.status(500).send({
        error: "Error inserting new user.  Try again later."
      });
    }
  } else {
    res.status(400).send({
      error: "Request body does not contain a valid User."
    });
  }
});

router.get('/:id', requireAuthentication, async (req, res, next) => {
  if (req.user !== req.params.id) {
    res.status(403).send({
      error: "Unauthorized to access the specified resource"
    });
  } else {
    try {
      const user = await getUserById(req.params.id);
      if (user) {
        res.status(200).send(user);
      } else {
        next();
      }
    } catch (err) {
      console.error("  -- Error:", err);
      res.status(500).send({
        error: "Error fetching user.  Try again later."
      });
    }
  }
});

router.post('/login', async (req, res) => {
  if (req.body && req.body.id && req.body.password) {
    try {
      const authenticated = await validateUser(
        req.body.id,
        req.body.password
      );
      if (authenticated) {
        const token = generateAuthToken(req.body.id);
        res.status(200).send({
          token: token
        });
      } else {
        res.status(401).send({
          error: "Invalid authentication credentials."
        })
      }
    } catch (err) {
      console.error("  -- error:", err);
      res.status(500).send({
        error: "Error logging in.  Try again later."
      });
    }
  } else {
    res.status(400).send({
      error: "Request body needs a user ID and password."
    });
  }
});

module.exports = router;
