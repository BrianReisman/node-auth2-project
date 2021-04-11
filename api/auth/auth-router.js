const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const JWT_SECRET = require("../secrets");
const Users = require("../users/users-model");
const bcrytp = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { permittedCrossDomainPolicies } = require("helmet");

router.post("/register", validateRoleName, async (req, res, next) => {
  const credentials = req.body;
  try {
    const hash = bcrytp.hashSync(credentials.password, 10);
    credentials.password = hash;

    Users.add(credentials)
      .then((user) => {
        // const token = generateToken(user)
        res.status(201).json(user);
      })
      .catch((err) => {
        console.log(err);
        res.status(400).json({
          message: "unable to add user, try unique information",
          ...err,
        });
      });
  } catch (error) {
    res.status(500).json({
      message: "server side issue",
      ...error,
    });
  }
});

router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body;
  Users.findBy({ username }).then(([user]) => {
    if (user && bcrytp.compareSync(password, user.password)) {
      const token = generateToken(user);
      res.status(200).json({ message: "welcome to the api", token });
    } else {
      res.status(400).json({ message: "invalid password" });
    }
  });

  //   res.status(500).json({
  //     message: "server side issue",
  //     ...err,
  //   });

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    rolename: user.rolename,
  };
  const options = {
    expiresIn: "1h",
  };

  const token = jwt.sign(payload, JWT_SECRET.jwtSecret, options);

  return token;
}

module.exports = router;
