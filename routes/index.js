const router = require("express").Router();

const bcrypt = require("bcryptjs");
const saltRounds = 10;

const User = require("../models/User.model");

const isLoggedIn = require('../middleware/isLoggedIn');
const isLoggedOut = require('../middleware/isLoggedOut');
const isPrivate = require('../middleware/isPrivate');

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

router.get('/signup', isLoggedOut, (req, res, next) => {
  res.render('users/signup');
});

router.post("/signup", isLoggedOut, (req, res, next) => {
  let { username, password, passwordRepeat } = req.body;

  if (username == "" || password == "" || passwordRepeat == "") {
    res.render("users/signup", {
      errorMessage: "Rellenar todos los campos.",
    });
    return;
  }

  if (password != passwordRepeat) {
    res.render("users/signup", {
      errorMessage: "Las contraseñas no coinciden.",
    });
    return;
  }

  User.find({ username })
    .then((result) => {
      if (result.length != 0) {
        res.render("users/signup", {
          errorMessage:
            "El usuario ya existe.",
        });
        return;
      }

      let salt = bcrypt.genSaltSync(saltRounds);
      let passwordEncriptada = bcrypt.hashSync(password, salt);

      User.create({
        username,
        password: passwordEncriptada,
      })
        .then(() => {
          res.redirect("/user/login");
        })
        .catch((err) => next(err));
    })
    .catch((err) => next(err));
});

router.get('/login', isLoggedOut, (req, res, next) => {
  res.render('users/login');
});


router.post("/login", isLoggedOut, (req, res, next) => {
  let { username, password } = req.body;

  if (username == "" || password == "") {
    res.render("users/login", { errorMessage: "Faltan campos por rellenar." });
  }

  User.find({ username })
    .then((result) => {
      if (result.length == 0) {
        res.render("users/login", {
          errorMessage: "El usuario no existe, por favor regístrate.",
        });
      }

      if (bcrypt.compareSync(password, result[0].password)) {
        let usuario = {
          username: result[0].username,
        };

        req.session.currentUser = usuario;
        console.log("req.session.currentUser: ", req.session.currentUser);
        res.redirect("/user/main");
      } else {
        res.render("users/login", {
          errorMessage: "Credenciales incorrectas.",
        });
      }
    })
    .catch((err) => next(err));
});

router.get("/private", isLoggedIn, (req, res, next) => {
  console.log("req.session.currentUser: ", req.session.currentUser);
  res.render("users/private", { username: req.session.currentUser.username });
});

router.get("/logout", isLoggedIn, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) {
      next(err);
    } else {
      res.redirect("/user/login");
    }
  });
});

router.get("/private", isLoggedIn, isPrivate, (req, res, next) => {
  res.send("user/private");
});


router.get('/main', isLoggedOut, (req, res, next) => {
  res.render('users/main');
});

router.get("/private", isLoggedIn, (req, res, next) => {
  console.log("req.session.currentUser: ", req.session.currentUser);
  res.render("users/private", { username: req.session.currentUser.username });
});

module.exports = router;
