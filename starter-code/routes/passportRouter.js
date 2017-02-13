const express        = require("express");
const router         = express.Router();
// User model
const User           = require("../models/user");
// Bcrypt to encrypt passwords
const bcrypt         = require("bcrypt");
const bcryptSalt     = 10;
const ensureLogin = require("connect-ensure-login");
const passport      = require("passport");







router.get('/signup', function(req, res) {
  res.render('passport/signup');
});

router.post('/signup', (req, res, next) => {
  let username = req.body.username;
  let password = req.body.password;

  if (username === "" || password === "") {
    res.render("auth/signup", {
      errorMessage: "Please provide your name, email, and new password to sign up..."
    });
    return;
  }else{
    User.findOne({ username: username}, (err, user) => {
      if(err){
        next(err);
      } else {
        if(!user) {
          // no user
          var salt     = bcrypt.genSaltSync(bcryptSalt);
          var hashPass = bcrypt.hashSync(password, salt);


          //STORING THE USER INFORMATION IN THE DATABASE WITH APPROPRIATE VARIABLES
          var newUser  = User({
            username,
            password: hashPass
          });
          console.log(newUser);
          newUser.save((err) => {
            if (err) {
              next(err);
            } else {
              res.redirect("/");
            }
          });
        }else {
            res.render("passport/signup", {
            errorMessage: "Email taken!"
          });
        }
      }
    });
  }
});


router.get("/login", (req, res, next) => {
  res.render("passport/login");
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/private-page",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));


router.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});





module.exports = router;
