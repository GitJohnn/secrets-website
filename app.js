//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require("bcrypt");
const saltRounds = 10;
//swap md5 with bcrypt
const md5 = require("md5");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));
//place code for express-session bellow
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true
}));

//we initialize express session with passport to establish authentication
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-jonathan:" + process.env.MONGO_ATLAS_PASSWORD + "@cluster0.k6ckh.mongodb.net/userDB",{useNewUrlParser:true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//no need for encryption since we now hash passwords.
//userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("user",userSchema);

passport.use(User.createStrategy());

//this is for local authentication only
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
//Session authentication local and with other instances
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//passport use Google strategy setup
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://fathomless-cove-48237.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile); Use to see which values can be saved to local database
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//passpor use Facebook strategy setup
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://fathomless-cove-48237.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ facebookId:profile.id }, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { successRedirect: "/secrets" ,failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { successRedirect: "/secrets",  failureRedirect: "/login" }));

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else if(foundUsers){
        res.render("secrets",{usersWithSecrets:foundUsers});
    }
  });
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }
  // else{
  //   res.redirect("/login");
  // }
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/")
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit")
  }
  else{
    res.redirect("/login")
  }
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user._id,function(err,foundUser){
    if(err){
      console.log(err);
    }
    else if(foundUser){
      foundUser.secret = submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/register",function(req,res){
  User.register({username:req.body.username},req.body.password,function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })
  //bcrypt.hash(req.body.password,saltRounds,function(err,hash){
  //  const newUser = new User({
  //    email: req.body.username,
  //    password: hash//md5(req.body.password)
  //  })
  //  newUser.save(function(err){
  //    if(err){
  //      console.log(err);
  //    }else{
  //      console.log("Successfully added new user");
  //      res.render("secrets");
  //    }
  //  })
  //});
});//register post ending

app.post("/login",function(req,res){
  const user = new User({
    username:req.body.username,
    password: req.body.passport
  });

  req.login(user,function(err){
    if(err){
      console.log(err);
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  });

  //const username = req.body.username;
  //const password = req.body.password;
  //User.findOne({email:username},function(err,foundUser){
  //    if(foundUser){
  //      bcrypt.compare(password,foundUser.password,function(err,result){
  //        if(result===true){
  //          console.log("Successfully logged in");
  //          res.render("secrets");
  //        }
  //      })
  //    }
  //    else{
  //      console.log(err);
  //    }
  //});
});//login post ending

let port = process.env.PORT;
if(port == null || port==""){
  port = 3000;
}


app.listen(port,function(){
  console.log("Server has Started Successfully");
});
