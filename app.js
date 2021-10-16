/* GENERAL STUFF */

//Enviroment variables
//Hashing Passwords & salt 
//Cookies & sessions 

//Require Modules
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const exp = require("constants");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


//Start express
const app = express();


//Folder for the static folders 
app.use(express.static("public"));

//EJS route
app.set('view engine', 'ejs');

//Parse the body
app.use(express.urlencoded({
    extended: true
}));

/* DB STUFF */

//Connect to the DB

//Session default options

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

//Passport init

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true })

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//Set passportmongoose to hash an salt passwords

userSchema.plugin(passportLocalMongoose);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());



/* RENDER STUFF */

//Render Index
app.get("/", function(req, res) {
    res.render("home");
})


//Render Login

app.get("/login", function(req, res) {
    res.render("login", { errMsg: "", username: "", password: "" });
})

//Render Register

app.get("/register", function(req, res) {
    res.render("register");
})

//Render secrets
app.get("/secrets", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

//Render Logout

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});

/* REGISTER POST */

app.post("/register", function(req, res) {
    User.register({ username: req.body.username }, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    })
});

/* LOGIN POST */

app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            })
        }
    })

});


//Listen on 3000
app.listen(3000, function() {
    console.log("Server up");
})