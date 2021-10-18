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
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


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
    password: String,
    googleId: String,
    secret: Array
});

//Set passportmongoose to hash an salt passwords

userSchema.plugin(passportLocalMongoose);
//Make find or create user
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    })
})

//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

//Google Auth


passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id, username: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));



/* RENDER STUFF */

//Render Index
app.get("/", function(req, res) {
    res.render("home");
})

//Google auth
app.route('/auth/google')

.get(passport.authenticate('google', {

    scope: ["profile"]

}));

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });



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
    User.find({ "secret": { $ne: null } },
        function(err, foundUsers) {
            if (err) {
                console.log(err);
            } else {
                if (foundUsers) {
                    res.render("secrets", { usersWithSecrets: foundUsers })
                }
            }
        });
});

//Render Logout

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});

//Render Submit

app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }

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

//Submit post

app.post("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        User.findById(req.user.id, function(err, user) {
            user.secret.push(req.body.secret);
            user.save(function() {
                res.redirect("/secrets");
            });
        });

    } else {
        res.redirect("/login");
    }
});

/*app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;
            foundUser.save(function() {
                res.redirect("/secrets");
            });
        }
    });

});*/


//Listen on 3000
app.listen(3000, function() {
    console.log("Server up");
})