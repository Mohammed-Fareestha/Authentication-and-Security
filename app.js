require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose')
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')
    // const mongooseEncryption = require('mongoose-encryption') ----> LEVEL 2
    // const md5 = require('md5') ------------------------------------> LEVEL 3
    // const bcrypt = require('bcrypt') ----------------------------------> LEVEL 4
    //     // Rounds 10 => 10 hashes/sec
    // const saltRound = 10

const app = express();

// console.log(process.env.API_KEY);

app.use(express.static("public"))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({
    extended: true
}))
app.use(session({
    secret: 'our little secret.',
    resave: false,
    saveUninitialized: false
}));

// app.use(passport.initialize());
// app.use(passport.session());
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRETS,
        callbackURL: "http://localhost:3000/auth/google/Authenticaton",
        userProfileURL: "http://www.googleleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
))

//mongoDB connection
mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema)

//Using Environment Variables to Keep Secrets Safe
// userSchema.plugin(mongooseEncryption, { secret: process.env.SECRET, encryptedFields: ["password"] })


/////GET request//////////
app.get('/', (req, res) => {
    res.render("home")
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/Authenticaton",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
    });

app.get('/login', (req, res) => {
    res.render("login")
})
app.get('/register', (req, res) => {
    res.render("register")
})
app.get('/secrets', (req, res) => {
    if (req.isAuthenticated()) {
        req.render('secrets')
    } else {
        res.redirect('/login')
    }
})

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        req.render('submit')
    } else {
        res.redirect('/login')
    }
})

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;
    console.log(req.body.id);

    User.findById(req.body.id, (req, res) => {
        if (err) {
            console.log(err)
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function() {
                    res.redirect('/secrets')
                })
            }
        }
    })
})

app.get('/logout', (req, res) => {
    req.logout()
    res.redirect('/')
})

//Register, the user who visit the page fist time they have to register over here with some validations
app.post('/register', (req, res) => {

    User.register({ username: req.body.username }, req.body.password, (err, User) => {
        if (err) {
            console.log(err);
            res.redirect('/register')
        } else {
            Passport.authenticate('local')(req, res, function() {
                res.redirect('/secrets')
            })
        };
    })
});
//Bcrypt Method// register
// bcrypt.hash(req.body.password, saltRound, function(err, hash) {
//     const newUser = new User({
//         email: req.body.username,
//         password: hash
//     })
//     newUser.save((err) => {
//         if (err) {
//             console.log(err)
//         } else {
//             res.render("secrets")
//         }
//     })
// });


//login with email & password, which we already give in register page if your email or password are worng it show the ERROR 
app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function(req, res) {
        if (err) {
            console.log(err)
        } else {
            Passport.authenticate('local')(req, res, function() {
                res.redirect('/secrets')
            })
        }
    })
});



//Bcrypt Method// login
// const username = req.body.username;
// const password = req.body.password;

// User.findOne({ email: username }, function(err, foundUser) {
//     if (err) {
//         console.log(err)
//     } else {
//         if (foundUser) {
//             // if (foundUser.password === password) {
//             bcrypt.compare(password, foundUser.password, function(err, result) {
//                 if (result === true) {
//                     res.render("secrets")
//                 }
//             });
//         }
//     }
// })


app.listen(3000, function() {
    console.log('sever started on PORT 3000')
})