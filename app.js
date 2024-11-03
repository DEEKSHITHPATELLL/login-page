const express = require('express');
const userModel = require("./models/usermodel");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const app = express();

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.get('/register', (req, res) => {
    const error = req.query.error || null;
    res.render("register", { error });
});

app.get('/login', (req, res) => {
    const error = req.query.error || null;
    const success = req.query.success || null;
    res.render("login", { error, success }); 
});


app.post('/register', async (req, res) => {
    let { username, email, password } = req.body;
    let user = await userModel.findOne({ email });

    if (user) {
        return res.redirect('/register?error=User already exists');
    } else {
        bcrypt.genSalt(10, (err, salt) => {
            if (err) throw err;
            bcrypt.hash(password, salt, async (err, hash) => {
                if (err) throw err;
                let newUser = await userModel.create({
                    username,
                    email,
                    password: hash
                });
                let token = jwt.sign({ email: email, userid: newUser._id }, "Deek");
                res.cookie("tokens", token);
                return res.send("Your account registered successfully");
            });
        });
    }
});

app.post('/login', async (req, res) => {
    let { email, password } = req.body;
    try {
        let user = await userModel.findOne({ email });

        if (!user) {
            return res.redirect('/register?error=User does not exist');
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error("Error comparing passwords:", err);
                res.status(500).send("An error occurred while verifying the password.");
                return;
            }
            if (result) {
                let token = jwt.sign({ email: email, userid: user._id }, "Deek");
                res.cookie("tokens", token);
                return res.redirect("/profile");
            } else {
                return res.redirect('/login?error=Incorrect password, please try again');
            }
        });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).send("An error occurred during login.");
    }
});

app.get('/logout', (req, res) => {
    res.cookie("tokens", " ");
    res.redirect("/login");
});
function isloggedin(req, res, next) {
    let token = req.cookies.tokens;
    if (!token || token === " ") {
        return res.redirect('/login'); 
    }
    try {
        let data = jwt.verify(token, "Deek");
        req.user = data;
        next();
    } catch (err) {
        return res.redirect('/login'); 
    }
}
app.get('/profile', isloggedin, (req, res) => {
    if(!req.user)
    {
        res.send("user doesnot exist")
    }
    else{
    console.log(req.user);
    res.render("profile");
    }
});
app.listen(8080, () => {
    console.log('Server started');
});
