// https://www.youtube.com/watch?v=EMf29HhIsRc

import express from "express"; // Import Express.js for building the web server
import bodyParser from "body-parser";
import passport from "passport"; // Import Passport.js for building authentication
import LocalStrategy from "passport-local"; // Import the local strategy for username/password authentication       
import session from "express-session"; // Import express-session for managing user sessions (e.g. storing user data in session after login) 
import bcrypt from "bcrypt"; // Import bcrypt for password hashing and verification (e.g. compare passwords)
import router from "./router/router.js"
import dotenv from "dotenv";
import methodover from "method-override"; // Import method-override to support HTTP verbs like PUT and DELETE in forms (e.g. override POST to PUT/DELETE)

// Load environment variables from .env file in development mode
if(process.env.NODE_ENV !== "production") { dotenv.config();}


// Initialize the Express application
const app=express();

// Define the port number for the server to listen on (you can change this to any port you prefer, e.g. 3000, 8080, etc.)
const port=56280;



// Middleware setup
//app.get("/",(req,res) => {
//    res.render("home.ejs");
//})


app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

// Configure sessions w3schools.com/nodejs/nodejs_api_auth.asp
app.use(session({
    //secret: process.env.SESSION_SECRET,
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Parse request bodies w3schools.com/nodejs/nodejs_api_auth.asp 
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Protected route w3schools.com/nodejs/nodejs_api_auth.asp
app.get('/profile', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    res.json({ message: 'Profile accessed', user: req.session.user });
});

app.use(passport.initialize());
app.use(passport.session());

app.use("/",router);

app.listen(port,() => {
    console.log(`server is listening at http://localhost:${port}`);
})