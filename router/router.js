// https://expressjs.com/en/guide/routing.html

import express from "express";
const router = express.Router();

import 
{   destroySession,
    generateChallenge,
isAuthenticated,
loginUser,
    signupUser
} from "../controller/auth.js";

router.get("/", (req,res) => {
    // Check if there's a message query parameter (e.g., for displaying error/success messages on the signup page)
    const message = req.query.message; // e.g. cannot get /user 
    
    // Nonce generieren
    const nonce = generateChallenge();

    // In Session speichern (wichtig!)
    req.session.nonce = nonce;

    res.render("home.ejs", { 
        message,
        nonce 
    });
})

router.post("/login",loginUser)

router.get("/signup",(req,res)=> {
    res.render("signup.ejs")
})

router.post("/signup",signupUser);

router.get("/result", isAuthenticated, (req,res) => {
    res.render("result.ejs");
});

router.post("/logout", destroySession);

export default router;