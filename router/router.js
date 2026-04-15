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

router.get("/api/resolve", async (req, res) => {
    const { did } = req.query;

    // 1. Input validieren
    if (!did) {
        return res.status(400).json({ error: "DID fehlt" });
    }

    try {
        // 2. DID auflösen
        const response = await fetch(`http://localhost:8080/1.0/identifiers/${did}`);

        if (!response.ok) {
            return res.status(response.status).json({ error: "DID nicht gefunden" });
        }

        const data = await response.json();

        // 3. Optional: Nur relevante Daten extrahieren
        const didDocument = data.didDocument;

        if (!didDocument) {
            return res.status(500).json({ error: "Ungültige DID-Antwort" });
        }

        // 🔑 Beispiel: Public Key extrahieren (für Challenge später!)
        const verificationMethod = didDocument.verificationMethod?.[0];

        res.json({
            did: did,
            didDocument,
            verificationMethod
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

export default router;