// https://www.w3schools.com/nodejs/nodejs_api_auth.asp

// https://nodejs.org/api/crypto.html

import pg from "pg"; // Import the pg library for PostgreSQL database interaction
import bcrypt from "bcrypt"; // Import bcrypt for password hashing and verification (e.g. compare passwords) 
import LocalStrategy from "passport-local"; // Import the local strategy for username/password authentication  
import session from "express-session"; // Import express-session for managing user sessions (e.g. storing user data in session after login)
import bodyParser from "body-parser"; // Import body-parser for parsing incoming request bodies (e.g. form data in POST requests)
import express from "express"; // Import Express.js for building the web server
import crypto from "crypto"; // Import crypto for generating random challenges (e.g. for challenge-response authentication)
import { verify } from "@stablelib/ed25519";
import { base58btc } from "multiformats/bases/base58";
import { prepareDataForSigning } from "didwebvh-ts";

const db = new pg.Client({
    host: "localhost",
    user: "postgres",
    database: "did-poc",
    password: "postgres",
    port: "5432",
})
db.connect()
    .then(() => console.log("DB connected"))
    .catch(err => console.error("DB connection failed:", err.message));




export function generateChallenge() {
    return crypto.randomBytes(32).toString('hex'); // Generate a random challenge (32 bytes converted to hex string)

}

function decodePublicKey(multibaseKey) {
    const bytes = base58btc.decode(multibaseKey);

    // remove multicodec prefix (first 2 bytes for ed25519)
    return bytes.slice(2);
}

function decodeSignature(signature) {
    return base58btc.decode(signature);
}

function verifySignature(nonce, signature, publicKey) {
    const decodedPublicKey = decodePublicKey(publicKey);
    const decodedSignature = decodeSignature(signature);

    const message = Buffer.from(nonce, "hex");

    return verify(
        decodedPublicKey,
        message,
        decodedSignature
    );
}

export async function loginUser(req, res) {
    const loginData = {
        did: req.body.did,
        signedChallenge: req.body.signedChallenge
    }

    if (!loginData.did) {
        return res.status(400).json({ error: "DID fehlt" });
    }

    if (!loginData.signedChallenge) {
        return res.status(400).json({ error: "Signatur fehlt" });
    }

    try {

        const challenge = req.session.challenge;

        if (!challenge) {
            return res.status(400).json({ error: "Keine Challenge vorhanden" });
        }

        // Expiry prüfen
        if (Date.now() > challenge.expiresAt) {
            delete req.session.challenge;
            return res.status(400).json({ error: "Challenge abgelaufen" });
        }

        // 2. DID auflösen
        //console.log(loginData.did);
        const response = await fetch(`http://localhost:8080/1.0/identifiers/${loginData.did}`);
        //console.log("DID Resolution Response: ", response);
        //console.log("DID Resolution Response CONTENT: ", response);
        if (!response.ok) {
            return res.status(response.status).json({ error: "DID nicht gefunden" });
        }

        const data = await response.json();

        //console.log("DID Document: ", data.didDocument);

        // 3. Optional: Nur relevante Daten extrahieren
        const didDocument = data.didDocument;

        if (!didDocument) {
            return res.status(500).json({ error: "Ungültige DID-Antwort" });
        }

        // 🔑 Beispiel: Public Key extrahieren (für Challenge später!)
        const verificationMethod = didDocument.verificationMethod?.[0];
        //console.log("Verification Method: ", verificationMethod);

        console.log("Nonce in Session: ", challenge.value);
        console.log("Signed Challenge: ", loginData.signedChallenge);
        console.log("Verification Method: ", verificationMethod);
        console.log("Public Key: ", verificationMethod.publicKeyMultibase);

        const isSignatureValid = await verifySignature(challenge.value, loginData.signedChallenge, verificationMethod.publicKeyMultibase);

        if (!isSignatureValid) {
            delete req.session.challenge;
            return res.status(400).json({ error: "Ungültige Signatur" });
        } else {
            console.log("Signature valid! User authenticated.");
            delete req.session.challenge;
            req.session.didDocument = didDocument; // Store DID Document in session for later use
        }

        //console.log("DID Document: ", didDocument);
        //console.log("Verification Method: ", verificationMethod);

    } catch (err) {
        console.error("Error during DID resolution: ", err.message);
        return res.status(500).json({ error: err.message });
    }


    try {
        const result = await db.query("SELECT * FROM users WHERE did=$1;", [loginData.did])
        result.rows.forEach(row => {
            console.log("DB DID: " + row.did);
        })
        if (result.rows.length === 1 && result.rows[0].did === loginData.did) {
            console.log("lOGIN DATA did: " + loginData.did + " and " + loginData.signedChallenge);


            // Store user information in session (excluding password) w3schools.com/nodejs/nodejs_api_auth.asp
            req.session.user = {
                did: result.rows[0].did,
                username: result.rows[0].username
            };

            // Redirect to result page after successful login
            return res.redirect("/result");
        } else {
            console.log("lOGIN DATA did: " + loginData.did);
            return res.redirect("/?message=Invalid%20credentials.%20Please%20try%20again.")
        }
    } catch (error) {
        console.log(error);
        return res.status(500).send("DB error");
    }
}



/*
export async function signupUser(req, res) {
    const signupData = {
        username: req.body.username,
        did: req.body.did,
    }
    try {
        const checkUserRegistered = await db.query("SELECT * FROM users WHERE did=$1;", [signupData.did]);
        if (checkUserRegistered.rows.length > 0) {
            res.redirect("/?message=User%20already%20registered.%20Please%20login.")
        } else {
            bcrypt.hash(signupData.did, saltRounds, async function (err, hash) {
                if (err) {
                    console.error("ERROR HASHING PASSWORD : ", err);
                }
                else {

                    const result = await db.query("INSERT INTO users(username, did) VALUES($1, $2) RETURNING *;", [signupData.username, signupData.did])
                    const user = result.rows[0];
                    res.redirect("/result")
                }
            })
        }
    } catch (error) {
        console.log(error)
    }
}*/

export async function signupUser(req, res) {
    const signupData = {
        username: req.body.username,
        did: req.body.did,
    };

    try {
        const checkUserRegistered = await db.query(
            "SELECT * FROM users WHERE did=$1;",
            [signupData.did]
        );

        if (checkUserRegistered.rows.length > 0) {
            return res.redirect("/?message=User%20already%20registered.%20Please%20login.");
        }

        await db.query(
            "INSERT INTO users(username, did) VALUES($1, $2);",
            [signupData.username, signupData.did]
        );

        return res.redirect("/result");

    } catch (error) {
        console.log(error);
        res.status(500).send("Server error");
    }
}

export function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();  // User is authenticated, proceed to the next middleware/route handler
    } else {
        res.status(401).json({ message: 'Unauthorized' }); // User is not authenticated, return 401 Unauthorized
    }
}

export function destroySession(req, res) {
    // Destroy session
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.json({ message: 'Logout successful' });
    });
}