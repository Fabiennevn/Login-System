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

function prepareEncodedData(input) {
    return base58btc.decode(input);
}

function verifySignature(nonce, signature, publicKey) {
    const decodedPublicKey = prepareEncodedData(publicKey).slice(2); // Remove the first 2 bytes (multicodec prefix)
    const decodedSignature = prepareEncodedData(signature);

    // hex to bytes
    const message = Buffer.from(nonce, "hex");

    return verify(
        decodedPublicKey,
        message,
        decodedSignature
    );
}

function checkExpiry(challenge) {
    return Date.now() > challenge.expiresAt;
}

function consoleLogMessage(message, logInput) {
    console.log("***************************************************************");
    console.log(" ");
    console.log(message, logInput);
    console.log(" ");
    console.log("***************************************************************");
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

        // If challenge is expired, delete it from session and return error
        if (checkExpiry(challenge)) {
            delete req.session.challenge;
            return res.status(400).json({ error: "Challenge abgelaufen" });
        }

        // 2. DID auflösen
        const response = await fetch(`http://localhost:8080/1.0/identifiers/${loginData.did}`);
        consoleLogMessage("DID Resolution Response: ", response);

        if (!response.ok) {
            return res.status(response.status).json({ error: "DID nicht gefunden" });
        }

        const data = await response.json();

        const didDocument = data.didDocument;
        consoleLogMessage("DID Document: ", didDocument);

        if (!didDocument) {
            return res.status(500).json({ error: "Ungültige DID-Antwort" });
        }

        // get first element out of verification method array
        const verificationMethod = didDocument.verificationMethod?.[0];

        consoleLogMessage("Nonce in Session: ", challenge.value);
        consoleLogMessage("Signed Challenge: ", loginData.signedChallenge);
        consoleLogMessage("Verification Method: ", verificationMethod);
        consoleLogMessage("Public Key: ", verificationMethod.publicKeyMultibase);

        const isSignatureValid = await verifySignature(challenge.value, loginData.signedChallenge, verificationMethod.publicKeyMultibase);

        if (!isSignatureValid) {
            delete req.session.challenge;
            return res.status(400).json({ error: "Ungültige Signatur" });
        }

        delete req.session.challenge;
        req.session.didDocument = didDocument; // Store DID Document in session for later use

        const result = await db.query("SELECT did, username FROM users WHERE did=$1;", [loginData.did])
        /*
        result.rows.forEach(row => {
            console.log("DB DID: " + row.did);
        })*/
        if (result.rows.length !== 1) {
            return res.redirect("/?message=Invalid%20credentials.%20Please%20try%20again.")
        }

        // Store user information in session (excluding password) w3schools.com/nodejs/nodejs_api_auth.asp
        req.session.user = {
            did: result.rows[0].did,
            username: result.rows[0].username
        };

        // Redirect to result page after successful login
        return res.redirect("/result");

    } catch (err) {
        console.error("Error during DID resolution: ", err.message);
        return res.status(500).json({ error: err.message });
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
        did: req.body.did,
        signedChallenge: req.body.signedChallenge
    };
    
    if (!signupData.did) {
        return res.status(400).json({ error: "DID fehlt" });
    }

    if (!signupData.signedChallenge) {
        return res.status(400).json({ error: "Signatur fehlt" });
    }

    try {
        const challenge = req.session.challenge;

        if (!challenge) {
            return res.status(400).json({ error: "Keine Challenge vorhanden" });
        }

        // If challenge is expired, delete it from session and return error
        if (checkExpiry(challenge)) {
            delete req.session.challenge;
            return res.status(400).json({ error: "Challenge abgelaufen" });
        }

        // 2. DID auflösen
        const response = await fetch(`http://localhost:8080/1.0/identifiers/${signupData.did}`);
        consoleLogMessage("DID Resolution Response: ", response);

        if (!response.ok) {
            return res.status(response.status).json({ error: "DID nicht gefunden" });
        }

        const data = await response.json();

        const didDocument = data.didDocument;
        consoleLogMessage("DID Document: ", didDocument);

        if (!didDocument) {
            return res.status(500).json({ error: "Ungültige DID-Antwort" });
        }

        const checkUserRegistered = await db.query(
            "SELECT * FROM users WHERE did=$1;",
            [signupData.did]
        );

        if (checkUserRegistered.rows.length > 0) {
            return res.redirect("/?message=User%20already%20registered.%20Please%20login.");
        }

        // get first element out of verification method array
        const verificationMethod = didDocument.verificationMethod?.[0];

        consoleLogMessage("Nonce in Session: ", challenge.value);
        consoleLogMessage("Signed Challenge: ", signupData.signedChallenge);
        consoleLogMessage("Verification Method: ", verificationMethod);
        consoleLogMessage("Public Key: ", verificationMethod.publicKeyMultibase);

        const isSignatureValid = await verifySignature(challenge.value, signupData.signedChallenge, verificationMethod.publicKeyMultibase);

        if (!isSignatureValid) {
            delete req.session.challenge;
            return res.status(400).json({ error: "Ungültige Signatur" });
        }

        delete req.session.challenge;
        req.session.didDocument = didDocument; // Store DID Document in session for later use

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