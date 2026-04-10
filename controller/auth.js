// https://www.w3schools.com/nodejs/nodejs_api_auth.asp

import pg from "pg"; // Import the pg library for PostgreSQL database interaction
import bcrypt from "bcrypt"; // Import bcrypt for password hashing and verification (e.g. compare passwords) 
import LocalStrategy from "passport-local"; // Import the local strategy for username/password authentication  
import session from "express-session"; // Import express-session for managing user sessions (e.g. storing user data in session after login)
import bodyParser from "body-parser"; // Import body-parser for parsing incoming request bodies (e.g. form data in POST requests)
import express from "express"; // Import Express.js for building the web server
import crypto from "crypto"; // Import crypto for generating random challenges (e.g. for challenge-response authentication)

const db = new pg.Client({
    host: "localhost",
    user: "postgres",
    database: "did-poc",
    password: "did-poc",
    port: "5432",
})
db.connect();




export function generateChallenge(req, res) {
    return crypto.randomBytes(32).toString('hex'); // Generate a random challenge (32 bytes converted to hex string)
    
}

function verifySignature(nonce, signature, publicKey) {
    return crypto.verify(
        "sha256",
        Buffer.from(nonce),
        publicKey,
        Buffer.from(signature, "base64")
    );
}

export async function loginUser(req, res) {
    const loginData = {
        username: req.body.username,
        did: req.body.did,
    }
    try {
        const result = await db.query("SELECT * FROM users WHERE did=$1;", [loginData.did])
        result.rows.forEach(row => {
            console.log("DB DID: " + row.did);
        })
        if (result.rows.length === 1 && result.rows[0].did === loginData.did) {
            console.log("lOGIN DATA did: " + loginData.did);
            // Store user information in session (excluding password) w3schools.com/nodejs/nodejs_api_auth.asp
            req.session.user = {
                did: result.rows[0].did,
                username: result.rows[0].username
            };

            // Redirect to result page after successful login
            res.redirect("/result");
        } else {
            console.log("lOGIN DATA did: " + loginData.did);
            res.redirect("/?message=Invalid%20credentials.%20Please%20try%20again.")
        }
    } catch (error) {
        console.log(error);
    }
}

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


