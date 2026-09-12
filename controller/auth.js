// controller/auth.js

import pg from "pg";
import crypto from "crypto";
import { verify } from "@stablelib/ed25519";
import { base58btc } from "multiformats/bases/base58";

const db = new pg.Client({
    host: "localhost",
    user: "postgres",
    database: "did-poc",
    password: "postgres",
    port: "5432",
});

db.connect()
    .then(() => console.log("DB connected"))
    .catch((err) =>
        console.error("DB connection failed:", err.message)
    );

export function generateChallenge() {
    return crypto.randomBytes(32).toString("hex");
}

function prepareEncodedData(input) {
    return base58btc.decode(input);
}


function verifySignature(nonce, signature, publicKey) {

    // Decode public key from Multibase/Base58BTC
    // First 2 bytes are the multicodec prefix and are removed
    const decodedPublicKey =
        prepareEncodedData(publicKey).slice(2);

    // Decode signature from Multibase/Base58BTC
    const decodedSignature =
        prepareEncodedData(signature);

    // Convert nonce from hex string to bytes
    const message =
        Buffer.from(nonce, "hex");

    // Verify Ed25519 signature
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

    console.log(
        "***************************************************************"
    );

    console.log(" ");

    console.log(
        message,
        logInput
    );

    console.log(" ");

    console.log(
        "***************************************************************"
    );
}

export async function loginUser(req, res) {

    const loginData = {
        did: req.body.did,
        signedChallenge: req.body.signedChallenge
    };

    if (!loginData.did) {
        return res.status(400).json({
            error: "DID fehlt"
        });
    }


    if (!loginData.signedChallenge) {
        return res.status(400).json({
            error: "Signatur fehlt"
        });
    }


    try {


        const challenge =
            req.session.challenge;


        if (!challenge) {
            return res.status(400).json({
                error: "Keine Challenge vorhanden"
            });
        }

        if (checkExpiry(challenge)) {

            delete req.session.challenge;

            return res.status(400).json({
                error: "Challenge abgelaufen"
            });
        }


        const response = await fetch(
            `http://localhost:8081/1.0/identifiers/${loginData.did}`
        );


        consoleLogMessage(
            "DID Resolution Response: ",
            response
        );


        if (!response.ok) {

            return res
                .status(response.status)
                .json({
                    error: "DID nicht gefunden"
                });
        }


        const data =
            await response.json();


        const didDocument =
            data.didDocument;


        consoleLogMessage(
            "DID Document: ",
            didDocument
        );


        if (!didDocument) {

            return res.status(500).json({
                error: "Ungültige DID-Antwort"
            });
        }

        const verificationMethod =
            didDocument.verificationMethod?.[0];


        if (!verificationMethod?.publicKeyMultibase) {

            return res.status(400).json({
                error:
                    "Kein gültiger Public Key im DID Document"
            });
        }


        consoleLogMessage(
            "Nonce in Session: ",
            challenge.value
        );


        consoleLogMessage(
            "Signed Challenge: ",
            loginData.signedChallenge
        );


        consoleLogMessage(
            "Verification Method: ",
            verificationMethod
        );


        consoleLogMessage(
            "Public Key: ",
            verificationMethod.publicKeyMultibase
        );

        const isSignatureValid =
            verifySignature(
                challenge.value,
                loginData.signedChallenge,
                verificationMethod.publicKeyMultibase
            );


        if (!isSignatureValid) {

            delete req.session.challenge;

            return res.status(400).json({
                error: "Ungültige Signatur"
            });
        }

        const result =
            await db.query(
                `SELECT did, username
                 FROM users
                 WHERE did=$1;`,
                [loginData.did]
            );


        if (result.rows.length !== 1) {

            return res.redirect(
                "/?message=Invalid%20credentials.%20Please%20try%20again."
            );
        }

        delete req.session.challenge;


        req.session.user = {
            did: result.rows[0].did,
            username: result.rows[0].username
        };


        req.session.didDocument =
            didDocument;

        req.session.save((err) => {

            if (err) {

                console.error(
                    "Session save error:",
                    err
                );

                return res.status(500).json({
                    error:
                        "Session konnte nicht gespeichert werden"
                });
            }

            return res.redirect("/result");

        });


    } catch (error) {

        console.error(
            "Error during login:",
            error
        );


        return res.status(500).json({
            error: "Server error"
        });
    }
}

export async function signupUser(req, res) {

    const signupData = {
        username: req.body.username,
        did: req.body.did,
        signedChallenge: req.body.signedChallenge
    };

    if (!signupData.username) {

        return res.status(400).json({
            error: "Username fehlt"
        });
    }


    if (!signupData.did) {

        return res.status(400).json({
            error: "DID fehlt"
        });
    }


    if (!signupData.signedChallenge) {

        return res.status(400).json({
            error: "Signatur fehlt"
        });
    }


    try {

        const challenge =
            req.session.challenge;


        if (!challenge) {

            return res.status(400).json({
                error: "Keine Challenge vorhanden"
            });
        }

        if (checkExpiry(challenge)) {

            delete req.session.challenge;

            return res.status(400).json({
                error: "Challenge abgelaufen"
            });
        }

        const response = await fetch(
            `http://localhost:8081/1.0/identifiers/${signupData.did}`
        );


        consoleLogMessage(
            "DID Resolution Response: ",
            response
        );


        if (!response.ok) {

            return res
                .status(response.status)
                .json({
                    error: "DID nicht gefunden"
                });
        }


        const data =
            await response.json();


        const didDocument =
            data.didDocument;


        consoleLogMessage(
            "DID Document: ",
            didDocument
        );


        if (!didDocument) {

            return res.status(500).json({
                error: "Ungültige DID-Antwort"
            });
        }

        const checkUserRegistered =
            await db.query(
                `SELECT *
                 FROM users
                 WHERE did=$1;`,
                [signupData.did]
            );


        if (checkUserRegistered.rows.length > 0) {

            return res.redirect(
                "/?message=User%20already%20registered.%20Please%20login."
            );
        }

        const verificationMethod =
            didDocument.verificationMethod?.[0];


        if (!verificationMethod?.publicKeyMultibase) {

            return res.status(400).json({
                error:
                    "Kein gültiger Public Key im DID Document"
            });
        }


        consoleLogMessage(
            "Nonce in Session: ",
            challenge.value
        );


        consoleLogMessage(
            "Signed Challenge: ",
            signupData.signedChallenge
        );


        consoleLogMessage(
            "Verification Method: ",
            verificationMethod
        );


        consoleLogMessage(
            "Public Key: ",
            verificationMethod.publicKeyMultibase
        );

        const isSignatureValid =
            verifySignature(
                challenge.value,
                signupData.signedChallenge,
                verificationMethod.publicKeyMultibase
            );


        if (!isSignatureValid) {

            delete req.session.challenge;

            return res.status(400).json({
                error: "Ungültige Signatur"
            });
        }

        delete req.session.challenge;

        const result =
            await db.query(
                `INSERT INTO users(username, did)
                 VALUES($1, $2)
                 RETURNING username, did;`,
                [
                    signupData.username,
                    signupData.did
                ]
            );


        const user =
            result.rows[0];


        req.session.user = {
            username: user.username,
            did: user.did
        };


        // Store DID document as well
        req.session.didDocument =
            didDocument;

        req.session.save((err) => {

            if (err) {

                console.error(
                    "Session save error:",
                    err
                );


                return res.status(500).json({
                    error:
                        "Session konnte nicht gespeichert werden"
                });
            }

            return res.redirect("/result");

        });


    } catch (error) {

        console.error(
            "Signup error:",
            error
        );


        return res.status(500).json({
            error: "Server error"
        });
    }
}


export function isAuthenticated(req, res, next) {

    if (req.session.user) {

        return next();

    }


    return res.status(401).json({
        message: "Unauthorized"
    });
}

export function destroySession(req, res) {

    req.session.destroy((err) => {

        if (err) {

            console.error(
                "Logout error:",
                err
            );


            return res.status(500).json({
                message: "Logout failed"
            });
        }


        return res.json({
            message: "Logout successful"
        });

    });
}