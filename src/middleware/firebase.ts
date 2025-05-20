import { Request, Response, NextFunction } from "express";
import * as admin from "firebase-admin";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Check if Firebase environment variables are set
const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const privateKeyRaw = process.env.FIREBASE_PRIVATE_KEY;

if (!projectId || !clientEmail || !privateKeyRaw) {
  console.error("Missing Firebase credentials in environment variables:");
  console.error(`  FIREBASE_PROJECT_ID: ${projectId ? "Set" : "Missing"}`);
  console.error(`  FIREBASE_CLIENT_EMAIL: ${clientEmail ? "Set" : "Missing"}`);
  console.error(`  FIREBASE_PRIVATE_KEY: ${privateKeyRaw ? "Set" : "Missing"}`);
  throw new Error(
    "Firebase configuration is incomplete. Check your environment variables."
  );
}

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  const privateKey = privateKeyRaw.replace(/\\n/g, "\n");

  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey,
      }),
    });
    console.log("Firebase Admin SDK initialized successfully");
  } catch (error) {
    console.error("Error initializing Firebase Admin SDK:", error);
    throw error;
  }
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: admin.auth.DecodedIdToken;
    }
  }
}

/**
 * Verify Firebase ID token
 * @param token Firebase ID token
 * @returns Decoded token
 */
export async function verifyFirebaseToken(
  token: string
): Promise<admin.auth.DecodedIdToken> {
  try {
    return await admin.auth().verifyIdToken(token);
  } catch (error) {
    console.error("Error verifying Firebase token:", error);
    throw error;
  }
}

/**
 * Express middleware to verify Firebase authentication
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Missing or invalid authorization header" });
  }

  const idToken = authHeader.split("Bearer ")[1];

  admin
    .auth()
    .verifyIdToken(idToken)
    .then((decodedToken) => {
      req.user = decodedToken;
      next();
    })
    .catch((error) => {
      console.error("Auth middleware error:", error);
      res.status(403).json({ error: "Invalid or expired token" });
    });
}
