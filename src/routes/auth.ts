import { Router, Request, Response } from "express";
import { getCloudRunToken, getFCMAuthToken } from "../utils/google-auth";
import { verifyFirebaseToken } from "../middleware/firebase";

const router = Router();

/**
 * Public endpoint to get Cloud Run token
 * Requires Firebase ID token in the Authorization header
 */
router.post("/public-token", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ error: "Missing or invalid authorization header" });
    }

    // Extract Firebase ID token
    const idToken = authHeader.split("Bearer ")[1];

    // Verify Firebase token
    try {
      await verifyFirebaseToken(idToken);
    } catch (error) {
      console.error("Firebase token verification failed:", error);
      return res.status(403).json({ error: "Invalid Firebase token" });
    }

    // Generate Cloud Run token
    const token = await getCloudRunToken();

    res.json({
      token,
      expiresIn: 3600, // 1 hour
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Error generating token:", error);
    res.status(500).json({
      error: "Failed to generate token",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * Generate FCM authorization token for notifications
 */
router.get("/fcm-token", async (req: Request, res: Response) => {
  try {
    const token = await getFCMAuthToken();
    res.json({
      token,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Error generating FCM token:", error);
    res.status(500).json({
      error: "Failed to generate FCM token",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * Health check endpoint
 */
router.get("/health", (req: Request, res: Response) => {
  res.json({
    status: "healthy",
    service: "gcloud-authentication",
    timestamp: new Date().toISOString(),
  });
});

export default router;
