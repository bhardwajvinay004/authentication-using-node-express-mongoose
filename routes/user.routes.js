import express from "express";
import {
  login,
  register,
  userProfile,
  verifyEmail,
  logout,
  resendVerificationEmail,
  registerOrloginUsingGoogle,
  googleCallbackToFetchTokens,
} from "../controllers/user.controllers.js";
import isLoggedIn from "../middlewares/is-logged-in.middlewares.js";

const router = express.Router();

router.get("/register", register);
router.get("/verify/:token", verifyEmail);
router.post("/resend-verification-email", resendVerificationEmail);
router.post("/login", login);
router.get("/user-profile", isLoggedIn, userProfile);
router.get("/logout", isLoggedIn, logout);
router.get("/google/register", registerOrloginUsingGoogle);
router.get("/google/login", isLoggedIn, registerOrloginUsingGoogle);
router.get("/google/callback", googleCallbackToFetchTokens);

export default router;
