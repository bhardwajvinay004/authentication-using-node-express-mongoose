import express from "express";
import {
  login,
  register,
  userProfile,
  verifyEmail,
  logout,
} from "../controllers/user.controllers.js";
import isLoggedIn from "../middlewares/is-logged-in.middlewares.js";

const router = express.Router();

router.get("/register", register);
router.get("/verify/:token", verifyEmail);
router.post("/login", login);
router.get("/user-profile", isLoggedIn, userProfile);
router.get("/logout", isLoggedIn, logout);

export default router;
