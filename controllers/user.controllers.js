import User from "../models/user.models.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import sendVerifyEmail from "../utils/send-mail.utils.js";

// Register Controller
const register = async (req, res) => {
  const { username, email, password } = req.body;

  // Validate Request Body data
  if (!username || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields are required",
    });
  }

  // Validate Password length
  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 6 characters",
    });
  }

  try {
    // Fetch an existing User using Email address
    const existingUser = await User.findOne({ email });

    // Check if the user already exists
    // If user exists, return an error response
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    // Generate a verification token and expiry time
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Create a new user
    const newUser = await User.create({
      username,
      email,
      password,
      verificationToken,
      verificationTokenExpiry,
    });

    // Check if user creation was successful
    // If user creation fails, return an error response
    if (!newUser) {
      return res.status(500).json({
        success: false,
        message: "Error creating user",
      });
    }

    // Send a verification email
    await sendVerifyEmail(newUser.email, verificationToken);
    return res.status(201).json({
      success: true,
      message: "User created successfully. Please verify your email.",
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        isVerified: newUser.isVerified,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// Verify Email Controller
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Verification token is required",
      });
    }

    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification token",
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiry = undefined;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// Login Controller
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate Request Body data
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // Fetch an existing User using Email address
    const user = await User.findOne({ email });

    // Check if the user exists and is verified or not
    if (!user || !user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Check if the password is correct
    const isPasswordMatching = await user.comparePassword(password);
    if (!isPasswordMatching) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Generate a JWT token
    const accessToken = jwt.sign(
      { id: user._id },
      process.env.JWT_ACCESS_TOKEN_SECRET,
      { expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRY }
    );

    // Generate a JWT token
    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_ACCESS_TOKEN_SECRET,
      { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRY }
    );

    user.refreshToken = refreshToken;
    await user.save();

    // Set cookie with JWT token
    const cookieOptions = {
      httpOnly: true,
      sameSite: "strict",
    };
    res.cookie("accessToken", accessToken, cookieOptions);
    res.cookie("reftreshToken", refreshToken, cookieOptions);

    return res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// User Profile Controller
const userProfile = async (req, res) => {
  const userId = req.user.id;
  const userData = await User.findById(userId).select(
    "-password -verificationToken -verificationTokenExpiry"
  );

  if (!userData) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  return res.status(200).json({
    success: true,
    message: "User profile fetched successfully",
    user: {
      id: userData._id,
      username: userData.username,
      email: userData.email,
      role: userData.role,
      isVerified: userData.isVerified,
    },
  });
};

const logout = async (req, res) => {
  try {
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

export { register, verifyEmail, login, logout, userProfile };
