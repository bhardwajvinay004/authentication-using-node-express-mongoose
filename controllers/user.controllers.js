import User from "../models/user.models.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import axios from "axios";
import sendVerifyEmail from "../utils/send-mail.utils.js";
import googleOidcConfig from "../utils/google-oidc-configuration.utils.js";

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

const resendVerificationEmail = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate Request Body data
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide an email address and password",
      });
    }

    // Fetch an existing User using Email address
    const user = await User.findOne({ email });

    // Check if the user exists and is verified or not
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if the user is already verified
    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "User already verified",
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

    // Check if token already exists
    if (user.verificationToken && user.verificationTokenExpiry > Date.now()) {
      return res.status(400).json({
        success: false,
        message: "Email already sent. Please check your inbox",
      });
    }

    // Generate a verification token and expiry time
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

    user.verificationToken = verificationToken;
    user.verificationTokenExpiry = verificationTokenExpiry;
    await user.save();

    // Send a verification email
    await sendVerifyEmail(user.email, verificationToken);
    return res.status(201).json({
      success: true,
      message: "Verfification email resent successfully",
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
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Check if the user exists and is verified or not
    if (!user.isVerified) {
      // Check if verification token expired or not
      if (user.verificationTokenExpiry < Date.now()) {
        return res.status(400).json({
          success: false,
          message: "Verification token expired",
        });
      }

      return res.status(400).json({
        success: false,
        message: "Please verify your email before logging in",
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

const registerOrloginUsingGoogle = async (req, res) => {
  try {
    // Fetch Google OIDC configuration
    const googleOidcConfigData =
      await googleOidcConfig.getGoogleOidcConfiguration();
    const { authorization_endpoint, scopes_supported } = googleOidcConfigData;

    // Generate Code Verifier and Code Challenge
    const codeVerifier = googleOidcConfig.generateCodeVerifier();
    const codeChallenge = googleOidcConfig.generateCodeChallenge(codeVerifier);
    console.log("Code Verifier generated: ", codeVerifier);
    console.log("Code Challenge generated: ", codeChallenge);

    // Set Code Verifier in cookies
    res.cookie("code_verifier", codeVerifier, {
      httpOnly: true,
      sameSite: "strict",
    });

    // Redirect to Google's Authorization endpoint
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_OAUTH_CLIENT_ID,
      redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
      response_type: "code",
      scope: scopes_supported.join(" "),
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    const googleOAuthUrl = `${authorization_endpoint}?${params.toString()}`;
    console.log("Google Oauth Url: ", googleOAuthUrl);
    res.redirect(googleOAuthUrl);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

async function getGoogleJwks(googleOidcConfigData) {
  try {
    const jwksResponse = await axios.get(googleOidcConfigData.jwks_uri);
    return jwksResponse.data.keys;
  } catch (error) {
    console.error("Error fetching JWKS: ", error);
    throw new Error("Unable to fetch JWKS");
  }
}

async function validateGoogleIdToken(idToken, googleOidcConfigData) {
  try {
    // Fetch Google's JWKS
    const jwks = await getGoogleJwks(googleOidcConfigData);

    // Decode the ID Token to get the kid (Key ID)
    const decodedToken = jwt.decode(idToken, { complete: true });
    console.log("Decoded ID Token: ", decodedToken);

    // Validate decoded token
    if (!decodedToken || !decodedToken.header || !decodedToken.header.kid) {
      console.error("Invalid ID Token: ", idToken);
      return false;
    }
    const { kid } = decodedToken.header;

    // Find the matching key in the JWKS keys
    const matchingKey = jwks.find((key) => key.kid === kid);
    if (!matchingKey) {
      console.error("Public key not fornd for kid: ", kid);
      return false;
    }

    // Convert the JWK to PEM format
    const pem = jwkToPem(matchingKey);

    // Verify the ID Token using the PEM key
    jwt.verify(
      idToken,
      pem,
      {
        algorithms: ["RS256"],
        audience: process.env.GOOGLE_OAUTH_CLIENT_ID,
        issuer: googleOidcConfigData.issuer,
      },
      (err, decoded) => {
        if (err) {
          console.error("Error verifying ID Token: ", err);
          return false;
        }

        console.log("Decoded User Info from Google: ", decoded);
        return decoded;
      }
    );
  } catch (error) {
    console.error("Error validating ID Token: ", error);
    return false;
  }
}

const googleCallbackToFetchTokens = async (req, res) => {
  try {
    // Fetch Google OIDC configuration
    const googleOidcConfigData =
      await googleOidcConfig.getGoogleOidcConfiguration();
    const { token_endpoint } = googleOidcConfigData;

    // Extract code from query parameters
    const { code } = req.query;
    console.log("Authorization code received: ", code);

    // Extract Code Verifier from cookies
    const codeVerifier = req.cookies.code_verifier;
    console.log("Code Verifier from cookies: ", req.cookies.code_verifier);

    // Exchange authorization code with Google for tokens using Google's Token Endpoint
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_OAUTH_CLIENT_ID,
      client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
    });
    const tokenResponse = await axios
      .post(token_endpoint, params, {
        headers: {
          "Content-Type": [
            "application/x-www-form-urlencoded",
            "application/json",
          ],
        },
      })
      .catch((error) => {
        console.error("Error fetching tokens: ", error);
        throw new Error("Unable to fetch tokens");
      });
    console.log("Token response from Google: ", tokenResponse.data);
    const { access_token, refresh_token, id_token } = tokenResponse.data;

    // Validate ID Token
    const decodedToken = await validateGoogleIdToken(
      id_token,
      googleOidcConfigData
    );

    // Check if ID Token is valid
    if (!decodedToken) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID Token",
      });
    }

    // Check if the user already exists in the database
    let user = await User.findOne({ email: decodedToken.email });
    if (!user) {
      // Create a new user if not found
      user = await User.create({
        _id: decodedToken.sub,
        username: decodedToken.email.split("@")[0],
        email: decodedToken.email,
        password: crypto.randomBytes(16).toString("hex"),
        isVerified: true,
        refreshToken: refresh_token,
      });
      user.refreshToken = refresh_token;
      await user.save();

      // Set cookie with JWT token
      const cookieOptions = {
        httpOnly: true,
        sameSite: "strict",
      };
      res.cookie("accessToken", access_token, cookieOptions);
      res.cookie("reftreshToken", refresh_token, cookieOptions);
      res.redirect("/user-profile");
    } else {
      user.refreshToken = refresh_token;
      await user.save();

      // Set cookie with JWT token
      const cookieOptions = {
        httpOnly: true,
        sameSite: "strict",
      };
      res.cookie("accessToken", access_token, cookieOptions);
      res.cookie("reftreshToken", access_token, cookieOptions);
      await user.save();
      res.redirect("/user-profile");
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Authentication failed",
      error: error.message,
    });
  }
};

export {
  register,
  verifyEmail,
  resendVerificationEmail,
  login,
  logout,
  userProfile,
  registerOrloginUsingGoogle,
  googleCallbackToFetchTokens,
};
