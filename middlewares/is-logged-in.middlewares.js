import jwt from "jsonwebtoken";
import User from "../models/user.models.js";

const isLoggedIn = async (req, res, next) => {
  try {
    const accessToken = req.cookies?.accessToken;
    const refreshToken = req.cookies?.refreshToken;

    if (!accessToken) {
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized Access",
        });
      }

      // If refresh token is present, verify it and issue a new access token
      const decodedRefreshToken = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );

      // Fetch user details using the decoded refresh token
      const user = await User.findById({ _id: decodedRefreshToken.id });
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized Access",
        });
      }

      // Generate new JWT token
      const newAccessToken = jwt.sign(
        { id: user._id },
        process.env.JWT_ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRY }
      );
      const newRefreshToken = jwt.sign(
        { id: user._id },
        process.env.JWT_REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRY }
      );

      user.refreshToken = newRefreshToken;
      await user.save();

      // Set cookie with JWT token
      const cookieOptions = {
        httpOnly: true,
        sameSite: "strict",
      };
      res.cookie("accessToken", newAccessToken, cookieOptions);
      res.cookie("reftreshToken", newRefreshToken, cookieOptions);
    } else {
      const decodedAccessToken = jwt.verify(
        accessToken,
        process.env.JWT_ACCESS_TOKEN_SECRET
      );

      // Fetch user details using the decoded access token
      const user = await User.findById({ _id: decodedAccessToken.id });
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized Access",
        });
      }

      // Generate new JWT token
      const newAccessToken = jwt.sign(
        { id: user._id },
        process.env.JWT_ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRY }
      );
      const newRefreshToken = jwt.sign(
        { id: user._id },
        process.env.JWT_REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRY }
      );

      user.refreshToken = newRefreshToken;
      await user.save();

      // Set cookie with JWT token
      const cookieOptions = {
        httpOnly: true,
        sameSite: "strict",
      };
      res.cookie("accessToken", newAccessToken, cookieOptions);
      res.cookie("reftreshToken", newRefreshToken, cookieOptions);

      req.user = decodedAccessToken;
    }

    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

export default isLoggedIn;
