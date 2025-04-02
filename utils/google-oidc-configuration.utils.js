import dotenv from "dotenv";
import crypto from "crypto";
import axios from "axios";

dotenv.config();

const getGoogleOidcConfiguration = async () => {
  try {
    const response = await axios.get(
      "https://accounts.google.com/.well-known/openid-configuration"
    );
    return response.data;
  } catch (error) {
    console.error("Error fetching Google OIDC configuration:", error);
    throw new Error("Failed to fetch Google OIDC configuration");
  }
};

const generateCodeVerifier = () => {
  return crypto.randomBytes(32).toString("hex");
};

const generateCodeChallenge = (codeVerifier) => {
  return crypto.createHash("sha256").update(codeVerifier).digest("hex");
};

export default {
  getGoogleOidcConfiguration,
  generateCodeVerifier,
  generateCodeChallenge,
};
