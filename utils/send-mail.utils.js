import nodemailer from "nodemailer";

const sendVerifyEmail = async (email, token) => {
  // Create a transporter object
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // Create a verification email URI
  const verificationUrl = `${process.env.BASE_URL}/api/v1/user/verify/${token}`;

  // Set up email options
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: email,
    subject: "Account Verification",
    text: `Please verify your account by clicking the link: ${verificationUrl}. The verification link will expire in 10 minutes. Please do not share this link with anyone. If you did not request this email, please ignore it.`,
  };

  // Send the email
  try {
    await transporter.sendMail(mailOptions);
    console.log("Verification email sent successfully");
    return true;
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw new Error("Error sending verification email");
  }
};

export default sendVerifyEmail;
