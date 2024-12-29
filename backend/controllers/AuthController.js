import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/user.models.js";
import transporter from "../config/nodemailer.js";

export const register = async (req, res) => {
  const { name, email, password } = req.body;

  //if email or password or name are not provided
  if (!email || !password || !name) {
    return res.status(400).json({ success: false, message: "Missing Details" });
  }

  //   if provided

  try {
    //if the user exists in database -->check

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }

    //if increases the number it will provide high security but it will take more time to encrypt the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new userModel({ email, name, password: hashedPassword });

    await user.save();

    const token = jwt.sign(
      {
        id: user._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //sending welcome eamil

    const mailoptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to our website",
      text: `Welcome to our website. Your account has been created with email id : ${email}`,
    };

    await transporter.sendMail(mailoptions);

    return res.json({ success: true, message: "Registered Suucessfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({
      success: false,
      message: "Email and Password are required",
    });
  }
  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "Invalid Credentials" });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.json({ success: false, message: "Invalid Credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({ success: true, message: "Logged-In Suucessfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, //7DAYS
    });

    return res.json({ success: true, message: "Logged Out Successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// Send verification otp to the user's email

export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await userModel.findById(userId);
    if (user.isAccountVerified) {
      return res.json({
        sucess: false,
        message: "Account is already verified",
      });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 1 * 24 * 60 * 60 * 1000;

    await user.save();

    const mailoptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp} Please enter this OTP to verify your account`,
    };

    await transporter.sendMail(mailoptions);

    res.json({ success: true, message: "verification otp sent to your email" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//verify the email using otp
export const verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing Details" });
  }
  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP has expired" });
    }

    user.isAccountVerified = true;

    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;
    await user.save();

    return res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//check if user is authenticated
export const isAuthenticated = async (req, res) => {
  try {
    return res.json({ success: true });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//send  otp  for resetting password

export const sendResetOtp = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.json({ success: false, message: "Email is Required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // 5 minutes
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "OTP for Resetting Password",
      text: `Your OTP for resetting password is ${otp} Use this OTP to reset your password `,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "OTP sent to your email" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//Reset User Password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.json({
      success: false,
      message: "Email , OTP and New Password are required",
    });
  }
  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    if (user.resetOtp !== otp || user.resetOtp === "") {
      return res.json({ success: false, message: "Invalid OTP" });
    }
    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP has expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;
    await user.save();

    return res.json({ success: true, message: "Password reset successfully" });


  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};
