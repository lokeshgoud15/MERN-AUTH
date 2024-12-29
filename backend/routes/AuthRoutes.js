import express from "express"
import { isAuthenticated, login, logout, register, resetPassword, sendResetOtp, sendVerifyOtp, verifyEmail } from "../controllers/AuthController.js"
import userAuth from "../middleware/userAuth.js"

const authRouter = express.Router()


authRouter.post('/register',register)
authRouter.post('/login',login)
authRouter.post('/logout',logout)

//to get the user id from req.body created a middleware as userAuth
authRouter.post('/send-verify-otp',userAuth,sendVerifyOtp)
authRouter.post('/verify-account',userAuth,verifyEmail)
authRouter.get('/is-auth',userAuth,isAuthenticated)

//Resetpassword

authRouter.post('/send-reset-otp',sendResetOtp)
authRouter.post('/reset-password',resetPassword)





export default authRouter