import express from "express"
import cors from 'cors';
import "dotenv/config"
import cookieParser from 'cookie-parser';

import connectDB  from"./config/mongodb.js"
import authRouter from "./routes/AuthRoutes.js";
import userRouter from "./routes/userRoutes.js";


const app = express()
const port = process.env.PORT || 3000
connectDB();
const allowedOrigins = ["http://localhost:5173"]

app.use(express.json())
app.use(cookieParser())
app.use(cors({origin: allowedOrigins,credentials:true}))


// api end points

app.get('/',(req,res)=>{
    res.send('Hello World ')
})

app.use('/api/auth',authRouter);
app.use('/api/user',userRouter);



app.listen(port,()=>{
    console.log(`server is listening to port ${port}`);
    
})