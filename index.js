const express = require("express");
const dotenv = require('dotenv');
const { connectDB } = require("./config/db")
const userRouter = require('./routes/userRoutes');
const cookieParser = require('cookie-parser');

const app = express();
dotenv.config({path: "./config/config.env"});
app.use(express.json());
app.use(cookieParser());

connectDB();

app.use(userRouter);

app.listen(process.env.PORT, ()=>{
    console.log(`server is running at port ${process.env.PORT}`);
})