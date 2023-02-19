const User = require("../models/userSchema");
const jwt = require('jsonwebtoken');
//register user
exports.register = async(req, res)=>{
    try {

        const {name, email, password} = req.body;

        const prevUser = await User.findOne({email})

        if(prevUser){
            return res.json({
                message: "Email already exists"
            })
        }

        const user = await User.create({name, email, password});

        res.status(201).json({
            message: "REgistered",
            user
        })
    } catch (error) {
        res.status(500).json({
            error
        })       
    }
}

//login user
exports.login = async (req, res)=>{
    try {

        const {email, password} = req.body;

        const user = await User.findOne({email});
        if(!user){
            return res.json({
                message: "User not found"
            })
        }

        if(user.count == 3){
            const diff = new Date() - user.blockedTime;
            if(diff < 1000*60*1){
                return res.json({
                    message: "Please try after some time"
                })
            }
            else{
                user.count = 0;
            }
        }

        const isMatch = await user.ComparePassword(password);

        if(!isMatch){
            user.count++;
            user.blockedTime = new Date();
            await user.save();

            return res.json({
                message: "Invalid login credentials"
            })
        }

        user.count = 0;
        const token = await user.genarateToken();
        let options = {
            expires: new Date(Date.now() + 1000*60*60*24*10),
            httpOnly: true
        }

        await user.save();
        res.status(200).cookie("token", token, options).json({
            message: "Login successfull"
        })
        
    } catch (error) {
        res.status(500).json({
            error
        })        
    }
}
//get profile
exports.profile = async(req, res)=>{
    try {

        // const user = await User.findById(req.user._id);

        res.status(200).json({
            user: req.user
        })

    } catch (error) {
        res.json({
            error
        })        
    }
}
//update profile 
exports.updatePassword = async(req, res)=>{
    try {

        const {oldPassword, newPassword} = req.body;

        //fetch user by id
        const user = await User.findById(req.user._id);
        const check = await user.ComparePassword(oldPassword);

        if(!check){
            return res.json({
                message: "Old Password doesn't matched"
            })
        }

        if(newPassword){
            user.password = newPassword;
        }

        await user.save();

        res.status(200).json({
            message: "Password updated !"
        })
        
    } catch (error) {
        res.status(500).json({
            error: error.message
        })        
    }
}

//forgot password
exports.forgotPassword = async(req, res)=>{
    try {
        const {email} = req.body;

        const user = await User.findOne({email});
        
        if(!user){
            return res.status(404).json({
                message: `User not found with ${email}`
            })
        }

        const payload = {
            email: user.email,
            _id: user._id
        }
        const secret = process.env.SECRET_KEY + user.password;
        const token = await jwt.sign(payload, secret, {expiresIn: "5min"});
        const link = `http://localhost:${process.env.PORT}/reset-password/${user._id}/${token}`;

        res.status(200).json({
            message: "Reset Your password using below link",
            link
        })

        
    } catch (error) {
        res.status(500).json({
            error: error.message
        })
    }
}


exports.resetPassword = async(req, res)=>{
    try {

        const {_id, token} = req.params;
        const user = await User.findById(_id);
        const secret = process.env.SECRET_KEY + user.password;
        const decoded = await jwt.verify(token, secret);

        const {password} = req.body;

        if(password){
            user.password = password;
        }
        await user.save();

        res.status(200).json({
            message: "Password Reset Done.",
            email: decoded.email,
            _id: decoded._id
        })

    } catch (error) {
        res.status(500).json({
            error: error.message
        })        
    }
}