const jwt = require('jsonwebtoken');
const User = require('../models/userSchema');

exports.isAuthenticated = async(req, res, next)=>{
    try {

        const {token} = req.cookies;
        if(!token){
            return res.status(401).json({
                message: "Please login ..."
            })
        }

        const decoded = await jwt.verify(token, process.env.SECRET_KEY);
        req.user = await User.findById(decoded._id);

        next();
        
    } catch (error) {
        res.json({
            error: error.message
        })      
    }
}