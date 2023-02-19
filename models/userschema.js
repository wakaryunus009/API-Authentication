const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    name:{
        type: String,
        required: [true, "name is required"]
    },
    email: {
        type: String,
        required: [true, "email is required"],
        unique: true,
    },
    password:{
        type: String,
        required: true
    },
    count: {
        type: Number,
        default: 0
    },
    blockedTime: {
        type: Date
    }
})
//hash user password while save
userSchema.pre("save", async function(next){
    if(this.isModified("password")){
        this.password = await bcrypt.hash(this.password, 8);
    }

    next();
})
//compare hashed password and user enetered password
userSchema.methods.ComparePassword = async function(pass){
    return await bcrypt.compare(pass, this.password);
}
//genarate token while login
userSchema.methods.genarateToken = async function(){
    const payload = {
        _id: this._id
    }
    return await jwt.sign(payload, process.env.SECRET_KEY);
}
const User = mongoose.model("User", userSchema);
module.exports = User;