const mongoose = require('mongoose');

exports.connectDB = async ()=>{
    try {

        const {connection} = await mongoose.connect(process.env.DB);
    
        console.log(`database connected with host ${connection.host}`);
    } catch (error) {
        console.log(error);        
    }
}