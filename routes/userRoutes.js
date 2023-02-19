const express = require('express');
const { register, login, profile, updatePassword, forgotPassword, resetPassword } = require("../controller/userController");
const { isAuthenticated } = require('../middlewares/authentication');

const router = express.Router();


router.post("/register", register);
router.post("/login", login);
router.get("/profile", isAuthenticated, profile);
router.put("/update", isAuthenticated, updatePassword);
router.post("/forgot-password", forgotPassword);
router.put("/reset-password/:_id/:token", resetPassword);



module.exports = router;