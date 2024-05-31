const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

//@desc Register user 
//@route POST /api/users/register
//@access Public
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    res.status(400);
    throw new Error("Please fill all fields");
  }
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  console.log("Hashed password: ", hashedPassword);
  const user = await User.create({
    username,
    email,
    password: hashedPassword
  });
  console.log("User created ", user);
  if (user) {
    res.status(201).json({
      _id: user._id,
      username: user.username,
      email: user.email,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
  res.json({ message: "Register the user"});
});

//@desc Login user 
//@route POST /api/users/login
//@access Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400);
    throw new Error("Please fill all fields");
  }
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("Email not registered");
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    res.status(401);
    throw new Error("Invalid password");
  } else {
    const accessToken = jwt.sign(
      {
        user: {
          username: user.username,
          email: user.email,
          id: user._id
        }
      }, 
      process.env.JWT_SECRET, 
      {expiresIn: "10m"}
    );
    res.status(200).json({accessToken});
  }
  res.json({ message: "Login user"});
});

//@desc Get current user information
//@route GET /api/users/current
//@access Private
const currentUserInfo = asyncHandler(async (req, res) => {
  res.json(req.user);
});

module.exports = { registerUser, loginUser, currentUserInfo };