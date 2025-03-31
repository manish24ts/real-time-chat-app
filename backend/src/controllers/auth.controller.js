import { generateToken } from "../lib/utils.js"
import User from "../models/user.model.js"
import bcrypt from "bcryptjs"
import cloudinary from "../lib/cloudinary.js"

export const signup = async (req, res) => { 
    const { fullName , email , password} = req.body
    try {
        if(!fullName || !email || !password) {
            return res.status(400).json({message:"All fields are not filled"})
        }
        //I am Hashing password for safety
        if (password.length < 6){
            return res.status(400).json({message: "Password must be at least 6 characters long"})
        }
        const user = await User.findOne({email})

        if (user) return res.status(400).json({message: "Email is already used"})

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)

        const newUser = new User(
            {
                fullName: fullName,   // you can shorten it by using just fullName, email, password:hashedPassword
                email:email,
                password:hashedPassword
            }
        )
        if(newUser) {
            // Generate JWT token hear
            generateToken(newUser._id , res)
            await newUser.save();
            res.status(201).json({
                _id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                profilePic: newUser.profilePic,
            })

        }
        else{
            return res.status(400).json({message: "Invalid data"})
        }

    }
    catch (error) { 
        console.log("Error in signup : " + error.message);
        res.status(500).json({message: "Internal error"});
    }

}

export const login = async (req, res) => { 
    const {email, password } = req.body
    try {
        const user = await User.findOne({email}) 
        if(!user){
            return res.status(400).json({message:"Invalid details"})
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if (!isPasswordCorrect){
            return res.status(400).json({message:"Invalid details"})
        }
        generateToken(user._id,res)
        res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            email: user.email,
            profilePic: user.profilePic,
        })


    }
    catch (error) {
        console.log("Error in login : " + error.message);
        res.status(500).json({message: "Internal error"});
    }

}

export const logout = (req, res) => { 
    try {
        res.cookie("jwt","", {maxAge:0})
        res.status(200).json({message: "Logged out successfully"});
    }
    catch (error){
        console.log("Error in logout : " + error.message);
        res.status(500).json({message: "Internal error"});
    }

}

export const updateProfile = async (req,res) => {
    try {
        const {profilePic} = req.body;
    const userId = req.user._id;
    if(!profilePic){
        return res.status(400).json({message: "Profile pic is needed"})
    }
    const uploadResponse = await cloudinary.uploader.upload(profilePic)
    const updatedUser = await User.findByIdAndUpdate(userId, {profilePic:uploadResponse.secure_url},{new:true})

    return res.status(200).json(updatedUser)
    }
    catch (error){
        console.log("Error in updating profile : " + error.message)
        return res.status(500).json({message: "Internal server error"})
    }
}


export const checkAuth = (req,res) => {
    try {
        res.status(200).json(req.user);
    }
    catch (error){
        console.log("Error in check authentication : " + error.message)
        return res.status(500).json({message: "Internal server error"})
    }
}