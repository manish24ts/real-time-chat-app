import jwt from "jsonwebtoken"

export const generateToken = (userId, res) => {
    const token = jwt.sign({userId}, process.env.JWT_SECRET,{
        expiresIn:"7d",
    });
    res.cookie("jwt",token,{
        maxAge: 7 * 24 * 60 * 60 * 1000, // maxAge is in milli seconds
        httpOnly: true, // For safety it prevents XSS attacks cross-site script attacks 
        sameSite: "strict", // For safety it prevents CSRF attacks cross-site forgery attacks 
        secure: process.env.NODE_ENV !== "development",
    });
    return token;
};