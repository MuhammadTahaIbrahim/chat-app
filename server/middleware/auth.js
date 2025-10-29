
import jwt from "jsonwebtoken"
import User from "../models/User.js"

// middlware function to decode jwt token to get clerkId

export const protectRoute = async (req, res, next) => {
    const token = req.headers.token

    if (!token) {
        return res.json({ success: false, message: 'Not Authorized Login Again' })
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        const user = await User.findById(decoded.userId).select("-password")
        if (!user) {
            return res.json({ success: false, message: 'User not found' })
        }

        req.user = user
        next()
    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}