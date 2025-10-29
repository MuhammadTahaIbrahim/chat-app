import mongoose from "mongoose";

export const connectDB = async () => {
    mongoose.connection.on('connected', () => {
        console.log("database connected")
    })
    await mongoose.connect(`${process.env.MONGODB_URI}/chat-app`)
}

// export default connectDB