import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const dbConnect = () => {
  mongoose
    .connect(process.env.MONGO_DB_URI)
    .then(() => {
      console.log("Mongo DB connected successfully!");
    })
    .catch((err) => console.log("Error connecting Mongo DB: ", err));
};

export default dbConnect;
