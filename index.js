import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import { MongoClient } from 'mongodb';


const app = express()

app.use(cors())
app.use(express.json())
const port = process.env.PORT || 5001;

const client = new MongoClient(process.env.DB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}

const connectedClient = await connectToMongoDB()
const db = connectedClient.db("a9-salonbook")

// Collections:
const usersCollection = db.collection("users");
const servicesCollection = db.collection("services");
const appointmentsCollection = db.collection("appointments");
const transactionsCollection = db.collection("transactions");


// Basic Health Check Route
app.get("/", (_req, res) => {
  res.json({ service: "SalonBook API", status: "running" });
});

// START SERVER
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
export default app;