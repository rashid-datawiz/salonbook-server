import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import { MongoClient } from 'mongodb';


const app = express()

app.use(cors())
app.use(express.json())


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



const port  = process.env.PORT || 5001
app.listen(port, ()=>{
    console.log("server is running on port 5001")
})