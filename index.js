import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { toNodeHandler, fromNodeHeaders } from "better-auth/node";

import jwt from "jsonwebtoken";


const app = express();
const port = process.env.PORT || 5001;


const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_for_dev_only";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

// ============================================================================
// 1. CORS CONFIGURATION
// ============================================================================
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const ALLOWED_ORIGINS = CLIENT_URL.split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ============================================================================
// 2. MONGODB CONNECTION & COLLECTIONS
// ============================================================================
const client = new MongoClient(process.env.DB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    throw err;
  }
}

const connectedClient = await connectToMongoDB();
const db = connectedClient.db("a9-salonbook");

// Collections:
export const usersCollection = db.collection("users");
export const servicesCollection = db.collection("services");
export const appointmentsCollection = db.collection("appointments");
export const transactionsCollection = db.collection("transactions");

// Performance & uniqueness indexes
await Promise.all([
  servicesCollection.createIndex({ serviceName: 1, category: 1, price: 1, status: 1 }),
  appointmentsCollection.createIndex({ customerId: 1, createdAt: -1 }),
  appointmentsCollection.createIndex({ serviceId: 1, appointmentDate: 1, timeSlot: 1, status: 1 }),
  transactionsCollection.createIndex({ stripeSessionId: 1 }, { unique: true }),
]);

// ============================================================================
// 3. BETTER AUTH CONFIGURATION (USES "users" COLLECTION)
// ============================================================================
export const auth = betterAuth({
  database: mongodbAdapter(db),
  secret: process.env.BETTER_AUTH_SECRET,
  baseURL: process.env.BETTER_AUTH_URL || `http://localhost:${port}`,
  trustedOrigins: ALLOWED_ORIGINS,
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
  },
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
    },
  },
  user: {
    modelName: "users",
    additionalFields: {
      role: {
        type: "string",
        required: false,
        defaultValue: "customer",
        input: false, // Critical: Blocks public signup from assigning "admin" role
      },
      isBlocked: {
        type: "boolean",
        required: false,
        defaultValue: false,
        input: false,
      },
      phone: {
        type: "string",
        required: false,
        defaultValue: "",
      },
    },
  },
});

// ============================================================================
// 4. HELPER UTILITIES (IDs, Regex & User Sanitization)
// ============================================================================
export const isValidObjectId = (id) =>
  typeof id === "string" && ObjectId.isValid(id) && String(new ObjectId(id)) === id;

export const toObjectIdIfValid = (id) => (isValidObjectId(id) ? new ObjectId(id) : id);

export const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const buildUserIdFilter = (id) => {
  if (isValidObjectId(id)) {
    return { $or: [{ _id: new ObjectId(id) }, { id }] };
  }
  return { $or: [{ _id: id }, { id }] };
};

export const sanitizeUser = (user) => {
  if (!user) return null;
  return {
    _id: String(user._id || user.id),
    name: user.name || "",
    email: user.email || "",
    image: user.image || "",
    phone: user.phone || "",
    role: user.role || "customer",
    isBlocked: Boolean(user.isBlocked),
    createdAt: user.createdAt || null,
  };
};

// ============================================================================
// 5. JWT & ROLE VERIFICATION MIDDLEWARES
// ============================================================================
export const verifyJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;

    if (!token) {
      return res.status(401).json({ message: "Unauthorized: missing JWT token." });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ message: "Unauthorized: invalid or expired token." });
    }

    const user = await usersCollection.findOne(buildUserIdFilter(decoded.userId));
    if (!user) {
      return res.status(401).json({ message: "Unauthorized: user not found." });
    }

    // Server-side enforcement: immediately reject blocked users
    if (user.isBlocked) {
      return res.status(403).json({
        message: "Access denied: your account has been blocked by an administrator.",
      });
    }

    req.user = sanitizeUser(user);
    return next();
  } catch (err) {
    return next(err);
  }
};

export const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({
      message: "Forbidden: insufficient role permissions.",
    });
  }
  return next();
};

export const verifyAdmin = requireRole("admin");
export const verifyCustomer = requireRole("customer");



// ============================================================================
// 6. BETTER AUTH ROUTES 
// ============================================================================
// Express 5 requires named wildcard syntax: {/*any} instead of *
app.all("/api/auth{/*any}", toNodeHandler(auth));

// Parse JSON body for all standard REST routes that follow
app.use(express.json());

// ============================================================================
// 7. JWT TOKEN EXCHANGE ROUTE
// ============================================================================
app.post("/api/jwt", async (req, res, next) => {
  try {
    const sessionData = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });

    if (!sessionData?.user) {
      return res.status(401).json({ message: "Unauthorized: no active Better Auth session." });
    }

    const dbUser = await usersCollection.findOne(buildUserIdFilter(sessionData.user.id));
    if (!dbUser) {
      return res.status(401).json({ message: "Unauthorized: user account not found." });
    }

    if (dbUser.isBlocked) {
      return res.status(403).json({ message: "Access denied: your account is blocked." });
    }

    const safeUser = sanitizeUser(dbUser);
    const token = jwt.sign(
      { userId: safeUser._id, email: safeUser.email, role: safeUser.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return res.json({ token, user: safeUser });
  } catch (err) {
    return next(err);
  }
});



// ============================================================================
// 6. HEALTH CHECK
// ============================================================================
app.get("/", (_req, res) => {
  res.json({ service: "SalonBook API", status: "running" });
});

// ============================================================================
// 7. START SERVER
// ============================================================================
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

export default app;