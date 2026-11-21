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
// 8. SALON SERVICES ROUTES (PUBLIC BROWSE + DETAILS)
// ============================================================================

// Public: Browse active services with search, category filtering, price sorting, and optional limit
app.get("/api/services", async (req, res, next) => {
  try {
    const { search, category, sort, limit } = req.query;
    const query = { status: "active" }; // Only active services visible to public

    // Case-insensitive service name search
    if (search && typeof search === "string" && search.trim()) {
      query.serviceName = { $regex: escapeRegex(search.trim()), $options: "i" };
    }

    // Category filter (handles "all" or specific category)
    if (category && typeof category === "string" && category.trim() && category !== "all") {
      query.category = { $regex: `^${escapeRegex(category.trim())}$`, $options: "i" };
    }

    // Price sorting & default newest first
    let sortStage = { createdAt: -1 };
    if (sort === "price_asc") sortStage = { price: 1 };
    if (sort === "price_desc") sortStage = { price: -1 };

    let cursor = servicesCollection.find(query).sort(sortStage);

    // Optional limit (useful for the homepage "Featured 6 Services" requirement)
    const parsedLimit = Number.parseInt(limit, 10);
    if (Number.isInteger(parsedLimit) && parsedLimit > 0) {
      cursor = cursor.limit(parsedLimit);
    }

    const services = await cursor.toArray();
    return res.json({ services });
  } catch (err) {
    return next(err);
  }
});

// Public: Get all distinct active service categories for filter dropdowns
app.get("/api/services/categories", async (_req, res, next) => {
  try {
    const categories = await servicesCollection.distinct("category", { status: "active" });
    return res.json({ categories });
  } catch (err) {
    return next(err);
  }
});

// Protected: Service Details (/services/[id])
app.get("/api/services/:id", verifyJWT, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: "Invalid service ID format." });
    }

    const service = await servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!service) {
      return res.status(404).json({ message: "Service not found." });
    }

    return res.json({ service });
  } catch (err) {
    return next(err);
  }
});

// ============================================================================
// 9. ADMIN SERVICES MANAGEMENT (CRUD)
// ============================================================================

// Admin Only: List all services (both active and inactive)
app.get("/api/admin/services", verifyJWT, verifyAdmin, async (req, res, next) => {
  try {
    const { search, category, status, sort } = req.query;
    const query = {};

    if (search && typeof search === "string" && search.trim()) {
      query.serviceName = { $regex: escapeRegex(search.trim()), $options: "i" };
    }
    if (category && typeof category === "string" && category.trim() && category !== "all") {
      query.category = { $regex: `^${escapeRegex(category.trim())}$`, $options: "i" };
    }
    if (status === "active" || status === "inactive") {
      query.status = status;
    }

    let sortStage = { createdAt: -1 };
    if (sort === "price_asc") sortStage = { price: 1 };
    if (sort === "price_desc") sortStage = { price: -1 };

    const services = await servicesCollection.find(query).sort(sortStage).toArray();
    return res.json({ services });
  } catch (err) {
    return next(err);
  }
});

// Admin Only: Add a new salon service
app.post("/api/services", verifyJWT, verifyAdmin, async (req, res, next) => {
  try {
    const { serviceName, category, description, price, duration, image, status } = req.body;

    // Strict validation
    if (!serviceName?.trim() || !category?.trim() || !description?.trim() || !image?.trim()) {
      return res.status(400).json({
        message: "serviceName, category, description, and image URL are required.",
      });
    }

    const numericPrice = Number(price);
    const numericDuration = Number(duration);

    if (!Number.isFinite(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({ message: "Price must be a positive number." });
    }

    if (!Number.isFinite(numericDuration) || numericDuration <= 0) {
      return res.status(400).json({ message: "Duration must be a positive number (in minutes)." });
    }

    const newService = {
      serviceName: serviceName.trim(),
      category: category.trim(),
      description: description.trim(),
      price: numericPrice,
      duration: numericDuration,
      image: image.trim(),
      status: status === "inactive" ? "inactive" : "active",
      createdAt: new Date(),
    };

    const result = await servicesCollection.insertOne(newService);
    return res.status(201).json({
      message: "Service created successfully.",
      service: { _id: result.insertedId, ...newService },
    });
  } catch (err) {
    return next(err);
  }
});

// Admin Only: Update service details or toggle active/inactive status
app.patch("/api/services/:id", verifyJWT, verifyAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: "Invalid service ID format." });
    }

    const { serviceName, category, description, price, duration, image, status } = req.body;
    const updates = {};

    if (serviceName !== undefined) updates.serviceName = String(serviceName).trim();
    if (category !== undefined) updates.category = String(category).trim();
    if (description !== undefined) updates.description = String(description).trim();
    if (image !== undefined) updates.image = String(image).trim();

    if (price !== undefined) {
      const numericPrice = Number(price);
      if (!Number.isFinite(numericPrice) || numericPrice <= 0) {
        return res.status(400).json({ message: "Price must be a positive number." });
      }
      updates.price = numericPrice;
    }

    if (duration !== undefined) {
      const numericDuration = Number(duration);
      if (!Number.isFinite(numericDuration) || numericDuration <= 0) {
        return res.status(400).json({ message: "Duration must be a positive number." });
      }
      updates.duration = numericDuration;
    }

    if (status !== undefined) {
      if (status !== "active" && status !== "inactive") {
        return res.status(400).json({ message: 'Status must be either "active" or "inactive".' });
      }
      updates.status = status;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "No valid fields provided to update." });
    }

    updates.updatedAt = new Date();

    const updated = await servicesCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: updates },
      { returnDocument: "after" }
    );

    if (!updated) {
      return res.status(404).json({ message: "Service not found." });
    }

    return res.json({ message: "Service updated successfully.", service: updated });
  } catch (err) {
    return next(err);
  }
});

// Admin Only: Delete a service
app.delete("/api/services/:id", verifyJWT, verifyAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: "Invalid service ID format." });
    }

    const result = await servicesCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Service not found." });
    }

    return res.json({ message: "Service deleted successfully." });
  } catch (err) {
    return next(err);
  }
});

// ============================================================================
// 10.CUSTOMER APPOINTMENTS ROUTES
// ============================================================================

// Customer Only: Submit a new appointment request
app.post("/api/appointments", verifyJWT, verifyCustomer, async (req, res, next) => {
  try {
    const { serviceId, appointmentDate, timeSlot, message } = req.body;

    if (!serviceId || !isValidObjectId(serviceId)) {
      return res.status(400).json({ message: "Valid serviceId is required." });
    }

    if (!appointmentDate?.trim() || !timeSlot?.trim()) {
      return res.status(400).json({ message: "appointmentDate and timeSlot are required." });
    }

    const serviceObjectId = new ObjectId(serviceId);
    const service = await servicesCollection.findOne({ _id: serviceObjectId });

    if (!service) {
      return res.status(404).json({ message: "Service not found." });
    }

    // Rule: Inactive services cannot be booked
    if (service.status !== "active") {
      return res.status(400).json({ message: "Inactive services cannot be booked." });
    }

    // Rule: Prevent double booking of the same slot if an active booking exists
    const existingBooking = await appointmentsCollection.findOne({
      serviceId: serviceObjectId,
      appointmentDate: appointmentDate.trim(),
      timeSlot: timeSlot.trim(),
      status: { $in: ["pending", "confirmed"] },
    });

    if (existingBooking) {
      return res.status(409).json({
        message: "This date and time slot is already booked. Please choose another slot.",
      });
    }

    const newAppointment = {
      serviceId: serviceObjectId,
      customerId: toObjectIdIfValid(req.user._id),
      appointmentDate: appointmentDate.trim(),
      timeSlot: timeSlot.trim(),
      message: message ? String(message).trim() : "",
      servicePrice: service.price, // Price snapshot at time of booking
      paymentStatus: "unpaid",
      status: "pending",
      createdAt: new Date(),
    };

    const result = await appointmentsCollection.insertOne(newAppointment);
    return res.status(201).json({
      message: "Appointment request submitted successfully.",
      appointment: { _id: result.insertedId, ...newAppointment },
    });
  } catch (err) {
    return next(err);
  }
});

// Customer Only: View own appointments list (with service details joined)
app.get("/api/appointments/my", verifyJWT, verifyCustomer, async (req, res, next) => {
  try {
    const customerKey = toObjectIdIfValid(req.user._id);

    const appointments = await appointmentsCollection
      .aggregate([
        { $match: { customerId: customerKey } },
        { $sort: { createdAt: -1 } },
        {
          $lookup: {
            from: "services",
            localField: "serviceId",
            foreignField: "_id",
            as: "service",
          },
        },
        { $unwind: { path: "$service", preserveNullAndEmptyArrays: true } },
      ])
      .toArray();

    return res.json({ appointments });
  } catch (err) {
    return next(err);
  }
});

// Authenticated: View single appointment details (Customer: own only, Admin: any)
app.get("/api/appointments/:id", verifyJWT, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: "Invalid appointment ID format." });
    }

    const [appointment] = await appointmentsCollection
      .aggregate([
        { $match: { _id: new ObjectId(id) } },
        {
          $lookup: {
            from: "services",
            localField: "serviceId",
            foreignField: "_id",
            as: "service",
          },
        },
        { $unwind: { path: "$service", preserveNullAndEmptyArrays: true } },
        {
          $lookup: {
            from: "users",
            localField: "customerId",
            foreignField: "_id",
            as: "customer",
          },
        },
        { $unwind: { path: "$customer", preserveNullAndEmptyArrays: true } },
      ])
      .toArray();

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found." });
    }

    // Role check: Only admin or the appointment owner can view details
    if (req.user.role !== "admin" && String(appointment.customerId) !== String(req.user._id)) {
      return res.status(403).json({ message: "Forbidden: access denied." });
    }

    if (appointment.customer) {
      appointment.customer = sanitizeUser(appointment.customer);
    }


// ============================================================================
// 9. HEALTH CHECK
// ============================================================================
app.get("/", (_req, res) => {
  res.json({ service: "SalonBook API", status: "running" });
});

// ============================================================================
// 10. START SERVER
// ============================================================================
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

export default app;