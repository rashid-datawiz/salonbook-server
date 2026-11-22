# SalonBook — Backend API Server

> **Assignment 9 — Category: 002**  
> REST API Backend for the SalonBook Luxury Appointment Booking Platform.

---

## 📌 Project Overview

**salonbook-server** is a robust, production-grade REST API backend built with **Express.js (v5)**, **Node.js**, and **MongoDB**. It handles authentication, catalog management, appointment workflows, role-based access control, cryptographic JWT issuance, and **Stripe** payment processing with webhook lifecycle management.

---

## ✨ Core Backend Capabilities

### 1. Authentication & Security
- **Better Auth Integration**: Multi-provider authentication supporting credential logins and Google OAuth.
- **JWT Verification Middleware (`verifyJWT`)**: Cryptographic signature validation for protected client requests.
- **Role-Based Authorization (`verifyAdmin`, `verifyCustomer`)**: Enforces strict endpoint boundaries between customers and salon management.
- **Account Blocking Mechanism**: Automatically denies access to blocked users at the middleware layer.

### 2. Service Catalog Management
- `GET /api/services`: Public active service listings with category filtering.
- `GET /api/admin/services`: Admin catalog audit including inactive rituals.
- `POST /api/services`: Create new ritual with price and duration validations.
- `PATCH /api/services/:id`: Modify ritual information or toggle active status.
- `DELETE /api/services/:id`: Remove service entry.

### 3. Appointment Booking System
- `POST /api/appointments`: Authenticated customer appointment reservation with conflict prevention.
- `GET /api/appointments/my`: Customer-specific appointment ledger.
- `PATCH /api/appointments/:id/cancel`: Customer cancellation of pending requests.
- `GET /api/admin/appointments`: Administrative appointment overview with `$lookup` customer and service joins.
- `PATCH /api/admin/appointments/:id/status`: Admin status updates (`confirmed` or `cancelled`).

### 4. Stripe Checkout & Immutable Financial Ledger
- `POST /api/payments/create-checkout-session`: Generates hosted Stripe Checkout sessions with verified appointment metadata.
- `POST /api/payments/webhook`: Raw-body Stripe webhook receiver validating signatures (`stripe.webhooks.constructEvent`). Listens for `checkout.session.completed` to atomically mark appointments as `paid` and upsert immutable records into `transactions`.
- `GET /api/payments/verify-session/:sessionId`: Direct session verification for return redirects.
- `GET /api/admin/transactions`: Read-only financial ledger aggregating transaction history with customers, appointments, and services. Manual financial edits are strictly disallowed.
- `GET /api/transactions/my`: Customer personal transaction history.

### 5. Registered Customer Directory
- `GET /api/admin/users`: Audit all registered customer profiles.
- `PATCH /api/admin/users/:id/block`: Admin toggle to block or restore customer platform access.

---

## 🛠 Technology Stack

- **Runtime**: [Node.js](https://nodejs.org/)
- **Framework**: [Express.js 5](https://expressjs.com/)
- **Database**: [MongoDB](https://www.mongodb.com/) (Native Driver v7.9)
- **Authentication**: [Better Auth](https://www.better-auth.com/) & [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
- **Payments**: [Stripe](https://stripe.com/)
- **CORS & Environment**: `cors`, `dotenv`

---

## 🚀 Getting Started

### Prerequisites
- Node.js `v20.x` or higher
- MongoDB instance (local or MongoDB Atlas)
- Stripe developer account with test API keys

### 1. Clone & Install
```bash
git clone <server-repo-url>
cd salonbook-server
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```env
PORT=5001
DB_URI=your_mongodb_connection_string
BETTER_AUTH_SECRET=your_better_auth_secret_here
BETTER_AUTH_URL=http://localhost:5001
CLIENT_URL=http://localhost:3000
JWT_SECRET=your_jwt_signing_secret_here
STRIPE_SECRET_KEY=your_stripe_secret_key_here
STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key_here
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret_here
```

### 3. Run the Server
```bash
node index.js
```
The server will start on port `5001`.

---

## 📋 Required Environment Variables (Names Only)

- `PORT`
- `DB_URI`
- `BETTER_AUTH_SECRET`
- `BETTER_AUTH_URL`
- `CLIENT_URL`
- `JWT_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_PUBLISHABLE_KEY`
- `STRIPE_WEBHOOK_SECRET`

---

## 🔗 Project Links

- **Live Application**: *https://salonbook-client-rose.vercel.app/*
- **Client GitHub Repository**: *https://github.com/rashid-datawiz/salonbook-client*
