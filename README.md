# 🚀 NexTrade: Professional B2B Marketplace

NexTrade is a next-generation B2B platform designed to revolutionize the way retailers and wholesalers interact. Moving away from traditional, cumbersome cart-and-order systems, NexTrade focuses on **real-time communication**, **AI-enhanced product discovery**, and **deal-based interactions**.

Built with a modern tech stack and integrated with cutting-edge AI, NexTrade provides a seamless, secure, and smart environment for business growth.

---

## ✨ Key Features

### 🏢 Dual-User Experience
- **Wholesaler Portal**: Efficient inventory management, AI-powered product auto-tagging, and deep business analytics.
- **Retailer Portal**: Discovery-focused interface with smart search, location-based filters, and direct inquiry flows.

### 🤖 AI-Powered Intelligence
- **Intelligent Search**: Semantic search that understands broad categories and synonyms (powered by Groq).
- **Auto-Tagging**: Instantly generate product names, categories, and descriptions from images using Vision AI.
- **Context-Aware Chatbot**: A dedicated business assistant that helps users find products, analyze stock, and answer queries.

### 💬 Real-Time Business Communication
- **WhatsApp-style Messaging**: Instant chat with support for image, audio, and text.
- **Inquiry Cards**: Share product details directly in the chat with "Reserved Stock" functionality for serious buyers.
- **Read Receipts & Status**: Real-time message tracking and online presence indicators.

### 📊 Smart Inventory & Analytics
- **Demand Forecasting**: Real-time distribution analysis and low-stock alerts.
- **Reserved Stock**: Dynamic inventory management that holds stock during active negotiations.

### 💳 Secure Transactions
- **Razorpay Integration**: Seamless and secure payment processing for confirmed orders.
- **Digital Invoicing**: Automated record-keeping for every transaction.

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3 (Vanilla), JavaScript, Socket.IO Client, GSAP, Lucide Icons |
| **Backend** | Node.js, Express.js |
| **Database** | MongoDB (Mongoose ODM) |
| **AI/ML** | Groq Cloud SDK (Llama 3.2 Vision, 3.3 70B Versatile) |
| **Real-time** | Socket.IO |
| **Payments** | Razorpay |
| **Auth** | JWT (JSON Web Tokens), bcryptjs |

---

## 📂 Project Structure

```bash
├── public/                 # Frontend Assets
│   ├── css/                # Stylesheets (Chatbot, Dashboard, etc.)
│   ├── js/                 # Client-side scripts
│   ├── index.html          # Landing Page
│   ├── browse-products.html# Product Discovery
│   ├── messages.html       # Messaging Portal
│   ├── profile.html        # Business Profiles
│   ├── wholesaler-dashboard.html
│   └── retailer-dashboard.html
├── image/                  # Static images/assets
├── server.js               # Main API & WebSocket Server
├── .env                    # Environment Configuration
└── package.json            # Project Dependencies
```

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kaif0008/nextrade-0.1.git
   cd nextrade-0.1
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory and add the following:
   ```env
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret_key
   GROQ_API_KEY=your_groq_api_key
   RAZORPAY_KEY_ID=your_razorpay_key_id
   RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   ```

4. **Run the server:**
   ```bash
   npm start
   ```
   *The server will typically run on `http://localhost:5010`.*

---

## 📑 API Overview

### Authentication
- `POST /signup`: Register as Retailer or Wholesaler (GST validation included).
- `POST /login`: Authenticate and receive JWT.

### Products
- `GET /products`: Search products with AI-enhanced context.
- `POST /products`: Add new inventory (Wholesalers only).
- `POST /products/auto-tag`: Generate metadata for image-based uploads.

### Communication
- `GET /conversations`: Retrieve all active chat threads.
- `GET /messages/:userId`: Fetch message history with a specific user.
- `POST /ai/chat`: Interact with the Groq-powered AI assistant.

---

## 📸 Screenshots
*(Add your project screenshots here to wow your viewers!)*
> [!TIP]
> Use high-resolution images of the Wholesaler Dashboard and the Messaging Portal.

---

## 🔮 Future Enhancements
- [ ] **Advanced Inventory Analytics**: Machine learning for predictive stock management.
- [ ] **Global Logistics Integration**: Real-time shipping tracking within the platform.
- [ ] **Mobile App**: Native iOS and Android versions (in progress).

---

## 👥 Meet the Team

| Name | Role | Responsibilities |
|---|---|---|
| **Kaif Ansari (TL)** | Backend & AI Lead | Backend dev, AI/ML models, system architecture, and technical decisions. |
| **Aryan Ranjan** | Full-Stack Support | Frontend development, Backend Intern support. |
| **Kaniksha Sharma** | Mobile & Docs | Mobile development, project documentation, research paper. |
| **Kanishka Tyagi** | UI/UX Designer | Frontend assistance, UI/UX planning, and user experience analysis. |

---

## 🎓 Academic Context
This project was developed as a **College Group Project** at [Your College Name]. It represents a collaborative effort to solve real-world B2B supply chain challenges using modern web technologies.
