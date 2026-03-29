const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();

const http = require('http');
const { Server } = require('socket.io');

// ================= CONSTANTS =================
const SALT_ROUNDS = 10;
const DEFAULT_PORT = 5010;
const JWT_SECRET = process.env.JWT_SECRET || 'nextrade_secret';

// ================= DB CONNECTION =================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/nextrade')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// ================= RAZORPAY =================
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ================= MIDDLEWARE =================
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ================= AUTH MIDDLEWARE =================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: "Session expired, please login again" });
    }
    return res.status(401).json({ success: false, message: "Invalid token" });
  }
};

// ================= MODELS =================

// User
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['admin', 'wholesaler', 'retailer'] },
  // Profile Details
  mobileNumber: String,
  photoUrl: String,
  dob: String,
  gender: String,
  // Business Details
  businessName: String,
  businessType: String,
  industry: String,
  gstNumber: String,
  yearOfEstablishment: String,
  websiteUrl: String,
  businessDescription: String,
  // Address Details
  houseNo: String,
  street: String,
  block: String,
  district: String,
  city: String,
  state: String,
  pincode: String,
  country: { type: String, default: 'India' },
  // Legacy fields
  shopName: String,
  shopAddress: String
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
  next();
});

userSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.password;
  return user;
};

const User = mongoose.model('User', userSchema);

// Product
const productSchema = new mongoose.Schema({
  name: String,
  pricePerUnit: Number,
  unit: String,
  category: String,
  image: String,
  description: String,
  stock: Number,
  moq: Number,
  wholesalerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// Order (SECURE VERSION)
const orderSchema = new mongoose.Schema({
  productName: String,
  price: Number,
  quantity: Number,
  address: String,
  paymentMethod: String,
  paymentStatus: { type: String, default: 'Pending' },
  razorpayOrderId: String,
  razorpayPaymentId: String,
  customerName: String,
  email: String,
  phone: String,
  status: { type: String, default: 'Processing' }
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);

//Message
const messageSchema = new mongoose.Schema({
  senderId: String,
  receiverId: String,
  productName: String,
  message: String
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// ================= ROUTES =================
const router = express.Router();

// ---------- AUTH ----------
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role, gstNumber } = req.body;

    // ✅ Basic validation
    if (!name || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    // ✅ GST rule
    const gstRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;

    // Wholesaler → GST required + valid
    if (role === "wholesaler") {
      if (!gstNumber || !gstRegex.test(gstNumber)) {
        return res.status(400).json({
          success: false,
          message: "Valid GST is required for wholesalers"
        });
      }
    }

    // Retailer → GST optional but must be valid if given
    if (role === "retailer" && gstNumber) {
      if (!gstRegex.test(gstNumber)) {
        return res.status(400).json({
          success: false,
          message: "Invalid GST format"
        });
      }
    }

    // ✅ Check existing user
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists"
      });
    }

    // ✅ Create user
    const user = new User({
      name,
      email,
      password,
      role,
      gstNumber
    });

    await user.save();

    res.status(201).json({
      success: true,
      message: "Account created successfully"
    });

  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Signup failed"
    });
  }
});


router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

  res.json({
    success: true,
    token,
    user
  });
});

// Get all registered wholesalers
router.get('/wholesalers', async (req, res) => {
  try {
    const wholesalers = await User.find(
      { role: 'wholesaler' },
      { password: 0 } // exclude password
    );

    res.json({
      success: true,
      wholesalers
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch wholesalers'
    });
  }
});

// Get products of a specific wholesaler
router.get('/products/wholesaler/:id', async (req, res) => {
  try {
    const products = await Product.find({
      wholesalerId: req.params.id
    }).sort({ createdAt: -1 });

    res.json({
      success: true,
      products
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch products'
    });
  }
});

// Get logged-in wholesaler products ONLY
router.get('/products/my', authMiddleware, async (req, res) => {
  if (req.user.role !== 'wholesaler') {
    return res.status(403).json({ success: false });
  }

  const products = await Product.find({
    wholesalerId: req.user.id
  }).sort({ createdAt: -1 });

  res.json({ success: true, products });
});


const ALLOWED_PROFILE_FIELDS = [
  'name', 'mobileNumber', 'photoUrl', 'dob', 'gender',
  'businessName', 'businessType', 'industry', 'gstNumber',
  'yearOfEstablishment', 'websiteUrl', 'businessDescription',
  'houseNo', 'street', 'block', 'district', 'city',
  'state', 'pincode', 'country', 'shopName', 'shopAddress'
];

router.post("/update-profile", authMiddleware, async (req, res) => {
  try {
    const safeUpdate = {};

    for (const field of ALLOWED_PROFILE_FIELDS) {
      if (req.body[field] !== undefined) {
        safeUpdate[field] = req.body[field];
      }
    }

    // 🔥 TRIM DATA
    for (const field in safeUpdate) {
      if (typeof safeUpdate[field] === "string") {
        safeUpdate[field] = safeUpdate[field].trim();
      }
    }

    // 🔐 GST VALIDATION
    if (safeUpdate.gstNumber) {
      const gstRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
      if (!gstRegex.test(safeUpdate.gstNumber)) {
        return res.status(400).json({
          success: false,
          message: "Invalid GST Number"
        });
      }
    }

    // 📱 MOBILE VALIDATION
    if (safeUpdate.mobileNumber) {
      if (!/^[0-9]{10}$/.test(safeUpdate.mobileNumber)) {
        return res.status(400).json({
          success: false,
          message: "Invalid mobile number"
        });
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      safeUpdate,
      { new: true, runValidators: true }
    );

    res.json({ success: true, user: updatedUser });

  } catch (err) {
    res.status(500).json({ success: false, message: "Profile update failed" });
  }
});


// ---------- PRODUCTS ----------
router.post('/products', authMiddleware, async (req, res) => {
  if (req.user.role !== 'wholesaler') {
    return res.status(403).json({ success: false, message: 'Only wholesalers can add products' });
  }

  const product = new Product({ ...req.body, wholesalerId: req.user.id });
  await product.save();

  res.status(201).json({ success: true, product });
});

router.get('/products', async (req, res) => {
  const search = req.query.search || '';
  const regex = new RegExp(search, 'i');

  const products = await Product.find({
    $or: [{ name: regex }, { category: regex }]
  }).sort({ createdAt: -1 });

  res.json({ success: true, products });
});

router.delete('/products/:id', authMiddleware, async (req, res) => {
  const product = await Product.findOne({
    _id: req.params.id,
    wholesalerId: req.user.id
  });

  if (!product) {
    return res.status(403).json({
      success: false,
      message: 'Not allowed'
    });
  }

  await product.deleteOne();
  res.json({ success: true });
});

router.put('/products/:id', authMiddleware, async (req, res) => {
  const product = await Product.findOneAndUpdate(
    { _id: req.params.id, wholesalerId: req.user.id },
    req.body,
    { new: true }
  );

  if (!product) {
    return res.status(403).json({ success: false });
  }

  res.json({ success: true, product });
});


// ---------- ORDERS ----------
router.post('/orders', async (req, res) => {
  const order = new Order(req.body);
  await order.save();
  res.status(201).json({ success: true, order });
});

router.get('/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find().sort({ createdAt: -1 });
  res.json({ success: true, orders });
});

// ---------- MESSAGES ----------

// Save message
router.post('/messages', authMiddleware, async (req, res) => {
  try {
    const msg = new Message(req.body);
    await msg.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to save message" });
  }
});

// Get chat messages between users
router.get('/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { senderId: req.user.id, receiverId: req.params.userId },
        { senderId: req.params.userId, receiverId: req.user.id }
      ]
    }).sort({ createdAt: 1 });

    res.json({ success: true, messages });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch messages" });
  }
});

// Get all conversations (like WhatsApp list)
router.get("/conversations", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const messages = await Message.find({
      $or: [
        { senderId: userId },
        { receiverId: userId }
      ]
    }).sort({ createdAt: -1 });

    const userIds = new Set();

    messages.forEach(msg => {
      if (msg.senderId !== userId) userIds.add(msg.senderId);
      if (msg.receiverId !== userId) userIds.add(msg.receiverId);
    });

    const users = await User.find(
      { _id: { $in: Array.from(userIds) } },
      { name: 1, role: 1 }
    );

    res.json({ success: true, users });

  } catch (err) {
  console.error("PROFILE UPDATE ERROR:", err);
  res.status(500).json({
    success: false,
    message: err.message
  });
}
});


// ---------- RAZORPAY ----------
app.post('/api/create-order', async (req, res) => {
  const order = await razorpay.orders.create({
    amount: Math.round(req.body.amount),
    currency: 'INR',
    receipt: `receipt_${Date.now()}`
  });
  res.json(order);
});

app.get('/api/get-razorpay-key', (req, res) => {
  res.json({ key: process.env.RAZORPAY_KEY_ID });
});

// ================= MOUNT ROUTER =================
app.use('/api', router);

// ================= STATIC =================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ================= START =================
const PORT = process.env.PORT || DEFAULT_PORT;

const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*" }
});

let users = {};

// SOCKET CONNECTION

io.on("connection", (socket) => {

  socket.on("register", (userId) => {
    users[userId] = socket.id;
  });

  socket.on("send_message", async (data) => {
    const { senderId, receiverId, message, productName } = data;

    // Save message in DB
    const newMsg = new Message({
      senderId,
      receiverId,
      message,
      productName
    });

    await newMsg.save();

    // Send to receiver
    if (users[receiverId]) {
      io.to(users[receiverId]).emit("receive_message", newMsg);
    }

    // Send back to sender (sync UI)
    socket.emit("receive_message", newMsg);
  });

  socket.on("disconnect", () => {
    for (let id in users) {
      if (users[id] === socket.id) {
        delete users[id];
      }
    }
  });

});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
