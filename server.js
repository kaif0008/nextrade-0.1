const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();

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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
  businessName: String,
  gstNumber: String,
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
  price: Number,
  category: String,
  image: String,
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

// ================= ROUTES =================
const router = express.Router();

// ---------- AUTH ----------
router.post('/signup', async (req, res) => {
  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).json({ success: true, message: 'Account created', user });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
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
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
