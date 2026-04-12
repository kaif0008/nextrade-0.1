const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
require('dotenv').config();

const nodemailer = require('nodemailer');

const app = express();

const http = require('http');
const { Server } = require('socket.io');

// ================= AI CONFIGURATION (GROQ) =================
const Groq = require('groq-sdk');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || 'fake_key' });

// ================= EMAIL TRANSPORTER (NODEMAILER) =================
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(toEmail, otp, userName) {
  const mailOptions = {
    from: `"NexTrade" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: 'Your NexTrade Verification Code',
    html: `
      <!DOCTYPE html>
      <html>
      <head><meta charset="UTF-8"></head>
      <body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',sans-serif;">
        <div style="max-width:560px;margin:40px auto;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
          <div style="background:linear-gradient(135deg,#4361ee,#4895ef);padding:36px 40px;text-align:center;">
            <h1 style="color:white;margin:0;font-size:26px;font-weight:700;">NexTrade</h1>
            <p style="color:rgba(255,255,255,0.85);margin:6px 0 0;font-size:14px;">B2B Trading Platform</p>
          </div>
          <div style="padding:40px;text-align:center;">
            <h2 style="color:#2b2d42;margin:0 0 8px;font-size:20px;">Email Verification</h2>
            <p style="color:#8d99ae;font-size:14px;margin:0 0 32px;">Hello ${userName}, here is your verification code:</p>
            <div style="background:#f0f4ff;border:2px dashed #4361ee;border-radius:12px;padding:24px;margin:0 auto 28px;display:inline-block;">
              <span style="font-size:48px;font-weight:800;letter-spacing:12px;color:#4361ee;">${otp}</span>
            </div>
            <p style="color:#ef233c;font-size:13px;font-weight:600;margin:0 0 8px;">⏱ This code expires in <strong>5 minutes</strong></p>
            <p style="color:#8d99ae;font-size:12px;margin:0;">If you didn&apos;t request this, you can safely ignore this email.</p>
          </div>
          <div style="background:#f8fafc;padding:20px 40px;text-align:center;border-top:1px solid #f1f5f9;">
            <p style="color:#8d99ae;font-size:11px;margin:0;">NexTrade &bull; Secure B2B Platform &bull; Do not share this code with anyone</p>
          </div>
        </div>
      </body>
      </html>
    `
  };
  return emailTransporter.sendMail(mailOptions);
}

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
  businessPhotoUrl: String,
  businessPhotos: [String],
  primaryBusinessPhotoIndex: { type: Number, default: 0 },
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
  shopAddress: String,
  // Email Verification
  emailVerified: { type: Boolean, default: false },
  otpCode: String,
  otpExpiry: Date,
  otpAttempts: { type: Number, default: 0 },
  otpRequestedAt: Date
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
  reservedStock: { type: Number, default: 0 },
  soldCount: { type: Number, default: 0 },
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

// Deal (Negotiation system)
const dealSchema = new mongoose.Schema({
  retailerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  wholesalerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  productName: String,
  productImage: String,
  listPrice: Number,
  quantity: { type: Number, default: 1 },
  offeredPrice: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'wholesaler_accepted', 'confirmed', 'rejected'], default: 'pending' },
}, { timestamps: true });

const Deal = mongoose.model('Deal', dealSchema);

// Review Model
const reviewSchema = new mongoose.Schema({
  retailerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  wholesalerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  dealId: { type: mongoose.Schema.Types.ObjectId, ref: 'Deal' },
  rating: { type: Number, required: true, min: 1, max: 5 },
  reviewText: String
}, { timestamps: true });

const Review = mongoose.model('Review', reviewSchema);

// Message
const messageSchema = new mongoose.Schema({
  senderId: String,
  receiverId: String,
  productName: String,
  productData: { type: mongoose.Schema.Types.Mixed }, // now handles product and deal metadata
  message: String,
  type: { type: String, enum: ['text', 'image', 'audio', 'deal', 'system'], default: 'text' },
  status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
  deletedBy: { type: [String], default: [] }
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// ================= ROUTES =================
const router = express.Router();

// ================= EMAIL VERIFICATION MIDDLEWARE =================
const requireEmailVerified = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.emailVerified) {
      return res.status(403).json({
        success: false,
        code: 'EMAIL_NOT_VERIFIED',
        message: 'Email verification required. Please verify your email from your Profile page.'
      });
    }
    next();
  } catch (err) {
    res.status(500).json({ success: false, message: 'Verification check failed' });
  }
};

// ---------- AUTH ----------
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role, gstNumber } = req.body;

    // âœ… Basic validation
    if (!name || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    // âœ… GST rule
    const gstRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;

    // Wholesaler â†’ GST required + valid
    if (role === "wholesaler") {
      if (!gstNumber || !gstRegex.test(gstNumber)) {
        return res.status(400).json({
          success: false,
          message: "Valid GST is required for wholesalers"
        });
      }
    }

    // Retailer â†’ GST optional but must be valid if given
    if (role === "retailer" && gstNumber) {
      if (!gstRegex.test(gstNumber)) {
        return res.status(400).json({
          success: false,
          message: "Invalid GST format"
        });
      }
    }

    // âœ… Check existing user
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists"
      });
    }

    // âœ… Create user
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

// ---------- OTP EMAIL VERIFICATION ----------

router.post('/auth/send-otp', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.emailVerified) return res.status(400).json({ success: false, message: 'Email is already verified' });

    // Rate limiting: 1 OTP per 60 seconds
    if (user.otpRequestedAt) {
      const secondsSinceLast = (Date.now() - new Date(user.otpRequestedAt).getTime()) / 1000;
      if (secondsSinceLast < 60) {
        const waitSecs = Math.ceil(60 - secondsSinceLast);
        return res.status(429).json({ success: false, message: `Please wait ${waitSecs} seconds before requesting a new OTP` });
      }
    }

    const otp = generateOTP();
    const hashedOtp = await bcrypt.hash(otp, 8);
    const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    user.otpCode = hashedOtp;
    user.otpExpiry = expiry;
    user.otpAttempts = 0;
    user.otpRequestedAt = new Date();
    await user.save();

    await sendOTPEmail(user.email, otp, user.name);

    res.json({ success: true, message: `OTP sent to ${user.email}` });
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP. Check email configuration.' });
  }
});

router.post('/auth/verify-otp', authMiddleware, async (req, res) => {
  try {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ success: false, message: 'OTP is required' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.emailVerified) return res.status(400).json({ success: false, message: 'Email already verified' });

    // Check attempts
    if (user.otpAttempts >= 3) {
      return res.status(400).json({ success: false, message: 'Too many incorrect attempts. Please request a new OTP.' });
    }

    // Check expiry
    if (!user.otpExpiry || new Date() > new Date(user.otpExpiry)) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
    }

    // Check OTP
    const isMatch = await bcrypt.compare(otp.trim(), user.otpCode);
    if (!isMatch) {
      user.otpAttempts = (user.otpAttempts || 0) + 1;
      await user.save();
      const remaining = 3 - user.otpAttempts;
      return res.status(400).json({ success: false, message: `Incorrect OTP. ${remaining} attempt(s) remaining.` });
    }

    // Success — clear OTP fields
    user.emailVerified = true;
    user.otpCode = undefined;
    user.otpExpiry = undefined;
    user.otpAttempts = 0;
    user.otpRequestedAt = undefined;
    await user.save();

    res.json({ success: true, message: 'Email verified successfully!', user });
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ success: false, message: 'Verification failed' });
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
    ).lean();

    const reviews = await Review.find();
    
    // Compute average ratings
    const wsWithRatings = wholesalers.map(ws => {
      const wReviews = reviews.filter(r => String(r.wholesalerId) === String(ws._id));
      const avg = wReviews.length > 0 ? (wReviews.reduce((sum, r) => sum + r.rating, 0) / wReviews.length).toFixed(1) : 0;
      return { ...ws, averageRating: Number(avg), reviewCount: wReviews.length };
    });

    res.json({
      success: true,
      wholesalers: wsWithRatings
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
    const wholesaler = await User.findById(req.params.id, { password: 0 }).lean();
    const products = await Product.find({
      wholesalerId: req.params.id
    }).sort({ createdAt: -1 });

    const reviews = await Review.find({ wholesalerId: req.params.id });
    const avg = reviews.length > 0 ? (reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length).toFixed(1) : 0;
    
    wholesaler.averageRating = Number(avg);
    wholesaler.reviewCount = reviews.length;

    res.json({
      success: true,
      wholesaler,
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

// Get Wholesaler Inventory Analytics
router.get('/analytics/inventory', authMiddleware, async (req, res) => {
  if (req.user.role !== 'wholesaler') {
    return res.status(403).json({ success: false });
  }

  try {
    const products = await Product.find({ wholesalerId: req.user.id });

    const totalProducts = products.length;
    let lowStockItems = [];
    let criticalStock = 0;
    const categoryDistribution = {};
    let mostSoldProduct = null;
    let maxSold = -1;

    products.forEach(p => {
      const sold = p.soldCount || 0;
      const daysSinceCreation = Math.max(1, Math.floor((new Date() - new Date(p.createdAt)) / (1000 * 60 * 60 * 24)));
      const runRate = sold / daysSinceCreation;
      let forecastDays = -1;
      if (runRate > 0) forecastDays = Math.round(p.stock / runRate);
      
      // Low stock
      if (p.stock <= 10) {
        lowStockItems.push({ id: p._id, name: p.name, stock: p.stock, forecastDays });
      }
      if (p.stock === 0) criticalStock++;

      // Distribution
      const cat = p.category || 'Uncategorized';
      categoryDistribution[cat] = (categoryDistribution[cat] || 0) + (p.stock || 0);

      // Most Sold
      if (sold > maxSold) {
        maxSold = sold;
        mostSoldProduct = { name: p.name, count: sold };
      }
    });

    res.json({
      success: true,
      analytics: {
        totalProducts,
        lowStockCount: lowStockItems.length,
        criticalStockCount: criticalStock,
        lowStockItems: lowStockItems,
        mostSoldProduct: maxSold > 0 ? mostSoldProduct : null,
        stockDistribution: categoryDistribution
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch analytics' });
  }
});


const ALLOWED_PROFILE_FIELDS = [
  'name', 'mobileNumber', 'photoUrl', 'dob', 'gender',
  'businessName', 'businessType', 'industry', 'gstNumber',
  'yearOfEstablishment', 'websiteUrl', 'businessDescription', 'businessPhotoUrl',
  'businessPhotos', 'primaryBusinessPhotoIndex',
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

    // ðŸ”¥ TRIM DATA
    for (const field in safeUpdate) {
      if (typeof safeUpdate[field] === "string") {
        safeUpdate[field] = safeUpdate[field].trim();
      }
    }

    // ðŸ” GST VALIDATION
    if (safeUpdate.gstNumber) {
      const gstRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
      if (!gstRegex.test(safeUpdate.gstNumber)) {
        return res.status(400).json({
          success: false,
          message: "Invalid GST Number"
        });
      }
    }

    // ðŸ“± MOBILE VALIDATION
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
router.post('/products', authMiddleware, requireEmailVerified, async (req, res) => {
  if (req.user.role !== 'wholesaler') {
    return res.status(403).json({ success: false, message: 'Only wholesalers can add products' });
  }

  const product = new Product({ ...req.body, wholesalerId: req.user.id });
  await product.save();

  res.status(201).json({ success: true, product });
});

router.post('/products/auto-tag', authMiddleware, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ success: false, message: 'No image provided' });

    const mimeMatch = image.match(/^data:(.*?);base64,/);
    const mimeType = mimeMatch ? mimeMatch[1] : 'image/jpeg';
    const base64Data = image.replace(/^data:(.*?);base64,/, "");

    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: `Analyze this product image for an e-commerce B2B platform. 
            Provide a JSON response with the following keys EXACTLY:
            "suggestedName": A clear, concise product name.
            "category": The closest broad category (e.g., Electronics, Clothing, Groceries).
            "description": A 2-sentence description.` },
            {
              type: "image_url",
              image_url: {
                url: `data:${mimeType};base64,${base64Data}`,
              },
            },
          ],
        },
      ],
      model: "llama-3.2-11b-vision-preview",
      response_format: { type: "json_object" }
    });

    const aiData = JSON.parse(completion.choices[0].message.content);
    res.json({ success: true, tags: aiData });
  } catch (error) {
    console.error('Auto tag error:', error);
    res.status(500).json({ success: false, message: 'Failed to analyze image' });
  }
});

router.get('/products', async (req, res) => {
  const search = req.query.search || '';
  
  if (!search) {
    const products = await Product.find().sort({ createdAt: -1 });
    return res.json({ success: true, products });
  }

  try {
    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are a helpful assistant that provides synonyms or broader categories for search terms. Return ONLY a comma-separated list of words."
        },
        {
          role: "user",
          content: `Give me 2 synonyms or related broader category words for the e-commerce search term: "${search}".`
        }
      ],
      model: "llama-3.3-70b-versatile",
    });
    
    const aiText = completion.choices[0].message.content;
    
    const terms = [search, ...aiText.split(',').map(s => s.trim().toLowerCase()).filter(s => s)];
    const regexes = terms.map(term => new RegExp(term, 'i'));

    const products = await Product.find({
      $or: [
        { name: { $in: regexes } },
        { category: { $in: regexes } }
      ]
    }).sort({ createdAt: -1 });

    res.json({ success: true, products, aiContext: terms });
  } catch (err) {
    const regex = new RegExp(search, 'i');
    const products = await Product.find({
      $or: [{ name: regex }, { category: regex }]
    }).sort({ createdAt: -1 });
    res.json({ success: true, products });
  }
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

router.patch('/products/:id/stock', authMiddleware, async (req, res) => {
  const { amount } = req.body;
  if (!amount) return res.status(400).json({ success: false, message: 'Amount is required' });

  const product = await Product.findOneAndUpdate(
    { _id: req.params.id, wholesalerId: req.user.id },
    { $inc: { stock: amount } },
    { new: true }
  );

  if (!product) return res.status(403).json({ success: false });
  res.json({ success: true, product });
});

router.post('/products/:id/inquiry', authMiddleware, async (req, res) => {
  const { qty } = req.body;
  const incQty = qty || 1;
  const product = await Product.findByIdAndUpdate(
    req.params.id,
    { $inc: { reservedStock: incQty } },
    { new: true }
  );
  if (!product) return res.status(404).json({ success: false });
  res.json({ success: true, product });
});

router.post('/products/inquiry-by-name', authMiddleware, async (req, res) => {
  const { productName, qty } = req.body;
  if (!productName) return res.status(400).json({ success: false, message: 'Product name required' });
  
  const incQty = qty || 1;
  const product = await Product.findOneAndUpdate(
    { name: productName },
    { $inc: { reservedStock: incQty } },
    { new: true }
  );
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  res.json({ success: true, product });
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
router.post('/orders', authMiddleware, requireEmailVerified, async (req, res) => {
  const order = new Order(req.body);
  await order.save();
  res.status(201).json({ success: true, order });
});

router.get('/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find().sort({ createdAt: -1 });
  res.json({ success: true, orders });
});

router.patch('/orders/:id/confirm', authMiddleware, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
    
    if (order.status === 'Confirmed') {
      return res.status(400).json({ success: false, message: 'Order already confirmed' });
    }

    order.status = 'Confirmed';
    await order.save();

    const decQty = order.quantity || 1;

    // Decrease stock/reservedStock and increase soldCount
    await Product.findOneAndUpdate(
      { name: order.productName },
      { $inc: { stock: -decQty, reservedStock: -decQty, soldCount: decQty } }
    );

    res.json({ success: true, order });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
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
      ],
      deletedBy: { $ne: req.user.id }
    }).sort({ createdAt: 1 });

    res.json({ success: true, messages });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch messages" });
  }
});

// Delete entire conversation (Soft Delete for current user)
router.delete('/messages/:targetUserId', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const targetUserId = req.params.targetUserId;

    await Message.updateMany(
      {
        $or: [
          { senderId: userId, receiverId: targetUserId },
          { senderId: targetUserId, receiverId: userId }
        ],
        deletedBy: { $ne: userId }
      },
      { $addToSet: { deletedBy: userId } }
    );
    res.json({ success: true, message: "Conversation deleted for you" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to delete conversation" });
  }
});

// Mark messages as read
router.patch('/messages/mark-read/:targetUserId', authMiddleware, async (req, res) => {
  try {
    await Message.updateMany(
      { senderId: req.params.targetUserId, receiverId: req.user.id, status: { $ne: 'read' } },
      { $set: { status: 'read' } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to mark messages as read" });
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
      ],
      deletedBy: { $ne: userId }
    }).sort({ createdAt: -1 });
    const userIds = new Set();
    const latestMessages = {};

    messages.forEach(msg => {
      let sId = msg.senderId ? msg.senderId.toString() : "";
      let rId = msg.receiverId ? msg.receiverId.toString() : "";
      let userIdStr = userId.toString();

      let otherId = sId === userIdStr ? rId : sId;
      if (otherId && !userIds.has(otherId)) {
        userIds.add(otherId);
        latestMessages[otherId] = msg;
      }
    });

    const validUserIds = Array.from(userIds).filter(id => id && /^[0-9a-fA-F]{24}$/.test(id));

    const users = await User.find(
      { _id: { $in: validUserIds } },
      { name: 1, role: 1, businessName: 1, email: 1 }
    );

    const conversations = await Promise.all(users.map(async u => {
      const uIdStr = u._id.toString();
      const unreadCount = await Message.countDocuments({
        senderId: uIdStr,
        receiverId: userId,
        status: { $ne: 'read' }
      });

      return {
        user: u,
        lastMessage: latestMessages[uIdStr],
        unreadCount
      };
    }));

    conversations.sort((a,b) => {
      const timeA = a.lastMessage ? new Date(a.lastMessage.createdAt) : 0;
      const timeB = b.lastMessage ? new Date(b.lastMessage.createdAt) : 0;
      return timeB - timeA;
    });

    res.json({ success: true, conversations });

  } catch (err) {
    console.error("CONVERSATION LOAD ERROR:", err);
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

// ---------- DEALS AND REVIEWS ----------

// Helper: build deal productData for messages
function buildDealMsgData(deal) {
  return {
    dealId: deal._id,
    productId: deal.productId,
    name: deal.productName,
    image: deal.productImage,
    listPrice: deal.listPrice,
    quantity: deal.quantity,
    offeredPrice: deal.offeredPrice,
    status: deal.status
  };
}

router.post('/deals/create', authMiddleware, requireEmailVerified, async (req, res) => {
  try {
    const { wholesalerId, productId, quantity, offeredPrice } = req.body;
    if (!wholesalerId || !productId) return res.status(400).json({ success: false, message: 'wholesalerId and productId are required' });
    const reqQty = Math.max(1, parseInt(quantity) || 1);
    const reqPrice = parseFloat(offeredPrice) || 0;

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });

    const reserved = product.reservedStock || 0;
    const currentStock = product.stock || 0;
    if (currentStock - reserved < reqQty) {
      return res.status(400).json({ success: false, message: `Only ${currentStock - reserved} units available` });
    }

    product.reservedStock = reserved + reqQty;
    await product.save();

    const deal = new Deal({
      retailerId: req.user.id,
      wholesalerId,
      productId,
      productName: product.name,
      productImage: product.image || '',
      listPrice: product.pricePerUnit || 0,
      quantity: reqQty,
      offeredPrice: reqPrice,
      status: 'pending'
    });
    await deal.save();

    const msg = new Message({
      senderId: req.user.id,
      receiverId: wholesalerId,
      type: 'deal',
      message: '',
      productData: buildDealMsgData(deal)
    });
    await msg.save();

    // Emit real-time socket events to both parties
    const io = req.app.get('io');
    const onlineUsers = req.app.get('onlineUsers');
    const dealEvent = { msg: msg.toObject(), deal: deal.toObject() };
    if (onlineUsers.has(wholesalerId)) io.to(onlineUsers.get(wholesalerId)).emit('deal_created', dealEvent);
    if (onlineUsers.has(String(req.user.id))) io.to(onlineUsers.get(String(req.user.id))).emit('deal_created', dealEvent);

    res.json({ success: true, deal, message: msg });
  } catch (err) {
    console.error('Deal create error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// Update deal offer (quantity + price renegotiation)
router.patch('/deals/:id/update', authMiddleware, async (req, res) => {
  try {
    const { quantity, offeredPrice } = req.body;
    const deal = await Deal.findById(req.params.id);
    if (!deal) return res.status(404).json({ success: false, message: 'Deal not found' });
    if (String(deal.retailerId) !== req.user.id) return res.status(403).json({ success: false, message: 'Only retailer can update the offer' });
    if (deal.status === 'confirmed' || deal.status === 'rejected') {
      return res.status(400).json({ success: false, message: 'Cannot renegotiate a finalised deal' });
    }

    const newQty = Math.max(1, parseInt(quantity) || deal.quantity);
    const newPrice = parseFloat(offeredPrice) || deal.offeredPrice;
    const diff = newQty - deal.quantity;

    if (diff !== 0) {
      const product = await Product.findById(deal.productId);
      if (product) {
        const available = (product.stock || 0) - (product.reservedStock || 0);
        if (diff > 0 && available < diff) {
          return res.status(400).json({ success: false, message: `Only ${available} additional units available` });
        }
        product.reservedStock = Math.max(0, (product.reservedStock || 0) + diff);
        await product.save();
      }
    }

    deal.quantity = newQty;
    deal.offeredPrice = newPrice;
    deal.status = 'pending'; // Reset to pending on re-negotiation
    await deal.save();

    // System message in chat
    const sysMsg = new Message({
      senderId: deal.retailerId,
      receiverId: deal.wholesalerId,
      type: 'system',
      message: `Retailer updated offer: ${newQty} units at ₹${newPrice}/unit (Total: ₹${(newQty * newPrice).toLocaleString('en-IN')})`
    });
    await sysMsg.save();

    // Updated deal message
    const dealMsg = new Message({
      senderId: deal.retailerId,
      receiverId: deal.wholesalerId,
      type: 'deal',
      message: '',
      productData: buildDealMsgData(deal)
    });
    await dealMsg.save();

    const io = req.app.get('io');
    const onlineUsers = req.app.get('onlineUsers');
    const payload = { sysMsg: sysMsg.toObject(), dealMsg: dealMsg.toObject(), deal: deal.toObject() };
    if (onlineUsers.has(String(deal.wholesalerId))) io.to(onlineUsers.get(String(deal.wholesalerId))).emit('deal_updated', payload);
    if (onlineUsers.has(req.user.id)) io.to(onlineUsers.get(req.user.id)).emit('deal_updated', payload);

    res.json({ success: true, deal, sysMsg, dealMsg });
  } catch (err) {
    console.error('Deal update error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// Change deal status (accept / reject / confirm / cancel)
router.patch('/deals/:id/status', authMiddleware, requireEmailVerified, async (req, res) => {
  try {
    const { status } = req.body;
    const deal = await Deal.findById(req.params.id);
    if (!deal) return res.status(404).json({ success: false, message: 'Deal not found' });
    if (deal.status === 'confirmed' || deal.status === 'rejected') {
      return res.status(400).json({ success: false, message: 'Deal is already finalised' });
    }

    const product = await Product.findById(deal.productId);
    const userId = req.user.id;

    if (status === 'wholesaler_accepted' && userId === String(deal.wholesalerId)) {
      deal.status = 'wholesaler_accepted';
    } else if (status === 'rejected' && (userId === String(deal.wholesalerId) || userId === String(deal.retailerId))) {
      deal.status = 'rejected';
      if (product) {
        product.reservedStock = Math.max(0, (product.reservedStock || 0) - deal.quantity);
        await product.save();
      }
    } else if (status === 'confirmed' && userId === String(deal.retailerId)) {
      deal.status = 'confirmed';
      if (product) {
        product.stock = Math.max(0, (product.stock || 0) - deal.quantity);
        product.reservedStock = Math.max(0, (product.reservedStock || 0) - deal.quantity);
        product.soldCount = (product.soldCount || 0) + deal.quantity;
        await product.save();
      }
    } else {
      return res.status(403).json({ success: false, message: 'Unauthorized action on deal' });
    }

    await deal.save();

    const statusLabels = { wholesaler_accepted: 'accepted', rejected: 'rejected', confirmed: 'confirmed' };
    const actor = userId === String(deal.wholesalerId) ? 'Wholesaler' : 'Retailer';
    let msgText = `${actor} ${statusLabels[status]} the deal`;
    if (status === 'rejected' && userId === String(deal.retailerId)) msgText = 'Retailer cancelled the deal';

    const otherId = userId === String(deal.retailerId) ? deal.wholesalerId : deal.retailerId;
    const sysMsg = new Message({
      senderId: userId,
      receiverId: otherId,
      type: 'system',
      message: msgText
    });
    await sysMsg.save();

    // Also save an updated deal card message (latest status)
    const dealMsg = new Message({
      senderId: deal.retailerId,
      receiverId: deal.wholesalerId,
      type: 'deal',
      message: '',
      productData: buildDealMsgData(deal)
    });
    await dealMsg.save();

    const io = req.app.get('io');
    const onlineUsers = req.app.get('onlineUsers');
    const payload = { sysMsg: sysMsg.toObject(), dealMsg: dealMsg.toObject(), deal: deal.toObject() };
    [String(deal.retailerId), String(deal.wholesalerId)].forEach(uid => {
      if (onlineUsers.has(uid)) io.to(onlineUsers.get(uid)).emit('deal_status_changed', payload);
    });

    res.json({ success: true, deal, sysMsg, dealMsg });
  } catch (err) {
    console.error('Deal status error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/reviews', authMiddleware, async (req, res) => {
  try {
    const { wholesalerId, dealId, rating, reviewText } = req.body;
    const existingReview = await Review.findOne({ retailerId: req.user.id, dealId });
    if (existingReview) return res.status(400).json({ success: false, message: 'Review already submitted for this deal' });
    const deal = await Deal.findOne({ _id: dealId, retailerId: req.user.id, wholesalerId, status: 'confirmed' });
    if (!deal) return res.status(400).json({ success: false, message: 'You can only rate after a confirmed deal' });
    const review = new Review({ retailerId: req.user.id, wholesalerId, dealId, rating, reviewText });
    await review.save();
    res.json({ success: true, review });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/wholesalers/:id/rating', async (req, res) => {
  try {
    const reviews = await Review.find({ wholesalerId: req.params.id }).populate('retailerId', 'name businessName');
    const avg = reviews.length > 0 ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
    res.json({ success: true, averageRating: avg, reviewCount: reviews.length, reviews });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---------- AI & ML ROUTES ----------

// 1. AI Chatbot (Floating Widget Context)
router.post('/ai/chat', authMiddleware, async (req, res) => {
  try {
    const { message, history } = req.body;
    
    // Fetch full user for role and context
    const fullUser = await User.findById(req.user.id);
    const role = fullUser.role; // 'retailer' or 'wholesaler'
    const name = fullUser.name;

    let tools = [];
    if (role === 'retailer') {
      tools = [
        {
          type: "function",
          function: {
            name: "smart_product_search",
            description: "Search for available products by name, category, maximum price, or location.",
            parameters: {
              type: "object",
              properties: {
                query: { type: "string", description: "Product name or search keyword." },
                category: { type: "string", description: "Category of product" },
                maxPrice: { type: "number", description: "Maximum price of the product" },
                location: { type: "string", description: "City or region of the wholesaler" }
              }
            }
          }
        },
        {
          type: "function",
          function: {
            name: "explore_wholesaler",
            description: "Get a list of registered wholesalers or explore a specific wholesaler's profile",
            parameters: {
              type: "object",
              properties: {
                name: { type: "string", description: "Optional name to search for a specific wholesaler" }
              }
            }
          }
        },
        {
          type: "function",
          function: {
            name: "send_inquiry",
            description: "Send an inquiry message to a specific wholesaler about their products.",
            parameters: {
              type: "object",
              properties: {
                wholesalerId: { type: "string", description: "The ID of the wholesaler" },
                messageText: { type: "string", description: "The message body" },
                productName: { type: "string", description: "Optional product name relating to this inquiry" }
              },
              required: ["wholesalerId", "messageText"]
            }
          }
        },
        {
          type: "function",
          function: {
            name: "get_inquiries",
            description: "Get a list of recent messages and inquiries sent by this retailer",
            parameters: { type: "object", properties: {} }
          }
        }
      ];
    } else if (role === 'wholesaler') {
      tools = [
        {
          type: "function",
          function: {
            name: "get_my_products",
            description: "Get the full list of the wholesaler's own products with stock, price, category, and sales data. Use this whenever a wholesaler asks about their inventory, products, or stock.",
            parameters: {
              type: "object",
              properties: {
                filterLowStock: { type: "boolean", description: "Set to true to only return products with low stock (<=10)." }
              }
            }
          }
        },
        {
          type: "function",
          function: {
            name: "update_product_data",
            description: "Update the stock count or price of a specific product the wholesaler owns.",
            parameters: {
              type: "object",
              properties: {
                productName: { type: "string", description: "Name of the product to update" },
                newStock: { type: "number", description: "New stock amount to set" },
                newPrice: { type: "number", description: "New price per unit to set" }
              },
              required: ["productName"]
            }
          }
        },
        {
          type: "function",
          function: {
            name: "get_monthly_analytics",
            description: "Get business analytics including total sales count, low stock items count, and top-selling product.",
            parameters: {
              type: "object",
              properties: {}
            }
          }
        },
        {
          type: "function",
          function: {
            name: "send_broadcast",
            description: "Send an announcement or discount message to all connected retailers.",
            parameters: {
              type: "object",
              properties: {
                announcementMessage: { type: "string", description: "The message to broadcast to retailers" }
              },
              required: ["announcementMessage"]
            }
          }
        }
      ];
    }

    const systemPrompt = `You are the NexTrade Virtual Assistant. You are talking to ${name}, a ${role}. 
    Use simple HTML (like <b>bold</b>, <ul><li>items</li></ul>, <br>) for formatting. Do NOT use markdown.
    If the user asks to send an inquiry or broadcast, or wants to update a product, use your tools to perform the action and tell the user you did it.
    If drafting a message, draft it nicely, and if they approve, use the appropriate tool to send it.`;

    let messages = [
      { role: "system", content: systemPrompt }
    ];

    if (history) {
      history.forEach(msg => {
        messages.push({
          role: msg.sender === 'user' ? 'user' : 'assistant',
          content: msg.text
        });
      });
    }

    messages.push({ role: "user", content: message });

    // Groq Tool Calling Loop
    let conversationFinished = false;
    let finalReply = "";

    while (!conversationFinished) {
      const response = await groq.chat.completions.create({
        model: "llama-3.3-70b-versatile",
        messages: messages,
        tools: tools.length > 0 ? tools : undefined,
        tool_choice: "auto",
      });

      const responseMessage = response.choices[0].message;
      messages.push(responseMessage);

      if (responseMessage.tool_calls) {
        for (const toolCall of responseMessage.tool_calls) {
          const functionName = toolCall.function.name;
          const functionArgs = JSON.parse(toolCall.function.arguments);
          let toolResult;

          try {
            if (functionName === "smart_product_search") {
              const { query, category, maxPrice, location } = functionArgs;
              let filter = { stock: { $gt: 0 } };
              if (query) filter.name = new RegExp(query, 'i');
              if (category) filter.category = new RegExp(category, 'i');
              if (maxPrice) filter.pricePerUnit = { $lte: maxPrice };
              
              let products = await Product.find(filter).populate('wholesalerId', 'city state name email').limit(20);
              
              if (location) {
                const locRegex = new RegExp(location, 'i');
                products = products.filter(p => p.wholesalerId && ((p.wholesalerId.city && locRegex.test(p.wholesalerId.city)) || (p.wholesalerId.state && locRegex.test(p.wholesalerId.state))));
              }
              products = products.slice(0, 5);
              toolResult = products.map(p => ({ 
                name: p.name, 
                price: p.pricePerUnit, 
                category: p.category,
                wholesalerName: p.wholesalerId?.name,
                wholesalerId: p.wholesalerId?._id,
                location: p.wholesalerId ? `${p.wholesalerId.city}, ${p.wholesalerId.state}` : 'Unknown'
              }));

            } else if (functionName === "explore_wholesaler") {
              const { name: searchName } = functionArgs;
              let ws;
              if (searchName) {
                ws = await User.find({ role: 'wholesaler', name: new RegExp(searchName, 'i') }).limit(3);
                toolResult = await Promise.all(ws.map(async w => {
                  const topProducts = await Product.find({ wholesalerId: w._id }).sort({soldCount: -1}).limit(3);
                  return { id: w._id, name: w.name, businessName: w.businessName, location: `${w.city}, ${w.state}`, products: topProducts.map(p=>p.name).join(', ') };
                }));
              } else {
                ws = await User.find({ role: 'wholesaler' }).limit(5);
                toolResult = ws.map(w => ({ id: w._id, name: w.name, businessName: w.businessName }));
              }

            } else if (functionName === "send_inquiry") {
              const { wholesalerId, messageText, productName } = functionArgs;
              const newMsg = new Message({
                senderId: fullUser._id,
                receiverId: wholesalerId,
                productName: productName || 'General Inquiry',
                message: messageText
              });
              await newMsg.save();
              toolResult = { success: true, info: "Inquiry message successfully sent to wholesaler." };

            } else if (functionName === "get_inquiries") {
              const msgs = await Message.find({ senderId: fullUser._id }).sort({createdAt:-1}).limit(5);
              toolResult = msgs.map(m => ({ to: m.receiverId, message: m.message, date: m.createdAt, product: m.productName }));

            } else if (functionName === "get_my_products") {
              const { filterLowStock } = functionArgs;
              let filter = { wholesalerId: fullUser._id };
              if (filterLowStock) filter.stock = { $lte: 10 };
              const myProducts = await Product.find(filter).sort({ createdAt: -1 });
              toolResult = myProducts.map(p => ({
                name: p.name,
                category: p.category || 'Uncategorized',
                stock: p.stock,
                pricePerUnit: p.pricePerUnit,
                unit: p.unit,
                soldCount: p.soldCount || 0,
                stockStatus: p.stock === 0 ? 'OUT OF STOCK' : p.stock <= 10 ? 'LOW STOCK' : 'In Stock'
              }));

            } else if (functionName === "update_product_data") {
              const { productName, newStock, newPrice } = functionArgs;
              const updateObj = {};
              if (newStock !== undefined) updateObj.stock = newStock;
              if (newPrice !== undefined) updateObj.pricePerUnit = newPrice;
              
              const updated = await Product.findOneAndUpdate(
                { wholesalerId: fullUser._id, name: new RegExp(productName, 'i') },
                { $set: updateObj },
                { new: true }
              );
              if (!updated) toolResult = { error: "Product not found or you don't own it." };
              else toolResult = { success: true, updatedProduct: { name: updated.name, stock: updated.stock, price: updated.pricePerUnit } };

            } else if (functionName === "get_monthly_analytics") {
              const products = await Product.find({ wholesalerId: fullUser._id });
              let lowStock = 0, totalSales = 0;
              let topProduct = null;
              products.forEach(p => {
                if (p.stock < 10) lowStock++;
                totalSales += (p.soldCount || 0);
                if (!topProduct || p.soldCount > topProduct.soldCount) topProduct = { name: p.name, soldCount: p.soldCount };
              });
              toolResult = { totalSales, lowStockItemsCount: lowStock, topSellingProduct: topProduct };

            } else if (functionName === "send_broadcast") {
              const { announcementMessage } = functionArgs;
              const prevMsgs = await Message.find({ receiverId: fullUser._id });
              const uniqueRetailers = [...new Set(prevMsgs.map(m => m.senderId))];
              
              if (uniqueRetailers.length === 0) {
                toolResult = { info: "No connected retailers to broadcast to." };
              } else {
                const broadcastPromises = uniqueRetailers.map(rId => {
                  return new Message({
                    senderId: fullUser._id,
                    receiverId: rId,
                    productName: 'Broadcast Announcement',
                    message: announcementMessage
                  }).save();
                });
                await Promise.all(broadcastPromises);
                toolResult = { success: true, info: `Broadcast sent to ${uniqueRetailers.length} retailers.` };
              }
            }
          } catch (e) {
            console.error('Tool error:', e);
            toolResult = { error: "Database query or logic failed: " + e.message };
          }

          messages.push({
            tool_call_id: toolCall.id,
            role: "tool",
            name: functionName,
            content: JSON.stringify(toolResult),
          });
        }
      } else {
        finalReply = responseMessage.content;
        conversationFinished = true;
      }
    }

    res.json({ success: true, reply: finalReply });
    
  } catch (error) {
    console.error('AI Chat Error:', error);
    if (error.status === 429) {
      return res.json({ 
        success: true, 
        reply: "I am receiving too many requests right now and taking a short breather. Please wait a few seconds and try again!" 
      });
    }
    res.status(500).json({ success: false, message: 'AI Assistant is currently unavailable' });
  }
});

// 3. Recommendation Engine API
router.get('/recommendations', authMiddleware, async (req, res) => {
  try {
    const orders = await Order.find({ email: req.user.email }).limit(20);
    const orderProductNames = orders.map(o => o.productName);
    
    let recommendations = [];
    if (orderProductNames.length > 0) {
      const boughtProducts = await Product.find({ name: { $in: orderProductNames } });
      const favoriteCategories = [...new Set(boughtProducts.map(p => p.category).filter(c => c))];
      
      recommendations = await Product.find({
        category: { $in: favoriteCategories },
        name: { $nin: orderProductNames },
        stock: { $gt: 0 }
      }).sort({ soldCount: -1 }).limit(5);
    } 

    if (recommendations.length < 5) {
      const needed = 5 - recommendations.length;
      const bestSellers = await Product.find({
        name: { $nin: [...orderProductNames, ...recommendations.map(r=>r.name)] },
        stock: { $gt: 0 }
      }).sort({ soldCount: -1 }).limit(needed);
      
      recommendations = [...recommendations, ...bestSellers];
    }
    res.json({ success: true, recommendations });
  } catch(error) {
    console.error('Recommendations error:', error);
    res.status(500).json({ success: false });
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
  cors: { origin: "*" },
  maxHttpBufferSize: 1e7 // Increase to 10MB to support large media
});

// Use a Map to track real-time online status
const onlineUsers = new Map();

// Expose to routes
app.set('io', io);
app.set('onlineUsers', onlineUsers);

// SOCKET CONNECTION
io.on("connection", (socket) => {
  let currentUserId = null;

  socket.on("register", (userId) => {
    currentUserId = userId;
    onlineUsers.set(userId, socket.id);
    // Broadcast that this user is now online
    io.emit("status_update", { userId, status: "online" });
  });

  socket.on("get_online_status", () => {
    socket.emit("online_users_list", Array.from(onlineUsers.keys()));
  });

  socket.on("send_message", async (data) => {
    const { senderId, receiverId, message, productName, productId, type } = data;

    let productData = null;
    if (productId) {
      try {
        const prod = await Product.findById(productId);
        if (prod) {
          productData = {
            id: prod._id,
            name: prod.name,
            price: prod.pricePerUnit || prod.price || 0,
            image: prod.image
          };
        }
      } catch(e) {}
    }

    const newMsg = new Message({
      senderId,
      receiverId,
      message,
      productName,
      productData,
      type: type || 'text',
      status: onlineUsers.has(receiverId) ? 'delivered' : 'sent'
    });

    await newMsg.save();

    // Send to receiver
    if (onlineUsers.has(receiverId)) {
      io.to(onlineUsers.get(receiverId)).emit("receive_message", newMsg);
    }
    // Send back to sender
    socket.emit("receive_message", newMsg);
  });

  socket.on("message_read", async (data) => {
    const { messageId, senderId } = data;
    await Message.findByIdAndUpdate(messageId, { status: 'read' });
    if (onlineUsers.has(senderId)) {
      io.to(onlineUsers.get(senderId)).emit("message_status_update", { messageId, status: 'read' });
    }
  });

  socket.on("typing", (data) => {
    if (onlineUsers.has(data.receiverId)) {
      io.to(onlineUsers.get(data.receiverId)).emit("typing", data);
    }
  });

  socket.on("disconnect", () => {
    if (currentUserId) {
      onlineUsers.delete(currentUserId);
      io.emit("status_update", { userId: currentUserId, status: "offline" });
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

