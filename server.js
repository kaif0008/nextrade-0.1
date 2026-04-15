const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require('nodemailer');
const dns = require('dns');

// Force IPv4 as default to avoid ENETUNREACH (IPv6) errors on cloud providers like Render
if (typeof dns.setDefaultResultOrder === 'function') {
  dns.setDefaultResultOrder('ipv4first');
}

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');

// ================= CLOUDINARY CONFIG =================
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();

const http = require('http');
const { Server } = require('socket.io');

// ================= AI CONFIGURATION (GROQ) =================
const Groq = require('groq-sdk');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ================= EMAIL TRANSPORTER (NODEMAILER) =================
// Custom lookup to strictly force IPv4
const ipv4Lookup = (hostname, options, callback) => {
  return dns.lookup(hostname, { family: 4 }, callback);
};

// const emailTransporter = nodemailer.createTransport({
//   host: 'smtp.gmail.com',
//   port: 465,
//   secure: true,
//   lookup: ipv4Lookup, // FORCE IPv4 at the DNS level
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS
//   },
//   tls: {
//     rejectUnauthorized: false,
//     minVersion: 'TLSv1.2'
//   },
//   connectionTimeout: 20000, 
//   greetingTimeout: 20000,
//   socketTimeout: 30000
// });
const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify connection on startup
emailTransporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email Transporter Error:', error.message);
    if (error.message.includes('Invalid login')) {
      console.error('👉 TIP: Check your EMAIL_USER and ensure EMAIL_PASS is a 16-character App Password, not your regular password.');
    }
  } else {
    console.log('✅ Email Transporter is ready to send messages');
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
  
  try {
    return await emailTransporter.sendMail(mailOptions);
  } catch (err) {
    console.error('❌ Nodemailer Error Detail:', {
      code: err.code,
      command: err.command,
      response: err.response,
      stack: err.stack
    });
    throw err; 
  }
}

// ================= CONSTANTS =================
const SALT_ROUNDS = 10;
const DEFAULT_PORT = 5010;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("FATAL ERROR: JWT_SECRET is not defined in .env");
  process.exit(1);
}

// ================= DB CONNECTION =================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/nextrade')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// ================= MIDDLEWARE =================
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for local development and to allow external scripts/styles used in the app
}));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { success: false, message: "Too many requests, please try again later." }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Strict limit for auth/OTP
  message: { success: false, message: "Too many attempts, please wait 15 minutes." }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ================= STORAGE CONFIG (CLOUDINARY) =================
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'nextrade_uploads',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 1000, height: 1000, crop: 'limit' }]
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit for cloud
});

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
  // Business Categories (for wholesalers)
  categories: { type: [String], default: [] },
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

userSchema.index({ name: 1 });
userSchema.index({ role: 1 });

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
  name: { type: String, required: true },
  pricePerUnit: { type: Number, required: true },
  unit: { type: String, required: true },
  category: { type: String, required: true },
  image: { type: String, required: true },
  description: { type: String, required: true },
  stock: { type: Number, required: true },
  reservedStock: { type: Number, default: 0 },
  soldCount: { type: Number, default: 0 },
  moq: { type: Number, required: true },
  wholesalerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

productSchema.index({ name: 1 });
productSchema.index({ category: 1 });
productSchema.index({ wholesalerId: 1 });

const Product = mongoose.model('Product', productSchema);

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
  moq: { type: Number, default: 1 },
  stock: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'wholesaler_updated', 'wholesaler_accepted', 'confirmed', 'rejected'], default: 'pending' },
  requirementId: { type: mongoose.Schema.Types.ObjectId, ref: 'Requirement' },
}, { timestamps: true });

const Deal = mongoose.model('Deal', dealSchema);

// Requirement Schema
const requirementSchema = new mongoose.Schema({
  retailerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  productName: String,
  quantity: Number,
  expectedPrice: Number,
  unit: { type: String, default: 'piece' },
  description: String,
  categories: { type: [String], default: [] },
  status: { type: String, enum: ['open', 'closed'], default: 'open' },
}, { timestamps: true });

const Requirement = mongoose.model('Requirement', requirementSchema);

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

// Contact Message
const contactMessageSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['new', 'read', 'replied'], default: 'new' }
}, { timestamps: true });

const ContactMessage = mongoose.model('ContactMessage', contactMessageSchema);


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
router.post('/signup', authLimiter, upload.single('photo'), async (req, res) => {
  try {
    const { name, email, password, role, gstNumber } = req.body;
    const photoUrl = req.file ? req.file.path : null;

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
      gstNumber,
      photoUrl
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

router.post('/auth/send-otp', authMiddleware, authLimiter, async (req, res) => {
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

// ---------- FORGOT PASSWORD FLOW ----------

router.post('/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email is required' });

    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if user exists or not, but in some B2B contexts it's fine.
      // However, usually we say "If an account exists, an OTP has been sent."
      // For this demo, we'll be explicit for better UX.
      return res.status(404).json({ success: false, message: 'No account found with this email' });
    }

    const otp = generateOTP();
    const hashedOtp = await bcrypt.hash(otp, 8);
    const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes for reset

    user.otpCode = hashedOtp;
    user.otpExpiry = expiry;
    user.otpAttempts = 0;
    user.otpRequestedAt = new Date();
    await user.save();

    await sendOTPEmail(user.email, otp, user.name);

    res.json({ success: true, message: `Password reset OTP sent to ${user.email}` });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ success: false, message: 'Failed to send reset OTP' });
  }
});

router.post('/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    // Check expiry
    if (!user.otpExpiry || new Date() > new Date(user.otpExpiry)) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
    }

    // Check OTP
    const isMatch = await bcrypt.compare(otp.trim(), user.otpCode);
    if (!isMatch) {
      user.otpAttempts = (user.otpAttempts || 0) + 1;
      await user.save();
      return res.status(400).json({ success: false, message: 'Incorrect OTP' });
    }

    // Success — update password and clear OTP
    user.password = newPassword; // This will be hashed by the pre-save hook
    user.otpCode = undefined;
    user.otpExpiry = undefined;
    user.otpAttempts = 0;
    user.otpRequestedAt = undefined;

    await user.save();

    res.json({ success: true, message: 'Password reset successfully! You can now login.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ success: false, message: 'Password reset failed' });
  }
});

router.post('/login', authLimiter, async (req, res) => {
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
  'categories',
  'houseNo', 'street', 'block', 'district', 'city',
  'state', 'pincode', 'country', 'shopName', 'shopAddress'
];

router.post("/update-profile", authMiddleware, upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'businessPhotos', maxCount: 5 }
]), async (req, res) => {
  try {
    const safeUpdate = {};

    if (req.files) {
      if (req.files.photo) {
        safeUpdate.photoUrl = req.files.photo[0].path;
      }
      
      // Handle Business Gallery Merging
      let existingPhotos = [];
      if (req.body.existingBusinessPhotos) {
        existingPhotos = Array.isArray(req.body.existingBusinessPhotos) 
          ? req.body.existingBusinessPhotos 
          : [req.body.existingBusinessPhotos];
      }

      let newPhotos = [];
      if (req.files.businessPhotos) {
        newPhotos = req.files.businessPhotos.map(f => f.path);
      }

      // If either existing or new photos are present, update the gallery
      // Note: If both are empty, it means the gallery was cleared (if it was sent)
      if (req.body.existingBusinessPhotos !== undefined || (req.files && req.files.businessPhotos)) {
        safeUpdate.businessPhotos = [...existingPhotos, ...newPhotos].slice(0, 5);
      }
    }

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


// Create Product
router.post('/products', authMiddleware, requireEmailVerified, upload.single('image'), async (req, res) => {
  try {
    if (req.user.role !== 'wholesaler') {
      return res.status(403).json({ success: false, message: 'Only wholesalers can add products' });
    }

    const { name, pricePerUnit, unit, category, description, stock, moq } = req.body;

    if (!name || !pricePerUnit || !unit || !category || !description || stock === undefined || moq === undefined) {
      return res.status(400).json({ success: false, message: 'All text fields are required' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Product image is required' });
    }

    const product = new Product({
      ...req.body,
      image: req.file.path,
      wholesalerId: req.user.id
    });

    await product.save();
    res.status(201).json({ success: true, product });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// AI code removed as per user request

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

router.put('/products/:id', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const updateData = { ...req.body };
    if (req.file) {
      updateData.image = req.file.path;
    }

    const product = await Product.findOneAndUpdate(
      { _id: req.params.id, wholesalerId: req.user.id },
      updateData,
      { new: true, runValidators: true }
    );

    if (!product) {
      return res.status(403).json({ success: false, message: 'Product not found or unauthorized' });
    }

    res.json({ success: true, product });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ---------- ORDERS ----------
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
    const userId = String(req.user.id);

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

    conversations.sort((a, b) => {
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
    moq: deal.moq || 1,
    stock: deal.stock || 0,
    status: deal.status
  };
}

// Get all deals for the logged-in user
router.get('/deals', authMiddleware, async (req, res) => {
  try {
    const deals = await Deal.find({
      $or: [{ retailerId: req.user.id }, { wholesalerId: req.user.id }]
    })
      .populate('retailerId', 'name mobileNumber')
      .populate('wholesalerId', 'name businessName rating')
      .sort({ createdAt: -1 });

    res.json({ success: true, deals });
  } catch (err) {
    console.error('Fetch deals error:', err);
    res.status(500).json({ success: false, message: 'Server error fetching deals' });
  }
});

router.post('/deals/create', authMiddleware, requireEmailVerified, async (req, res) => {
  try {
    const { wholesalerId, productId, quantity, offeredPrice, requirementId, retailerId } = req.body;

    // Role-aware ID assignment
    const isWholesaler = req.user.role === 'wholesaler';
    const finalRetailerId = isWholesaler ? retailerId : req.user.id;
    const finalWholesalerId = isWholesaler ? req.user.id : (wholesalerId || req.body.wholesalerId);

    if (!finalRetailerId || !finalWholesalerId || !productId) {
      return res.status(400).json({ success: false, message: 'retailerId, wholesalerId and productId are required' });
    }

    const reqQty = Math.max(1, parseInt(quantity) || 1);
    const reqPrice = parseFloat(offeredPrice) || 0;

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });

    // Inventory check
    const reserved = product.reservedStock || 0;
    const currentStock = product.stock || 0;
    if (currentStock - reserved < reqQty) {
      return res.status(400).json({ success: false, message: `Only ${currentStock - reserved} units available` });
    }

    product.reservedStock = reserved + reqQty;
    await product.save();

    const deal = new Deal({
      retailerId: finalRetailerId,
      wholesalerId: finalWholesalerId,
      productId,
      productName: product.name,
      productImage: product.image || '',
      listPrice: product.pricePerUnit || 0,
      quantity: reqQty,
      offeredPrice: reqPrice,
      moq: product.moq || 1,
      stock: product.stock || 0,
      status: isWholesaler ? 'wholesaler_updated' : 'pending',
      requirementId: requirementId || null
    });
    await deal.save();

    const receiverId = isWholesaler ? finalRetailerId : finalWholesalerId;
    const msg = new Message({
      senderId: req.user.id,
      receiverId: receiverId,
      type: 'deal',
      message: isWholesaler ? 'Wholesaler sent an offer based on your requirement.' : '',
      productData: buildDealMsgData(deal)
    });
    await msg.save();

    // Emit real-time socket events
    const io = req.app.get('io');
    const onlineUsers = req.app.get('onlineUsers');
    const dealEvent = { msg: msg.toObject(), deal: deal.toObject() };

    if (onlineUsers.has(String(receiverId))) io.to(onlineUsers.get(String(receiverId))).emit('deal_created', dealEvent);
    if (onlineUsers.has(String(req.user.id))) io.to(onlineUsers.get(String(req.user.id))).emit('deal_created', dealEvent);

    res.json({ success: true, deal, message: msg });
  } catch (err) {
    console.error('Deal create error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// Update deal offer (negotiation)
router.patch('/deals/:id/update', authMiddleware, async (req, res) => {
  try {
    const { quantity, offeredPrice } = req.body;
    const deal = await Deal.findById(req.params.id);
    if (!deal) return res.status(404).json({ success: false, message: 'Deal not found' });

    const isRetailer = String(deal.retailerId) === req.user.id;
    const isWholesaler = String(deal.wholesalerId) === req.user.id;

    if (!isRetailer && !isWholesaler) {
      return res.status(403).json({ success: false, message: 'Unauthorized to update this deal' });
    }

    if (deal.status === 'confirmed' || deal.status === 'rejected') {
      return res.status(400).json({ success: false, message: 'Cannot renegotiate a finalised deal' });
    }

    const newQty = Math.max(1, parseInt(quantity) || deal.quantity);
    const newPrice = parseFloat(offeredPrice) || deal.offeredPrice;

    // Strict validation for retailers only
    if (isRetailer) {
      if (newQty < (deal.moq || 1)) {
        return res.status(400).json({ success: false, message: `Minimum order quantity is ${deal.moq || 1} units` });
      }
      const product = await Product.findById(deal.productId);
      if (product) {
        // Stock check: Retailer cannot exceed (product.stock + their current reservation)
        const maxAllowed = (product.stock || 0) + (deal.quantity || 0);
        if (newQty > maxAllowed) {
          return res.status(400).json({ success: false, message: `Only ${product.stock} units available` });
        }
      }
    }

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

    // Logic: If wholesaler updates, status becomes 'wholesaler_updated'
    // If retailer updates, status becomes 'pending'
    deal.status = isWholesaler ? 'wholesaler_updated' : 'pending';
    await deal.save();

    const actorLabel = isWholesaler ? 'Wholesaler' : 'Retailer';
    const receiverId = isWholesaler ? deal.retailerId : deal.wholesalerId;

    // System message in chat
    const sysMsg = new Message({
      senderId: req.user.id,
      receiverId: receiverId,
      type: 'system',
      message: `${actorLabel} updated offer: ${newQty} units at ₹${newPrice}/unit (Total: ₹${(newQty * newPrice).toLocaleString('en-IN')})`
    });
    await sysMsg.save();

    // Updated deal message
    const dealMsg = new Message({
      senderId: req.user.id,
      receiverId: receiverId,
      type: 'deal',
      message: '',
      productData: buildDealMsgData(deal)
    });
    await dealMsg.save();

    const io = req.app.get('io');
    const onlineUsers = req.app.get('onlineUsers');
    const payload = { sysMsg: sysMsg.toObject(), dealMsg: dealMsg.toObject(), deal: deal.toObject() };

    [deal.retailerId, deal.wholesalerId].forEach(uid => {
      if (onlineUsers.has(String(uid))) io.to(onlineUsers.get(String(uid))).emit('deal_updated', payload);
    });

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
    const isWholesaler = userId === String(deal.wholesalerId);
    const isRetailer = userId === String(deal.retailerId);

    let finalStatus = null;

    if (status === 'confirmed') {
      // Logic for finalizing: 
      // 1. Wholesaler confirms Retailer's offer (pending)
      // 2. Retailer confirms Wholesaler's offer (wholesaler_updated)
      // 3. Retailer confirms Wholesaler's acceptance (legacy wholesaler_accepted)
      if (isWholesaler && deal.status === 'pending') {
        finalStatus = 'confirmed';
      } else if (isRetailer && (deal.status === 'wholesaler_updated' || deal.status === 'wholesaler_accepted')) {
        finalStatus = 'confirmed';
      } else {
        return res.status(403).json({ success: false, message: 'Unauthorized to confirm at this stage' });
      }
    } else if (status === 'wholesaler_accepted' && isWholesaler && deal.status === 'pending') {
      // Legacy "Acceptance" flow
      finalStatus = 'wholesaler_accepted';
    } else if (status === 'rejected' && (isWholesaler || isRetailer)) {
      finalStatus = 'rejected';
    } else {
      return res.status(403).json({ success: false, message: 'Unauthorized action on deal' });
    }

    deal.status = finalStatus;

    // Inventory adjustments
    if (finalStatus === 'confirmed') {
      if (product) {
        product.stock = Math.max(0, (product.stock || 0) - deal.quantity);
        product.reservedStock = Math.max(0, (product.reservedStock || 0) - deal.quantity);
        product.soldCount = (product.soldCount || 0) + deal.quantity;
        await product.save();
      }
      // If linked to a requirement, close it
      if (deal.requirementId) {
        await Requirement.findByIdAndUpdate(deal.requirementId, { status: 'closed' });
      }
    } else if (finalStatus === 'rejected') {
      if (product) {
        product.reservedStock = Math.max(0, (product.reservedStock || 0) - deal.quantity);
        await product.save();
      }
    }

    await deal.save();

    const statusLabels = { wholesaler_accepted: 'accepted', rejected: 'rejected', confirmed: 'finalized/confirmed' };
    const actor = isWholesaler ? 'Wholesaler' : 'Retailer';
    let msgText = `${actor} ${statusLabels[deal.status] || deal.status} the deal`;
    if (deal.status === 'rejected' && isRetailer) msgText = 'Retailer cancelled the deal';

    const otherId = isRetailer ? deal.wholesalerId : deal.retailerId;
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

// ---------- REQUIREMENTS ----------

router.post('/requirements', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'retailer') {
      return res.status(403).json({ success: false, message: 'Only retailers can post requirements' });
    }
    const requirement = new Requirement({
      ...req.body,
      retailerId: req.user.id
    });
    await requirement.save();
    res.status(201).json({ success: true, requirement });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to post requirement' });
  }
});

router.get('/requirements', authMiddleware, async (req, res) => {
  try {
    const { category, minPrice, maxPrice, sortBy, order, search } = req.query;
    let filter = { status: 'open' };

    if (category) filter.categories = { $in: [category] };
    if (minPrice || maxPrice) {
      filter.expectedPrice = {};
      if (minPrice) filter.expectedPrice.$gte = parseFloat(minPrice);
      if (maxPrice) filter.expectedPrice.$lte = parseFloat(maxPrice);
    }
    if (search) {
      filter.productName = { $regex: search, $options: 'i' };
    }

    let sortObj = { createdAt: -1 };
    if (sortBy === 'price') {
      sortObj = { expectedPrice: order === 'desc' ? -1 : 1 };
    } else if (sortBy === 'date') {
      sortObj = { createdAt: order === 'asc' ? 1 : -1 };
    }

    const requirements = await Requirement.find(filter)
      .populate('retailerId', 'name businessName city district')
      .sort(sortObj);

    res.json({ success: true, requirements });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch requirements' });
  }
});

router.get('/requirements/my', authMiddleware, async (req, res) => {
  try {
    const requirements = await Requirement.find({ retailerId: req.user.id })
      .sort({ createdAt: -1 });
    res.json({ success: true, requirements });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch your requirements' });
  }
});

router.patch('/requirements/:id/close', authMiddleware, async (req, res) => {
  try {
    const requirement = await Requirement.findOneAndUpdate(
      { _id: req.params.id, retailerId: req.user.id },
      { status: 'closed' },
      { new: true }
    );
    if (!requirement) return res.status(404).json({ success: false, message: 'Requirement not found or unauthorized' });
    res.json({ success: true, requirement });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to close requirement' });
  }
});

router.patch('/requirements/:id', authMiddleware, async (req, res) => {
  try {
    const requirement = await Requirement.findOneAndUpdate(
      { _id: req.params.id, retailerId: req.user.id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!requirement) return res.status(404).json({ success: false, message: 'Requirement not found or unauthorized' });
    res.json({ success: true, requirement });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update requirement' });
  }
});

router.delete('/requirements/:id', authMiddleware, async (req, res) => {
  try {
    const requirement = await Requirement.findOneAndDelete({
      _id: req.params.id,
      retailerId: req.user.id
    });
    if (!requirement) return res.status(404).json({ success: false, message: 'Requirement not found or unauthorized' });
    res.json({ success: true, message: 'Requirement deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete requirement' });
  }
});

router.get('/messages/unread-count', authMiddleware, async (req, res) => {
  try {
    const userId = String(req.user.id);
    const count = await Message.countDocuments({
      receiverId: userId,
      status: { $ne: 'read' }
    });
    res.json({ success: true, count });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch unread count' });
  }
});

router.patch('/messages/read-all/:senderId', authMiddleware, async (req, res) => {
  try {
    const { senderId } = req.params;
    await Message.updateMany(
      { receiverId: req.user.id, senderId, status: { $ne: 'read' } },
      { status: 'read' }
    );
    res.json({ success: true, message: 'Messages marked as read' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update message status' });
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
    const { message: userMsg, history } = req.body;
    const msgLower = userMsg.toLowerCase();

    // TOOL GUARD: Only enable tools if message implies data inquiry
    const toolKeywords = ['search', 'find', 'product', 'deal', 'stock', 'inventory', 'requirement', 'price', 'update', 'status', 'analytics', 'moq', 'wholesaler', 'detail'];
    const useTools = toolKeywords.some(kw => msgLower.includes(kw));

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
            name: "search_products",
            description: "Search for available products by name or category.",
            parameters: {
              type: "object",
              properties: {
                query: { type: "string", description: "Product name or search keyword." },
                category: { type: "string", description: "Category of product" }
              }
            }
          }
        },
        {
          type: "function",
          function: {
            name: "explore_wholesalers",
            description: "Find wholesalers by name, category (industry), or location (city/state).",
            parameters: {
              type: "object",
              properties: {
                name: { type: "string", description: "Name of the wholesaler" },
                category: { type: "string", description: "Industry or category (e.g. Fashion, Electronics)" },
                location: { type: "string", description: "City or state" }
              }
            }
          }
        },
        {
          type: "function",
          function: {
            name: "get_product_details",
            description: "Get full details including description, MCQ, and current stock for a specific product name.",
            parameters: {
              type: "object",
              properties: {
                productName: { type: "string", description: "The exact or partial name of the product" }
              },
              required: ["productName"]
            }
          }
        },
        {
          type: "function",
          function: {
            name: "get_my_deals",
            description: "Retrieve your negotiation deals.",
            parameters: { type: "object", properties: {} }
          }
        },
        {
          type: "function",
          function: {
            name: "check_requirements",
            description: "List your marketplace buying requirements.",
            parameters: { type: "object", properties: {} }
          }
        }
      ];
    } else if (role === 'wholesaler') {
      tools = [
        {
          type: "function",
          function: {
            name: "get_my_inventory",
            description: "List your products with stock and price.",
            parameters: { type: "object", properties: {} }
          }
        },
        {
          type: "function",
          function: {
            name: "update_product_details",
            description: "Update a product's stock, price, or MOQ.",
            parameters: {
              type: "object",
              properties: {
                productName: { type: "string", description: "Name of the product" },
                stock: { type: "number", description: "New stock quantity" },
                price: { type: "number", description: "New price per unit" },
                moq: { type: "number", description: "New minimum order quantity" }
              },
              required: ["productName"]
            }
          }
        },
        {
          type: "function",
          function: {
            name: "view_received_deals",
            description: "View incoming offers from retailers.",
            parameters: { type: "object", properties: {} }
          }
        },
        {
          type: "function",
          function: {
            name: "discover_market_requirements",
  description: "Find buying requirements from retailers",
  parameters: {
    type: "object",
    properties: {
      category: {
        type: "string",
        description: "Optional category filter"
      }
    }
  }
          }
        },
        {
          type: "function",
          function: {
            name: "get_business_analytics",
            description: "Overview of sales and top products.",
            parameters: { type: "object", properties: {} }
          }
        }
      ];
    }

    const systemPrompt = `You are Nexa, the professional AI Assistant for NexTrade.
    User's name: ${name}
    User's role: ${role}
    
    STRICT OPERATIONAL RULES:
    1. CONVERSATIONAL: For greetings or gratitude, respond naturally as Nexa. Do NOT use tools.
    2. TOOL USAGE: ONLY call a tool if the user's request requires fetching or updating real-time data.
    3. VALID JSON ONLY: When using a tool, you must generate a structured tool call. NEVER output XML tags like <function> or any other text around the tool call.
    4. HTML FORMATTING: Always use HTML (<b>, <ul>, <li>, <table border="1">) for data presentation.
    5. NO HALLUCINATION: If a tool returns no data, inform the user politely. Do not invent products or deals.
    6. LIMITED ACCESS: You can view deal statuses but cannot accept/reject deals.`;

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

    messages.push({ role: "user", content: userMsg });

    // Groq Tool Calling Loop
    let conversationFinished = false;
    let finalReply = "";
    let iterations = 0;
    const MAX_ITERATIONS = 4; // Safety limit

    while (!conversationFinished && iterations < MAX_ITERATIONS) {
      iterations++;
      const response = await groq.chat.completions.create({
        model: "llama-3.1-8b-instant",
        messages: messages,
        tools: useTools ? tools : undefined,
        tool_choice: useTools ? "auto" : undefined,
        temperature: 0,
      });

      const responseMessage = response.choices[0].message;
      messages.push(responseMessage);

      if (responseMessage.tool_calls) {
        for (const toolCall of responseMessage.tool_calls) {
          const functionName = toolCall.function.name;
          let functionArgs = {};
          try {
            functionArgs = toolCall.function.arguments
              ? JSON.parse(toolCall.function.arguments)
              : {};
          } catch (e) {
            console.warn("Invalid JSON arguments, using empty object");
            functionArgs = {};
          }
          let toolResult;

          try {
            if (functionName === "search_products") {
              const { query, category } = functionArgs;
              let filter = { stock: { $gt: 0 } };
              if (query) filter.name = new RegExp(query, 'i');
              if (category) filter.category = new RegExp(category, 'i');

              const products = await Product.find(filter).populate('wholesalerId', 'businessName city').limit(15);
              toolResult = products.map(p => ({
                name: p.name,
                price: `₹${p.pricePerUnit}/${p.unit}`,
                moq: p.moq,
                stock: p.stock,
                category: p.category,
                wholesaler: p.wholesalerId?.businessName || 'Unknown',
                location: p.wholesalerId ? p.wholesalerId.city : 'N/A'
              }));

            } else if (functionName === "explore_wholesalers") {
              const { name: searchName, category, location } = functionArgs;
              let filter = { role: 'wholesaler' };
              if (searchName) filter.name = new RegExp(searchName, 'i');
              if (category) filter.categories = { $in: [new RegExp(category, 'i')] };
              if (location) {
                filter.$or = [
                  { city: new RegExp(location, 'i') },
                  { state: new RegExp(location, 'i') }
                ];
              }
              const ws = await User.find(filter).limit(15);
              toolResult = ws.map(w => ({
                name: w.name,
                business: w.businessName,
                categories: w.categories.join(', '),
                location: `${w.city || ''}, ${w.state || ''}`,
                id: w._id
              }));

            } else if (functionName === "get_product_details") {
              const { productName } = functionArgs;
              const p = await Product.findOne({ name: new RegExp(productName, 'i') }).populate('wholesalerId');
              if (!p) toolResult = { error: "Product not found" };
              else toolResult = {
                name: p.name,
                description: p.description,
                price: p.pricePerUnit,
                moq: p.moq,
                stock: p.stock,
                wholesaler: p.wholesalerId?.businessName
              };

            } else if (functionName === "get_my_deals" || functionName === "view_received_deals") {
              const deals = await Deal.find({
                $or: [{ retailerId: fullUser._id }, { wholesalerId: fullUser._id }]
              }).sort({ createdAt: -1 }).limit(10);
              toolResult = deals.map(d => ({
                id: d._id,
                product: d.productName,
                quantity: d.quantity,
                offeredPrice: d.offeredPrice,
                status: d.status,
                date: d.createdAt.toLocaleDateString()
              }));

            } else if (functionName === "check_requirements") {
              const reqs = await Requirement.find({ retailerId: fullUser._id }).sort({ createdAt: -1 });
              toolResult = reqs.map(r => ({
                product: r.productName,
                quantity: r.quantity,
                price: r.expectedPrice,
                status: r.status
              }));

            } else if (functionName === "get_my_inventory") {
              const myProducts = await Product.find({ wholesalerId: fullUser._id }).sort({ stock: 1 });
              toolResult = myProducts.map(p => ({
                name: p.name,
                stock: p.stock,
                price: p.pricePerUnit,
                moq: p.moq,
                status: p.stock <= 10 ? 'LOW STOCK' : 'OK'
              }));

            } else if (functionName === "update_product_details") {
              const { productName, stock, price, moq } = functionArgs;
              const update = {};
              if (stock !== undefined) update.stock = stock;
              if (price !== undefined) update.pricePerUnit = price;
              if (moq !== undefined) update.moq = moq;

              const updated = await Product.findOneAndUpdate(
                { wholesalerId: fullUser._id, name: new RegExp(productName, 'i') },
                { $set: update },
                { new: true }
              );
              if (!updated) toolResult = { error: "Product not found in your inventory" };
              else toolResult = { success: true, updated: { name: updated.name, stock: updated.stock, price: updated.pricePerUnit, moq: updated.moq } };

            } else if (functionName === "discover_market_requirements") {
              // Find requirements that match wholesaler's categories
              const filter = { status: 'open' };
              if (fullUser.categories && fullUser.categories.length > 0) {
                filter.categories = { $in: fullUser.categories };
              }
              const marketplaceReqs = await Requirement.find(filter).sort({ createdAt: -1 }).limit(10);
              toolResult = marketplaceReqs.map(r => ({
                product: r.productName,
                quantity: r.quantity,
                expectedPrice: r.expectedPrice,
                categories: r.categories.join(', ')
              }));

            } else if (functionName === "get_business_analytics") {
              const products = await Product.find({ wholesalerId: fullUser._id });
              const deals = await Deal.find({ wholesalerId: fullUser._id });

              const topProduct = [...products].sort((a, b) => (b.soldCount || 0) - (a.soldCount || 0))[0];
              const pendingDeals = deals.filter(d => d.status === 'pending').length;
              const confirmedDeals = deals.filter(d => d.status === 'confirmed').length;

              toolResult = {
                totalProducts: products.length,
                totalSalesVolume: products.reduce((sum, p) => sum + (p.soldCount || 0), 0),
                topSelling: topProduct ? topProduct.name : 'N/A',
                pendingNegotiations: pendingDeals,
                confirmedDeals: confirmedDeals
              };
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

    if (!finalReply) {
      if (messages.length > 0) {
        const lastMsg = messages[messages.length - 1];
        finalReply = lastMsg.content || "I have processed your request. Is there anything specific from the data you'd like me to explain?";
      } else {
        finalReply = "I'm sorry, I couldn't process that request right now.";
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

// 3. Smart Recommendation Engine (Retailer)
router.get('/recommendations', authMiddleware, async (req, res) => {
  try {
    const userId = String(req.user.id);

    // --- Build interest profile from retailer's history ---
    const categoryScores = {};  // category -> score
    const productBoosts = {};   // productId -> extra score

    // A) Past confirmed deals (+30 per category)
    const pastDeals = await Deal.find({ retailerId: userId, status: 'confirmed' }).lean();
    for (const deal of pastDeals) {
      if (deal.productId) {
        const prod = await Product.findById(deal.productId).lean();
        if (prod && prod.category) {
          categoryScores[prod.category] = (categoryScores[prod.category] || 0) + 30;
          productBoosts[String(prod._id)] = (productBoosts[String(prod._id)] || 0) + 40;
        }
      }
    }

    // B) Messages/Inquiries sent by retailer (+20 per product mentioned)
    const sentMessages = await Message.find({
      senderId: userId,
      productName: { $exists: true, $ne: '' }
    }).lean();
    const mentionedNames = new Set();
    for (const msg of sentMessages) {
      if (msg.productName) mentionedNames.add(msg.productName.toLowerCase().trim());
    }

    // C) Requirements posted (+15 per category)
    const requirements = await Requirement.find({ retailerId: userId }).lean();
    for (const reqDoc of requirements) {
      if (reqDoc.categories && reqDoc.categories.length > 0) {
        reqDoc.categories.forEach(cat => {
          categoryScores[cat] = (categoryScores[cat] || 0) + 15;
        });
      }
    }

    // --- Fetch all in-stock products ---
    const allProducts = await Product.find({ stock: { $gt: 0 } })
      .populate('wholesalerId', 'name businessName city')
      .lean();

    // --- Score each product ---
    const scored = allProducts.map(p => {
      let score = 0;
      let reason = 'Trending on platform';

      // Category match from user history
      const catScore = categoryScores[p.category] || 0;
      if (catScore > 0) { score += catScore; reason = 'Based on your activity'; }

      // Popularity boost (soldCount signal)
      const popularity = Math.floor((p.soldCount || 0) / 5) * 10;
      score += Math.min(popularity, 40);

      // Reserved stock = demand signal
      score += Math.min((p.reservedStock || 0) * 2, 20);

      // Direct product boost (from confirmed deals)
      if (productBoosts[String(p._id)]) {
        score += productBoosts[String(p._id)];
        reason = 'Based on your past deals';
      }

      // Name mentioned in messages
      if (mentionedNames.has((p.name || '').toLowerCase().trim())) {
        score += 25;
        reason = 'Based on your inquiries';
      }

      // Trending products (high soldCount) get a minimum baseline
      if ((p.soldCount || 0) >= 10 && score < 20) {
        score = 20;
        reason = 'Trending 🔥';
      }

      return { ...p, score, reason };
    });

    // Sort by score descending, top 8
    scored.sort((a, b) => b.score - a.score);
    const recommendations = scored.slice(0, 8);

    res.json({ success: true, recommendations });
  } catch (error) {
    console.error('Recommendations error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch recommendations' });
  }
});

// 4. Demand Insights API (Wholesaler)
router.get('/demand-insights', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'wholesaler') {
      return res.status(403).json({ success: false, message: 'Only wholesalers can access demand insights' });
    }

    const wholesalerId = String(req.user.id);
    const now = new Date();
    const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
    const sixtyDaysAgo = new Date(now - 60 * 24 * 60 * 60 * 1000);

    const products = await Product.find({ wholesalerId }).lean();

    const insights = await Promise.all(products.map(async (p) => {
      const pId = String(p._id);
      const pName = (p.name || '').toLowerCase();
      const pCat = p.category || '';

      // A) Confirmed deals in last 30 days
      const recent30 = await Deal.countDocuments({
        wholesalerId,
        productId: p._id,
        status: 'confirmed',
        createdAt: { $gte: thirtyDaysAgo }
      });

      // B) Confirmed deals in prev 30 days (31-60 days ago)
      const prev30 = await Deal.countDocuments({
        wholesalerId,
        productId: p._id,
        status: 'confirmed',
        createdAt: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo }
      });

      // C) Total confirmed deals all time
      const totalDeals = await Deal.countDocuments({
        wholesalerId, productId: p._id, status: 'confirmed'
      });

      // D) Message inquiries referencing this product name
      const inquiries = await Message.countDocuments({
        receiverId: wholesalerId,
        productName: { $regex: new RegExp(pName, 'i') }
      });

      // E) Open requirements matching product category
      const requirements = await Requirement.countDocuments({
        status: 'open',
        $or: [
          { categories: { $in: [pCat] } },
          { productName: { $regex: new RegExp(pName, 'i') } }
        ]
      });

      // --- Score calculation ---
      let demandScore = 0;
      demandScore += Math.min(recent30 * 15, 45);     // up to 45 from recent deals
      demandScore += Math.min(inquiries * 8, 30);      // up to 30 from inquiries
      demandScore += Math.min(requirements * 5, 20);   // up to 20 from requirements
      demandScore += Math.min((p.soldCount || 0) * 2, 20); // popularity boost

      // --- Trend ---
      let trend = 'stable';
      if (recent30 > prev30) trend = 'increasing';
      else if (recent30 < prev30 && prev30 > 0) trend = 'decreasing';

      // --- Demand level & action ---
      let demandLevel, suggestedAction, trendLabel;
      if (demandScore >= 60) {
        demandLevel = 'high';
        suggestedAction = 'Increase stock';
      } else if (demandScore >= 25) {
        demandLevel = 'medium';
        suggestedAction = 'Maintain stock';
      } else {
        demandLevel = 'low';
        suggestedAction = 'Consider reducing stock';
      }

      if (trend === 'increasing') trendLabel = '↑ Increasing';
      else if (trend === 'decreasing') trendLabel = '↓ Decreasing';
      else trendLabel = '→ Stable';

      return {
        productId: pId,
        name: p.name,
        category: p.category,
        image: p.image,
        stock: p.stock,
        soldCount: p.soldCount || 0,
        demandLevel,
        demandScore: Math.min(demandScore, 100),
        trend,
        trendLabel,
        suggestedAction,
        confirmedDeals: totalDeals,
        recentDeals: recent30,
        inquiries,
        requirements
      };
    }));

    // Sort by demandScore desc
    insights.sort((a, b) => b.demandScore - a.demandScore);

    res.json({ success: true, insights });
  } catch (error) {
    console.error('Demand insights error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch demand insights' });
  }
});

// ---------- DIAGNOSTIC: TEST EMAIL ----------
// This endpoint is for troubleshooting deployment issues.
router.get('/config/test-email', async (req, res) => {
  try {
    const testEmailSnippet = `
      <div style="font-family:sans-serif; padding:20px; border:1px solid #4361ee; border-radius:10px;">
        <h2 style="color:#4361ee;">NexTrade Diagnostic</h2>
        <p>If you see this, your email configuration is working perfectly on Render!</p>
        <p>Timestamp: ${new Date().toLocaleString()}</p>
      </div>
    `;

    console.log('--- Starting Diagnostic Email Test ---');
    console.log('Using EMAIL_USER:', process.env.EMAIL_USER ? 'SET (Redacted)' : 'NOT SET');
    
    await emailTransporter.sendMail({
      from: `"NexTrade Diagnostic" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER, // Send to self
      subject: 'NexTrade Diagnostic Test',
      html: testEmailSnippet
    });

    res.json({ 
      success: true, 
      message: 'Test email sent successfully to ' + process.env.EMAIL_USER,
      diagnostics: 'Connection verified and message accepted by Gmail.'
    });
  } catch (err) {
    console.error('Test Email Failed:', err);
    res.status(500).json({ 
      success: false, 
      error: err.message,
      code: err.code,
      response: err.response,
      instruction: 'If you see "Invalid Login", please double check your App Password on Render.'
    });
  }
});

// ---------- CONTACT US ----------
router.post('/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const newMessage = new ContactMessage({ name, email, subject, message });
    await newMessage.save();

    // Send confirmation email to user
    try {
      await emailTransporter.sendMail({
        from: `"NexTrade Support" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `We've received your message: ${subject}`,
        html: `
          <div style="font-family: sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #4361ee;">Hello ${name},</h2>
            <p>Thank you for reaching out to NexTrade! We have received your message regarding <b>"${subject}"</b>.</p>
            <p>Our team will review your inquiry and get back to you within 24-48 business hours.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="font-size: 0.9em; color: #666;">This is an automated confirmation. Please do not reply to this email.</p>
          </div>
        `
      });
    } catch (emailErr) {
      console.error("Failed to send contact confirmation email:", emailErr);
    }

    res.status(201).json({ success: true, message: "Your message has been sent successfully!" });

  } catch (err) {
    console.error("Contact error:", err);
    res.status(500).json({ success: false, message: "Failed to send message" });
  }
});

// ================= MOUNT ROUTER =================
app.use('/api', apiLimiter, router);

// ================= GLOBAL ERROR HANDLER =================
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);

  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File is too large. Max limit is 5MB.' });
    }
    return res.status(400).json({ success: false, message: 'File upload error: ' + err.message });
  }

  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message
  });
});

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
  cors: { origin: "*" }, // Open for production, can be restricted later if needed
  maxHttpBufferSize: 1e7 // Support up to 10MB
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
      } catch (e) { }
    }

    // Fetch sender name for real-time notifications
    let senderName = 'Someone';
    try {
      const sender = await User.findById(senderId);
      if (sender) senderName = sender.businessName || sender.name;
    } catch (e) { }

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

    const payload = { ...newMsg.toObject(), senderName };

    // Send to receiver
    if (onlineUsers.has(receiverId)) {
      io.to(onlineUsers.get(receiverId)).emit("receive_message", payload);
    }
    // Send back to sender
    socket.emit("receive_message", payload);
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

