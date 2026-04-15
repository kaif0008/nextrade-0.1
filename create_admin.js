require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// MongoDB setup
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/nextrade';

// Define User schema specifically for this script so it runs standalone
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['admin', 'wholesaler', 'retailer'] },
  emailVerified: { type: Boolean, default: false }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', userSchema);

async function setupAdmin() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');

    // 🔴 CREDENTIALS ARE NOW SECURELY LOADED FROM YOUR .env FILE 🔴
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;

    if (!adminEmail || !adminPassword) {
      console.error('Error: ADMIN_EMAIL and ADMIN_PASSWORD must be set in your .env file');
      process.exit(1);
    }

    const existingAdmin = await User.findOne({ role: 'admin' });
    
    if (existingAdmin) {
      console.log('Admin user already exists. Updating credentials...');
      existingAdmin.email = adminEmail;
      existingAdmin.password = adminPassword;
      await existingAdmin.save();
      console.log(`Successfully updated admin user.\nNew Email: ${adminEmail}\nNew Password: ${adminPassword}`);
      process.exit(0);
    }

    const adminUser = new User({
      name: 'Super Admin',
      email: adminEmail,
      password: adminPassword,
      role: 'admin',
      emailVerified: true
    });

    await adminUser.save();
    console.log(`Successfully created admin user.\nEmail: ${adminEmail}\nPassword: ${adminPassword}`);
    process.exit(0);

  } catch (err) {
    console.error('Failed to setup admin:', err);
    process.exit(1);
  }
}

setupAdmin();
