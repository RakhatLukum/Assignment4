const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  twoFASecret: { type: String, required: false }, // Секретный ключ для 2FA
  is2FAEnabled: { type: Boolean, default: false }, // Включен ли 2FA
});

module.exports = mongoose.model("User", userSchema);
