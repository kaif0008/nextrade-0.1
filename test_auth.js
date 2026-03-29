const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// This script will connect to the DB, create a user if not exists, log in (get token), and then try to hit the update-profile endpoint using fetch.

async function testFlow() {
  const email = "test@nextrade.com";
  const password = "password123";

  try {
    console.log("Creating user...");
    const resSignup = await fetch('http://localhost:5010/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: "Test User",
        email,
        password,
        role: "retailer"
      })
    });
    console.log("Signup:", await resSignup.json());

    console.log("Logging in...");
    const resLogin = await fetch('http://localhost:5010/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const loginData = await resLogin.json();
    console.log("Login OK:", loginData.success);
    
    if (!loginData.success) {
      console.log("Failed to login!");
      return;
    }

    const token = loginData.token;
    console.log("Got token:", token.substring(0, 15) + "...");

    console.log("Updating profile...");
    const resUpdate = await fetch('http://localhost:5010/api/update-profile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        name: "Updated Test User",
        mobileNumber: "9876543210"
      })
    });

    const updateData = await resUpdate.json();
    console.log("Update OK:", updateData.success);
    if (!updateData.success) {
      console.log("Update Error Message:", updateData.message);
    }

  } catch (err) {
    console.error("Test failed:", err);
  }
}

testFlow();
