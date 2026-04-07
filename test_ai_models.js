const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

async function listModels() {
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  try {
    // There isn't a direct listModels in the standard SDK easily, but we can test a simple completion
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const result = await model.generateContent("test");
    console.log("Gemini 1.5 Flash works!");
  } catch (e) {
    console.log("Gemini 1.5 Flash failed:", e.message);
    if (e.status === 404) {
       console.log("Trying gemini-pro...");
       try {
         const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
         const result = await model.generateContent("test");
         console.log("Gemini Pro works!");
       } catch (e2) {
         console.log("Gemini Pro failed:", e2.message);
       }
    }
  }
}

listModels();
