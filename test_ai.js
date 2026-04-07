const http = require('http');

const data = JSON.stringify({
  message: "Hello",
  history: [ { sender: "user", text: "Hello" } ],
  userContext: { role: "retailer", name: "Test" }
});

const options = {
  hostname: 'localhost',
  port: 5010,
  path: '/api/ai/chat',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
    // Note: We need a valid JWT token. But let's just bypass auth for the test if we can, or we will just get 401.
  }
};

const req = http.request(options, res => {
  let body = '';
  res.on('data', d => { body += d; });
  res.on('end', () => {
    console.log(`Status: ${res.statusCode}`);
    console.log(`Body: ${body}`);
  });
});

req.on('error', error => {
  console.error(error);
});

req.write(data);
req.end();
