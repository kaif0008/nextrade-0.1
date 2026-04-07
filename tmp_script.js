const fs = require('fs');
const path = require('path');
const publicDir = 'c:\\Users\\mrkai\\OneDrive\\Desktop\\nextrade-0.1\\public';
const files = ['items.html', 'wholesalers.html', 'retailer-dashboard.html', 'wholesaler-dashboard.html', 'product-management.html', 'orders.html', 'cart.html', 'index.html', 'profile.html', 'messages.html', 'checkout.html', 'contact.html'];

files.forEach(f => {
  const fp = path.join(publicDir, f);
  if(fs.existsSync(fp)) {
    let content = fs.readFileSync(fp, 'utf-8');
    if(!content.includes('chatbot.js')) {
      content = content.replace('</body>', '  <!-- AI Chatbot -->\n  <link rel="stylesheet" href="/css/chatbot.css">\n  <script src="/chatbot.js"></script>\n</body>');
      fs.writeFileSync(fp, content);
      console.log('Updated ' + f);
    }
  }
});
