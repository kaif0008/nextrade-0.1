// chatbot.js
document.addEventListener('DOMContentLoaded', () => {
  // Fetch user info for role-aware greeting
  let user = null;
  try {
    const userStr = localStorage.getItem('user');
    if (userStr) user = JSON.parse(userStr);
  } catch(e) { console.error("Error parsing user from localStorage", e); }

  const userName = user && user.name ? user.name : '';
  const userRole = user && user.role ? (user.role.charAt(0).toUpperCase() + user.role.slice(1)) : '';
  
  let greetingMessage = "Hello! I'm your NexTrade virtual assistant. How can I help you today?";
  if (userName && userRole) {
    greetingMessage = `Hello ${userName}! I'm your specific ${userRole} Assistant. How can I help you?`;
  }

  // Inject HTML
  const container = document.createElement('div');
  container.id = 'nt-chatbot-container';
  container.innerHTML = `
    <div id="nt-chatbot-window">
      <div id="nt-chatbot-header">
        <span>🤖 NexTrade AI</span>
        <button id="nt-chatbot-close">&times;</button>
      </div>
      <div id="nt-chatbot-messages">
        <div class="nt-msg nt-msg-ai">${greetingMessage}</div>
      </div>
      <div id="nt-chatbot-input-area">
        <input type="text" id="nt-chatbot-input" placeholder="Type your message..." autocomplete="off" />
        <button id="nt-chatbot-send">➤</button>
      </div>
    </div>
    <button id="nt-chatbot-toggle">💬</button>
  `;
  document.body.appendChild(container);

  // Link elements
  const toggleBtn = document.getElementById('nt-chatbot-toggle');
  const closeBtn = document.getElementById('nt-chatbot-close');
  const chatWindow = document.getElementById('nt-chatbot-window');
  const sendBtn = document.getElementById('nt-chatbot-send');
  const input = document.getElementById('nt-chatbot-input');
  const messagesDiv = document.getElementById('nt-chatbot-messages');

  let chatHistory = [];

  // Toggle logic
  toggleBtn.addEventListener('click', () => {
    chatWindow.style.display = chatWindow.style.display === 'flex' ? 'none' : 'flex';
  });

  closeBtn.addEventListener('click', () => {
    chatWindow.style.display = 'none';
  });

  // Send message
  const sendMessage = async () => {
    const text = input.value.trim();
    if (!text) return;

    // Display user message
    addMessage(text, 'user');
    input.value = '';
    
    // Show typing status
    const typingId = 'typing-' + Date.now();
    addTypingIndicator(typingId);

    try {
      const resp = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: JSON.stringify({ 
          message: text, 
          history: chatHistory,
          userContext: user // Providing the backend with local user knowledge
        })
      });
      
      const data = await resp.json();
      removeTypingIndicator(typingId);

      if (data.success) {
        addMessage(data.reply, 'model');
      } else if (resp.status === 401) {
        addMessage('Please <a href="login.html" style="color:#3b82f6;text-decoration:underline">log in</a> to use the AI Assistant.', 'model');
      } else {
        addMessage('Sorry, I encountered an error.', 'model');
      }

    } catch (e) {
      removeTypingIndicator(typingId);
      addMessage('Network error. Please try again later.', 'model');
    }
  };

  sendBtn.addEventListener('click', sendMessage);
  input.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
  });

  function addMessage(text, role) {
    const div = document.createElement('div');
    div.className = 'nt-msg ' + (role === 'user' ? 'nt-msg-user' : 'nt-msg-ai');
    div.innerHTML = text; 
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    
    if(chatHistory.length > 20) chatHistory = chatHistory.slice(-20); // keep it reasonable
    chatHistory.push({ sender: role, text });
  }

  function addTypingIndicator(id) {
    const div = document.createElement('div');
    div.id = id;
    div.className = 'nt-msg nt-typing';
    div.textContent = 'AI is typing...';
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }

  function removeTypingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }
});
