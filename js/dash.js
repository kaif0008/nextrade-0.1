  // ====================================
  // Display user info
  // ====================================
  const user = JSON.parse(localStorage.getItem('user'));
  if (user) {
      document.getElementById('userInfo').innerHTML = `
          <p>Name: ${user.name}</p>
          <p>Email: ${user.email}</p>
          <p>Role: ${user.role}</p>
      `;
  } else {
      window.location.href = 'login.html';
  }
// ====================================
  // Logout
  // ====================================
  document.getElementById('logoutBtn').addEventListener('click', () => {
      localStorage.removeItem('user');
      window.location.href = 'login.html';
  });