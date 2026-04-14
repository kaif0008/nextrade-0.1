document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const role = document.getElementById('role').value;
    
    try {
        const formData = new FormData();
        formData.append('name', name);
        formData.append('email', email);
        formData.append('password', password);
        formData.append('role', role);
        
        // Handle photo if available (optional for signup usually, but I'll add the support)
        const photoInput = document.getElementById('photo');
        if (photoInput && photoInput.files[0]) {
            formData.append('photo', photoInput.files[0]);
        }

        const response = await fetch('/api/signup', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            // ====================================
            // Show success message
            const statusMessage = document.querySelector('.status-message');
            statusMessage.style.display = 'flex';
            
            // Redirect after 2 seconds
            // ====================================
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
        } else {
            alert(data.message || 'Signup failed');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    }
});