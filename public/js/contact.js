// contact.js
document.addEventListener('DOMContentLoaded', () => {
    const contactForm = document.getElementById('contactForm');
    
    if (contactForm) {
        contactForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const submitBtn = contactForm.querySelector('button[type="submit"]');
            const originalBtnContent = submitBtn.innerHTML;
            
            // Collect data
            const formData = {
                name: document.getElementById('name').value,
                email: document.getElementById('email').value,
                subject: document.getElementById('subject').value,
                message: document.getElementById('message').value
            };
            
            // Set loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
            
            try {
                const response = await fetch('/api/contact', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                const data = await response.json();
                
                if (data.success) {
                    // Show success state
                    contactForm.innerHTML = `
                        <div class="contact-success-message" style="text-align: center; padding: 40px 20px;">
                            <div style="font-size: 60px; color: #4CAF50; margin-bottom: 20px;">
                                <i class="fas fa-check-circle"></i>
                            </div>
                            <h2 style="margin-bottom: 10px;">Message Sent!</h2>
                            <p style="color: #666; margin-bottom: 25px;">Thank you for reaching out. We've received your inquiry and sent a confirmation email to <strong>${formData.email}</strong>.</p>
                            <button onclick="window.location.reload()" class="btn btn-primary">Send Another Message</button>
                        </div>
                    `;
                } else {
                    throw new Error(data.message || 'Failed to send message');
                }
            } catch (err) {
                console.error('Contact error:', err);
                alert('Sorry, there was an error sending your message. Please try again later.');
                
                // Reset button
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtnContent;
            }
        });
    }
});
