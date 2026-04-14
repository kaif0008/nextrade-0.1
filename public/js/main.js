// NexTrade Main Landing Page Logic
document.addEventListener("DOMContentLoaded", () => {
    // 1. Authentication Check & UI Toggle
    const user = JSON.parse(localStorage.getItem("user"));
    const token = localStorage.getItem("token");

    const loginBtn = document.getElementById("loginBtn");
    const signupBtn = document.getElementById("signupBtn");
    const dashboardBtn = document.getElementById("dashboardBtn");

    if (user && token) {
        if (loginBtn) loginBtn.style.display = "none";
        if (signupBtn) signupBtn.style.display = "none";
        if (dashboardBtn) dashboardBtn.style.display = "inline-block";
    } else {
        if (loginBtn) loginBtn.style.display = "inline-block";
        if (signupBtn) signupBtn.style.display = "inline-block";
        if (dashboardBtn) dashboardBtn.style.display = "none";
    }

    // 2. Initialize Marketplace Logic
    initMarketplace();

    // 3. Handle 'Post' query parameter
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('post') === 'true' && user && user.role === 'retailer') {
        setTimeout(() => {
            if (typeof toggleReqModal === 'function') toggleReqModal(true);
        }, 500);
    }
});

let mpCatSelector = null;

async function initMarketplace() {
    const user = JSON.parse(localStorage.getItem("user"));
    const token = localStorage.getItem("token");
    if (!user || !token) return;

    if (user.role === 'retailer') {
        const heroPostBtn = document.getElementById('heroPostBtn');
        const heroJoinBtn = document.getElementById('heroJoinBtn');
        if (heroPostBtn) heroPostBtn.style.display = 'flex';
        if (heroJoinBtn) heroJoinBtn.style.display = 'none';

        if (typeof CategorySelector === 'function') {
            mpCatSelector = new CategorySelector('reqCategoryContainer', {
                placeholder: "Search & add categories..."
            });
        }
    } else if (user.role === 'wholesaler') {
        const mpSection = document.getElementById('marketplaceSection');
        const reqFeed = document.getElementById('wholesalerReqFeed');
        const mpTitle = document.getElementById('mpTitle');
        const mpSub = document.getElementById('mpSub');

        if (mpSection) mpSection.style.display = 'block';
        if (reqFeed) reqFeed.style.display = 'block';
        if (mpTitle) mpTitle.innerText = "Live Retailer Requirements";
        if (mpSub) mpSub.innerText = "Personalized opportunities matching your industry.";
        loadRequirements();
    }
}

function toggleReqModal(show) {
    const modal = document.getElementById('reqModal');
    if (!modal) return;
    if (show) modal.classList.add('show');
    else modal.classList.remove('show');
}

async function postRequirement() {
    const productName = document.getElementById('reqProductName').value.trim();
    const quantity = parseInt(document.getElementById('reqQuantity').value);
    const expectedPrice = parseFloat(document.getElementById('reqPrice').value) || null;
    const unit = document.getElementById('reqUnit').value;
    const description = document.getElementById('reqDescription').value.trim();
    const categories = mpCatSelector ? mpCatSelector.getSelected() : [];

    if (!productName || !quantity || categories.length === 0) {
        showToast('Please fill Product Name, Quantity and at least one Category', 'error');
        return;
    }

    try {
        const res = await fetch('/api/requirements', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ productName, quantity, expectedPrice, unit, description, categories })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Requirement posted successfully! 🎉', 'success');
            toggleReqModal(false);
            // Clear form
            document.getElementById('reqProductName').value = '';
            document.getElementById('reqQuantity').value = '';
            document.getElementById('reqPrice').value = '';
            document.getElementById('reqDescription').value = '';
            if (mpCatSelector) mpCatSelector.setSelected([]);
        } else {
            showToast(data.message || 'Failed to post', 'error');
        }
    } catch (e) { console.error(e); showToast('Server error', 'error'); }
}

async function loadRequirements() {
    const reqList = document.getElementById('reqList');
    const emptyState = document.getElementById('mpEmptyState');
    if (!reqList) return;
    
    try {
        const res = await fetch('/api/requirements', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        const data = await res.json();
        
        if (data.success) {
            if (!data.requirements || data.requirements.length === 0) {
                reqList.style.display = 'none';
                if (emptyState) emptyState.style.display = 'block';
                return;
            }

            reqList.style.display = 'grid';
            if (emptyState) emptyState.style.display = 'none';
            reqList.innerHTML = data.requirements.map(req => {
                const postedDate = new Date(req.createdAt);
                const isNew = (new Date() - postedDate) < 24 * 60 * 60 * 1000;
                
                return `
                <div class="req-card">
                    ${isNew ? '<div class="req-badge" style="background:#2bc155; color:white; left:20px; right:auto;">NEW</div>' : ''}
                    <div class="req-badge">${req.categories[0]}${req.categories.length > 1 ? ` +${req.categories.length-1}` : ''}</div>
                    <h3 class="req-title">${req.productName}</h3>
                    <div class="req-meta">
                        <span><i class="fas fa-cubes"></i> Qty: ${req.quantity}</span>
                        ${req.expectedPrice ? `<span><i class="fas fa-tag"></i> Target: ₹${req.expectedPrice}/${req.unit || 'piece'}</span>` : ''}
                    </div>
                    <p class="req-desc">${req.description || 'No additional details provided.'}</p>
                    <div class="req-footer">
                        <div class="req-retailer">
                            <i class="fas fa-store"></i>
                            <div>
                                ${req.retailerId?.businessName || req.retailerId?.name || 'Retailer'}<br>
                                <small style="font-weight:400; color:#94a3b8;">${req.retailerId?.city || ''} • ${postedDate.toLocaleDateString()}</small>
                            </div>
                        </div>
                        <a href="messages.html?user=${req.retailerId?._id}&requirementId=${req._id}&productName=${encodeURIComponent(req.productName)}&quantity=${req.quantity}&price=${req.expectedPrice || ''}" class="btn-send-offer">
                            Send Offer <i class="fas fa-paper-plane"></i>
                        </a>
                    </div>
                </div>
            `;}).join('');
        }
    } catch (e) { 
        console.error(e); 
        reqList.innerHTML = '<p style="color:#ef233c;">Failed to load requirements.</p>';
    }
}

function showToast(msg, type='success') {
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toastMsg');
    if (!toast || !toastMsg) {
        alert(msg); // Fallback
        return;
    }
    
    toastMsg.innerText = msg;
    toast.className = 'toast show ' + (type === 'error' ? 'err' : 'ok');
    setTimeout(() => { toast.classList.remove('show'); }, 3000);
}
