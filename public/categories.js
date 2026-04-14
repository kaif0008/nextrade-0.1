/**
 * CategorySelector.js
 * Handles the searchable multi-select UI for product categories.
 */

const NEX_TRADE_CATEGORIES = [
    "Food", "Grocery", "Fruits & Vegetables", "Dairy Products", "Packaged Food & Beverages",
    "Fashion & Apparel", "Footwear", "Electronics", "Mobile & Accessories", "Computers & IT",
    "Home Appliances", "Furniture", "Home Decor", "Kitchenware", "Pharmacy & Medical",
    "Ayurvedic & Herbal", "Beauty & Cosmetics", "Personal Care", "Hardware & Tools",
    "Electrical Supplies", "Construction Materials", "Automobile Parts & Accessories",
    "Tyres & Batteries", "Stationery & Office Supplies", "Books & Education",
    "Toys & Games", "Gifts & Novelties", "Agriculture & Farming Supplies",
    "Seeds & Fertilizers", "Pet Supplies", "Sports & Fitness", "Jewellery & Accessories",
    "General Store / Multi-category"
];

class CategorySelector {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.selectedCategories = options.selected || [];
        this.onSelectionChange = options.onChange || (() => {});
        this.placeholder = options.placeholder || "Search categories...";
        this.render();
    }

    render() {
        this.container.innerHTML = `
            <div class="cat-selector-wrap">
                <div class="cat-search-box">
                    <i class="fas fa-search"></i>
                    <input type="text" class="cat-search-input" placeholder="${this.placeholder}">
                </div>
                <div class="cat-dropdown" style="display: none;">
                    <div class="cat-options-list"></div>
                </div>
                <div class="cat-selected-chips"></div>
            </div>
            <style>
                .cat-selector-wrap { position: relative; width: 100%; font-family: 'Poppins', sans-serif; }
                .cat-search-box { 
                    display: flex; align-items: center; gap: 10px; 
                    background: #f8fafc; border: 1.5px solid #e2e8f0; 
                    padding: 10px 14px; border-radius: 10px; transition: 0.2s;
                }
                .cat-search-box:focus-within { border-color: #4361ee; background: white; box-shadow: 0 0 0 3px rgba(67,97,238,0.08); }
                .cat-search-box i { color: #94a3b8; font-size: 14px; }
                .cat-search-input { border: none; background: transparent; outline: none; flex: 1; font-size: 14px; color: #1e293b; }
                
                .cat-dropdown { 
                    position: absolute; top: 100%; left: 0; right: 0; 
                    background: white; border-radius: 10px; border: 1px solid #e2e8f0;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.1); z-index: 1000; 
                    margin-top: 5px; max-height: 250px; overflow-y: auto;
                }
                .cat-option { 
                    padding: 10px 15px; font-size: 13px; color: #334155; 
                    cursor: pointer; transition: 0.2s; display: flex; align-items: center; justify-content: space-between;
                }
                .cat-option:hover { background: #f1f5f9; color: #4361ee; }
                .cat-option.selected { background: #eff6ff; color: #4361ee; font-weight: 600; }
                .cat-option.selected::after { content: '\f00c'; font-family: 'Font Awesome 5 Free'; font-weight: 900; }
                
                .cat-selected-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
                .cat-chip { 
                    background: #e0e7ff; color: #4361ee; font-size: 12px; font-weight: 600;
                    padding: 4px 10px; border-radius: 20px; display: flex; align-items: center; gap: 6px;
                }
                .cat-chip i { cursor: pointer; color: #818cf8; transition: 0.2s; }
                .cat-chip i:hover { color: #ef233c; }
            </style>
        `;

        this.searchInput = this.container.querySelector('.cat-search-input');
        this.dropdown = this.container.querySelector('.cat-dropdown');
        this.optionsList = this.container.querySelector('.cat-options-list');
        this.chipsContainer = this.container.querySelector('.cat-selected-chips');

        this.setupEvents();
        this.updateChips();
    }

    setupEvents() {
        this.searchInput.addEventListener('focus', () => this.showDropdown(""));
        this.searchInput.addEventListener('input', (e) => this.showDropdown(e.target.value));

        document.addEventListener('click', (e) => {
            if (!this.container.contains(e.target)) this.dropdown.style.display = 'none';
        });
    }

    showDropdown(query) {
        const filtered = NEX_TRADE_CATEGORIES.filter(c => 
            c.toLowerCase().includes(query.toLowerCase())
        );

        if (filtered.length === 0) {
            this.optionsList.innerHTML = `<div class="cat-option" style="color:#94a3b8; cursor:default;">No matching categories</div>`;
        } else {
            this.optionsList.innerHTML = filtered.map(c => `
                <div class="cat-option ${this.selectedCategories.includes(c) ? 'selected' : ''}" data-val="${c}">
                    ${c}
                </div>
            `).join('');

            this.optionsList.querySelectorAll('.cat-option[data-val]').forEach(el => {
                el.addEventListener('click', () => {
                    const val = el.getAttribute('data-val');
                    this.toggleCategory(val);
                    this.dropdown.style.display = 'none';
                    this.searchInput.value = "";
                });
            });
        }
        this.dropdown.style.display = 'block';
    }

    toggleCategory(val) {
        if (this.selectedCategories.includes(val)) {
            this.selectedCategories = this.selectedCategories.filter(c => c !== val);
        } else {
            this.selectedCategories.push(val);
        }
        this.updateChips();
        this.onSelectionChange(this.selectedCategories);
    }

    updateChips() {
        this.chipsContainer.innerHTML = this.selectedCategories.map(c => `
            <div class="cat-chip">
                ${c} <i class="fas fa-times" data-val="${c}"></i>
            </div>
        `).join('');

        this.chipsContainer.querySelectorAll('i').forEach(el => {
            el.addEventListener('click', (e) => {
                this.toggleCategory(el.getAttribute('data-val'));
            });
        });
    }

    getSelected() {
        return this.selectedCategories;
    }

    setSelected(cats) {
        this.selectedCategories = cats || [];
        this.updateChips();
    }
}
