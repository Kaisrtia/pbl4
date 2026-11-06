// ==============================================================================
// ElectroShop - API Integration & Client State Controller
// Project: PBL4 - DevSecOps & Plaintext Network Defense System
// ==============================================================================

const API_BASE = window.API_BASE_URL || '/api';

// Product Image Mappings (High-resolution assets)
const PRODUCT_IMAGES = {
  'MCU-ARD-R4':
    'https://lh3.googleusercontent.com/aida-public/AB6AXuChuccybepULQ9tp5GLZODL-2QlIZmEw4dIMHHUqbJBuwl2vJ_dLRFTMzuVwpCYWVUG0xD34XJE-UrOh2-EqUv0zqYbXcKy2Cf5LyP2gFPXJpLa0DShLDdNzeqeC8MB3jeUzbDq5bBoRvUqrD5DFYnNZhq4fZ-zJNmD9lL7KJ8yITPj2t2AF20d3QilC6kxici_7gukoBTYIXYqf1b50xWn9ecgUAnPe9DMQlbiTD-yO34_kr2kI-j9',
  'MCU-ESP-32D':
    'https://lh3.googleusercontent.com/aida-public/AB6AXuDY1bC4I9h8H0jaKj6mc7bafN7-29X1mL1mdiAJpR9yX_bNUC8-uoiwn5kKqoDNCvqxtrU7o8pmrGmfVm31jjGZpCqZ66W1SBcSOr14lSo8rHeAg8Fv446VGW2rQ-DjjujUZL9_ygwspQeAarrtF5ZgN65VpqcOxac3XfBHvsYaHCEFM0-4CxbsaJHocNCVaZYObQg-hfuQ66L49yHbKyj155Fn2_Mz6CBmROtxKBsY2hf5-uk2ZEo4',
  'SEN-UC-SR04':
    'https://lh3.googleusercontent.com/aida-public/AB6AXuA5wasAV4ye6VnArPp0fKN4wqAalG9lCgZ4gWO6hzpYvITjhAxo0nWFVwTjKkdFzDPggm4qzlT-mH0gF56rfHs5trYd2RPtzdlvsD43Pwq4yuMx4hnVJRpufnlt6Xy3Ehy-2hnfE3iqCBbfYdxQy69XyVI4PD2x1Asn4G6C-zNL6t-w-NViCQP2F5MZiXZ5Yri5Y8OSfLvSnNxlpnmyfMwBrqMXHMSdmBB0bI7LIN6NfjFqIZvoAbRF',
  'PWR-LM-2596':
    'https://lh3.googleusercontent.com/aida-public/AB6AXuCsL-DvxrSEwrqr8bmuyfINzqEg7lvNAXP5yj3RQEGlfjzLAQr20_du_6aZyGAHImOV5sEhSMdXntke4bZUTv-3XtWHl1NC-gUhCIuXtyymIU8ySmqWqpdBcV_ucSZpG1xHg35n22V3U4vBFZpVLuqJL9JW_yngRyAI4FCJhlv6ZBazq_yekr5GAQCGaNKwnbW0JChxrEKtLhKeigq11Pyss-pWjxckjVyYcx8M2-h8GdDy3KCoIgUf',
  'SEN-DHT-22':
    'https://lh3.googleusercontent.com/aida-public/AB6AXuCLhXO1pOPLztRCbbOiiKK3PbqQRwGaCRPb5TBXHhPbIZXd75Zk6erRiHRipxkqFIH2_K2V_ZoAheoZsm3QgwMKFBQM39BL8R_gW_NWcMc4IC9QbUxDhlnxvRqQCilZejwuZOO7UohZk8EOySnPYBLxbVAGHrbmNRNMn_Yhn_vCE3rMUP4RJE9sDeAnMsHzBybvkNUeOcBxczLClGmWOSj798as2ArCwWwA7JDzmtCvlrjHF2JvhIMv',
  'MOD-RLY-4CH':
    'https://lh3.googleusercontent.com/aida-public/AB6AXuAlue1QWOPut50HJxfUSiJkK4z6gWj-5CC-ByJlhMV3tKEcjd10RVGOMNV98koiPdz_GC7-nP_gZ2gSkHLTnPOukdVjcmaLLhPMTs74yPJ-B-ZPpw7cXZADNVvAYHk5fqq5FBTj_Z3cp_2H36wc0ztOSCTXHf6r4WWwebDW3T3PO7o6fw-_WxrlblqRq_Gb-owG1DVoVptr06NOiKdbBs4xpWp0C90BDolb39LKK7RJ0Rt0443_6oZ6',
};

// Global Application State
let appState = {
  currentCategory: 'all',
  currentSearch: '',
  currentSort: '',
  cart: { total_items: 0, total_price: 0, items: [] },
  defense: {},
  currentUser: null,
  serverStatus: { online: false, rttMs: null },
  activeLabSimState: 'normal', // 'normal', 'syn', 'rst', 'arp'
};

// ------------------------------------------------------------------------------
// 1. HTTP API WRAPPER & WIRE LOGGING
// ------------------------------------------------------------------------------
function getSessionId() {
  let sid = localStorage.getItem('es_session_id');
  if (!sid || sid === 'demo-guest-session-pbl4') {
    sid = 'guest-' + Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem('es_session_id', sid);
  }
  return sid;
}

function getAuthToken() {
  return localStorage.getItem('es_access_token');
}

/**
 * Universal API Fetcher with Automatic Wire Logging & Error Tracking
 */
async function apiFetch(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
  const method = options.method || 'GET';
  const headers = {
    'Accept': 'application/json, text/plain, */*',
    'x-session-id': getSessionId(),
    ...(options.headers || {}),
  };

  const token = getAuthToken();
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const startTime = performance.now();
  let status = 0;
  let responseData = null;
  let isError = false;

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(8000), ...options, headers });
    status = res.status;
    const duration = Math.round(performance.now() - startTime);

    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      responseData = await res.json();
    } else {
      responseData = await res.text();
    }

    logWirePacket(method, endpoint, status, duration, options.body, responseData);

    if (!res.ok) {
      isError = true;
      const errorMsg =
        (responseData && responseData.message) ||
        (responseData && responseData.error) ||
        `HTTP ${status}`;
      return { ok: false, status, data: responseData, error: errorMsg };
    }

    return { ok: true, status, data: responseData };
  } catch (err) {
    const duration = Math.round(performance.now() - startTime);
    logWirePacket(method, endpoint, 'NET_ERR', duration, options.body, err.message);
    return { ok: false, status: 0, error: err.message };
  }
}

/**
 * Appends formatted HTTP packets to the Lab Drawer Wire Log
 */
function escapeText(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
}
function logWirePacket(method, endpoint, status, durationMs, reqBody, resData) {
  const wireBox = document.getElementById('drawer-wire-box');
  if (!wireBox) return;

  const now = new Date().toLocaleTimeString('vi-VN', { hour12: false });
  let statusColor = 'text-emerald-400';
  if (status === 429) statusColor = 'text-amber-400';
  else if (status >= 400 || status === 'NET_ERR') statusColor = 'text-rose-400';

  const entry = document.createElement('div');
  entry.className = 'py-1 border-b border-slate-800/60 font-mono text-[11px] leading-tight';

  const cleanEndpoint = endpoint.replace(/^http:\/\/[^/]+/, '');
  let preview = '';
  if (resData && typeof resData === 'object') {
    preview = resData.message || (resData.status ? `status: ${resData.status}` : '');
  }

  entry.innerHTML = `
    <div class="flex items-center justify-between">
      <span class="${statusColor} font-semibold">${escapeText(method)} ${escapeText(cleanEndpoint)}</span>
      <span class="text-slate-500 text-[10px]">${durationMs}ms [${now}]</span>
    </div>
    <div class="text-slate-400 text-[10px] flex items-center justify-between mt-0.5">
      <span>Status: <strong class="${statusColor}">${status}</strong></span>
      <span class="truncate max-w-[180px] text-slate-500">${escapeText(preview)}</span>
    </div>
  `;

  // Prepend to top and limit to 20 entries
  wireBox.insertBefore(entry, wireBox.firstChild);
  while (wireBox.children.length > 20) {
    wireBox.removeChild(wireBox.lastChild);
  }
}

// ------------------------------------------------------------------------------
// 2. PRODUCTS & CATEGORIES CONTROLLER
// ------------------------------------------------------------------------------
async function fetchCategories() {
  const res = await apiFetch('/products/categories');
  if (!res.ok || !res.data) return;

  const categories = res.data.data?.categories || [];
  const container = document.getElementById('filter-container');
  if (!container) return;

  const totalCount = res.data.data?.total_products ?? categories.reduce((sum, c) => sum + (c.count || 0), 0);

  let html = `
    <button
      class="category-pill ${appState.currentCategory === 'all' ? 'active-pill bg-slate-900 text-white' : 'bg-slate-100 text-slate-600'} px-4 py-1.5 rounded-full text-[13px] font-medium shadow-xs transition-all whitespace-nowrap"
      onclick="filterItems('all', this)">
      Tất cả (${totalCount})
    </button>
  `;

  categories.forEach((cat) => {
    const isActive = appState.currentCategory === cat.slug;
    html += `
      <button
        class="category-pill ${isActive ? 'active-pill bg-slate-900 text-white' : 'bg-slate-100 text-slate-600'} px-4 py-1.5 rounded-full text-[13px] font-medium hover:text-slate-900 hover:bg-slate-200 transition-all whitespace-nowrap"
        onclick="filterItems('${cat.slug}', this)">
        ${cat.name} (${cat.count || 0})
      </button>
    `;
  });

  container.innerHTML = html;
}

async function fetchProducts() {
  const grid = document.getElementById('product-grid');
  if (!grid) return;

  // Render loading skeleton
  grid.innerHTML = Array(6)
    .fill(0)
    .map(
      () => `
      <div class="bg-white rounded-2xl border border-slate-200/60 p-5 animate-pulse space-y-4">
        <div class="w-full aspect-[4/3] bg-slate-100 rounded-xl"></div>
        <div class="h-4 bg-slate-100 rounded w-1/3"></div>
        <div class="h-5 bg-slate-100 rounded w-3/4"></div>
        <div class="h-4 bg-slate-100 rounded w-full"></div>
        <div class="h-10 bg-slate-100 rounded-xl"></div>
      </div>
    `,
    )
    .join('');

  const params = new URLSearchParams();
  if (appState.currentCategory && appState.currentCategory !== 'all') {
    params.set('category', appState.currentCategory);
  }
  if (appState.currentSearch.trim()) {
    params.set('search', appState.currentSearch.trim());
  }
  if (appState.currentSort) {
    params.set('sort', appState.currentSort);
  }

  const queryStr = params.toString() ? `?${params.toString()}` : '';
  const res = await apiFetch(`/products${queryStr}`);

  if (!res.ok || !res.data) {
    grid.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-500">
        <span class="material-symbols-outlined text-4xl text-rose-400 mb-2">cloud_off</span>
        <p class="font-medium text-slate-700">Không thể kết nối đến Target Server</p>
        <p class="text-[12px] text-slate-500 mt-1">Đảm bảo Backend đang chạy tại: ${API_BASE}</p>
      </div>
    `;
    return;
  }

  const products = res.data.data || [];
  if (products.length === 0) {
    grid.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-500">
        <span class="material-symbols-outlined text-4xl text-slate-300 mb-2">search_off</span>
        <p class="font-medium text-slate-700">Không tìm thấy linh kiện phù hợp</p>
        <p class="text-[12px] text-slate-500 mt-1">Thử đổi từ khóa tìm kiếm hoặc chọn danh mục khác</p>
      </div>
    `;
    return;
  }

  grid.innerHTML = products
    .map((prod) => {
      const imgSrc = PRODUCT_IMAGES[prod.sku] || prod.image_url || 'https://placehold.co/400x300';
      const formattedPrice = new Intl.NumberFormat('vi-VN').format(prod.price) + ' ₫';
      const specs = Array.isArray(prod.specs) ? prod.specs : [];

      return `
      <article
        class="product-item group bg-white rounded-2xl border border-slate-200/70 p-5 flex flex-col justify-between hover:shadow-xl hover:border-slate-300 transition-all duration-300"
        data-id="${prod.id}"
        data-cat="${prod.category_slug}">
        <div>
          <!-- Thumbnail Container -->
          <div class="relative w-full aspect-[4/3] rounded-xl overflow-hidden bg-slate-50 mb-5 flex items-center justify-center">
            <img alt="${prod.name}"
              class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500 ease-out"
              src="${imgSrc}" onerror="this.onerror=null;this.src='/assets/product-placeholder.svg'">
            <div class="absolute top-3 left-3 flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/90 backdrop-blur-md border border-slate-200/50 text-[11px] font-medium text-slate-700 shadow-2xs">
              <span class="w-1.5 h-1.5 rounded-full ${prod.stock > 0 ? 'bg-emerald-500' : 'bg-rose-500'}"></span>
              <span>${prod.stock > 0 ? `Sẵn hàng (${prod.stock})` : 'Tạm hết'}</span>
            </div>
            <div class="absolute top-3 right-3 px-2 py-0.5 rounded-md bg-white/80 font-mono text-[10px] text-slate-500 font-semibold border border-slate-200/40">
              ${prod.sku}
            </div>
          </div>
          <!-- Product Details -->
          <div class="space-y-2">
            <span class="text-[12px] font-medium text-slate-500 block">${prod.brand}</span>
            <h3 class="text-[17px] font-semibold text-slate-900 group-hover:text-brand-600 transition-colors leading-snug">
              ${prod.name}
            </h3>
            <p class="text-[13px] text-slate-600 line-clamp-2 leading-relaxed">
              ${prod.description}
            </p>
            <!-- Technical Specs Tags -->
            <div class="flex flex-wrap gap-1.5 pt-1.5">
              ${specs.map((s) => `<span class="px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 font-mono text-[11px]">${s}</span>`).join('')}
            </div>
          </div>
        </div>
        <!-- Card Footer -->
        <div class="pt-5 mt-5 border-t border-slate-100 flex items-center justify-between gap-3">
          <div>
            <span class="block text-[11px] text-slate-500 uppercase font-medium">Giá bán lẻ</span>
            <span class="text-[18px] font-bold text-slate-900">${formattedPrice}</span>
          </div>
          <button
            class="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 active:scale-95 text-white text-[13px] font-semibold transition-all shadow-2xs"
            onclick="handleAddToCart(${prod.id}, '${prod.name.replace(/'/g, "\\'")}', ${prod.price})">
            <span class="material-symbols-outlined text-[17px]">add_shopping_cart</span>
            <span>Thêm giỏ</span>
          </button>
        </div>
      </article>
    `;
    })
    .join('');
}

function filterItems(category, btnElement) {
  appState.currentCategory = category;
  document.querySelectorAll('.category-pill').forEach((btn) => {
    btn.classList.remove('bg-slate-900', 'text-white', 'shadow-xs', 'active-pill');
    btn.classList.add('bg-slate-100', 'text-slate-600');
  });
  if (btnElement) {
    btnElement.classList.remove('bg-slate-100', 'text-slate-600');
    btnElement.classList.add('bg-slate-900', 'text-white', 'shadow-xs', 'active-pill');
  }
  fetchProducts();
}

let searchDebounceTimer = null;
function handleSearchInput(value) {
  appState.currentSearch = value;
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    fetchProducts();
  }, 300);
}

function handleSortChange(sortValue) {
  appState.currentSort = sortValue;
  fetchProducts();
}

// ------------------------------------------------------------------------------
// 3. CART API OPERATIONS & CART DRAWER
// ------------------------------------------------------------------------------
async function fetchCart() {
  const res = await apiFetch('/cart');
  if (res.ok && res.data && res.data.data) {
    appState.cart = res.data.data;
    updateCartBadge(appState.cart.total_items || 0);
  }
}

function updateCartBadge(count) {
  const badge = document.getElementById('header-cart-count');
  if (badge) badge.textContent = count;
}

async function handleAddToCart(productId, name, price) {
  // Check for simulated SYN Flood error
  if (appState.activeLabSimState === 'syn') {
    showToast('Lỗi 504 Gateway Timeout', 'Không thể thêm sản phẩm: Máy chủ đang bị tấn công SYN Flood');
    return;
  }

  const res = await apiFetch('/cart', {
    method: 'POST',
    body: { productId, quantity: 1 },
  });

  if (res.ok && res.data && res.data.data) {
    appState.cart = res.data.data;
    updateCartBadge(appState.cart.total_items || 0);
    const formatted = new Intl.NumberFormat('vi-VN').format(price) + ' ₫';
    showToast('Đã thêm vào giỏ hàng', `${name} • ${formatted}`);
  } else if (res.status === 429) {
    showToast('429 Too Many Requests', 'Khiên Rate Limit L3 chặn thao tác quá nhanh');
  } else {
    showToast('Không thể thêm sản phẩm', res.error || 'Lỗi kết nối máy chủ');
  }
}

async function updateCartItemQuantity(itemId, quantity) {
  if (quantity < 1) {
    return removeCartItem(itemId);
  }
  const res = await apiFetch(`/cart/items/${itemId}`, {
    method: 'PATCH',
    body: { quantity },
  });
  if (res.ok && res.data && res.data.data) {
    appState.cart = res.data.data;
    updateCartBadge(appState.cart.total_items || 0);
    renderCartModal();
  }
}

async function removeCartItem(itemId) {
  const res = await apiFetch(`/cart/items/${itemId}`, { method: 'DELETE' });
  if (res.ok && res.data && res.data.data) {
    appState.cart = res.data.data;
    updateCartBadge(appState.cart.total_items || 0);
    renderCartModal();
    showToast('Đã xóa linh kiện', 'Đã cập nhật lại giỏ hàng');
  }
}

async function clearEntireCart() {
  const res = await apiFetch('/cart', { method: 'DELETE' });
  if (res.ok) {
    appState.cart = { total_items: 0, total_price: 0, items: [] };
    updateCartBadge(0);
    renderCartModal();
    showToast('Đã làm trống giỏ hàng', 'Toàn bộ linh kiện đã được xóa');
  }
}

function openCartModal() {
  renderCartModal();
  const modal = document.getElementById('cart-modal');
  const card = document.getElementById('cart-modal-card');
  if (modal && card) {
    modal.classList.remove('opacity-0', 'pointer-events-none');
    card.classList.remove('translate-x-full');
  }
}

function closeCartModal() {
  const modal = document.getElementById('cart-modal');
  const card = document.getElementById('cart-modal-card');
  if (modal && card) {
    card.classList.add('translate-x-full');
    modal.classList.add('opacity-0', 'pointer-events-none');
  }
}

function renderCartModal() {
  const container = document.getElementById('cart-items-container');
  const totalElem = document.getElementById('cart-total-price');
  if (!container || !totalElem) return;

  const items = appState.cart.items || [];
  totalElem.textContent = new Intl.NumberFormat('vi-VN').format(appState.cart.total_price || 0) + ' ₫';

  if (items.length === 0) {
    container.innerHTML = `
      <div class="py-16 text-center text-slate-500">
        <span class="material-symbols-outlined text-4xl text-slate-300 mb-2">shopping_bag</span>
        <p class="font-medium text-slate-700">Giỏ hàng đang trống</p>
        <p class="text-[12px] text-slate-500 mt-1">Chọn linh kiện từ danh mục để bắt đầu</p>
      </div>
    `;
    return;
  }

  container.innerHTML = items
    .map((item) => {
      const imgSrc = PRODUCT_IMAGES[item.sku] || item.image_url || 'https://placehold.co/100x100';
      const formattedSubtotal = new Intl.NumberFormat('vi-VN').format(item.subtotal) + ' ₫';

      return `
      <div class="flex items-center justify-between gap-3 p-3.5 bg-slate-50 rounded-2xl border border-slate-100">
        <div class="w-14 h-14 rounded-xl overflow-hidden bg-white border border-slate-200/60 shrink-0">
          <img src="${imgSrc}" onerror="this.onerror=null;this.src='/assets/product-placeholder.svg'" alt="${item.name}" class="w-full h-full object-cover">
        </div>
        <div class="flex-1 min-w-0">
          <h4 class="text-[13px] font-semibold text-slate-900 truncate">${item.name}</h4>
          <span class="text-[11px] font-mono text-slate-500">${item.sku}</span>
          <div class="text-[13px] font-bold text-slate-900 mt-0.5">${formattedSubtotal}</div>
        </div>
        <div class="flex items-center gap-2">
          <button class="w-7 h-7 rounded-lg bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 flex items-center justify-center font-bold text-sm"
            onclick="updateCartItemQuantity(${item.id}, ${item.quantity - 1})">-</button>
          <span class="font-mono text-xs font-semibold px-1">${item.quantity}</span>
          <button class="w-7 h-7 rounded-lg bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 flex items-center justify-center font-bold text-sm"
            onclick="updateCartItemQuantity(${item.id}, ${item.quantity + 1})">+</button>
          <button class="w-7 h-7 rounded-lg text-rose-500 hover:bg-rose-50 flex items-center justify-center ml-1"
            onclick="removeCartItem(${item.id})">
            <span class="material-symbols-outlined text-[17px]">delete</span>
          </button>
        </div>
      </div>
    `;
    })
    .join('');
}

// ------------------------------------------------------------------------------
// 4. AUTHENTICATION & USER PROFILE CONTROLLER (JWT AUTHORIZATION)
// ------------------------------------------------------------------------------
function openAuthModal() {
  const modal = document.getElementById('auth-modal');
  const card = document.getElementById('auth-modal-card');
  if (modal && card) {
    modal.classList.remove('opacity-0', 'pointer-events-none');
    card.classList.remove('scale-95');
    card.classList.add('scale-100');
  }
}

function closeAuthModal() {
  const modal = document.getElementById('auth-modal');
  const card = document.getElementById('auth-modal-card');
  if (modal && card) {
    card.classList.remove('scale-100');
    card.classList.add('scale-95');
    modal.classList.add('opacity-0', 'pointer-events-none');
  }
}

function toggleUserMenuOrOpenAuth() {
  if (!appState.currentUser) {
    openAuthModal();
    return;
  }
  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown) {
    dropdown.classList.toggle('hidden');
  }
}

// Global click listener to close dropdown when clicking outside
document.addEventListener('click', (e) => {
  const wrapper = document.getElementById('auth-dropdown-wrapper');
  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown && wrapper && !wrapper.contains(e.target)) {
    dropdown.classList.add('hidden');
  }
});

function prefillUser(username, password) {
  const uInput = document.getElementById('modal-username');
  const pInput = document.getElementById('modal-password');
  if (uInput) uInput.value = username;
  if (pInput) pInput.value = password;
  showToast('Đã chọn tài khoản', `Điền thông tin: ${username}`);
}

function prefillSqlPayload() {
  const uInput = document.getElementById('modal-username');
  const pInput = document.getElementById('modal-password');
  if (uInput) uInput.value = "admin' --";
  if (pInput) pInput.value = "any_password_123";
  showToast('Đã điền payload SQLi', "Bấm 'Đăng nhập' để thử nghiệm Auth Bypass");
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('modal-username').value;
  const password = document.getElementById('modal-password').value;

  const res = await apiFetch('/auth/login', {
    method: 'POST',
    body: { username, password },
  });

  if (res.ok && res.data) {
    const payload = res.data;
    localStorage.setItem('es_access_token', payload.access_token);
    localStorage.setItem('es_user', JSON.stringify(payload.user));
    appState.currentUser = payload.user;

    updateHeaderAuthUI();
    closeAuthModal();

    if (payload.warning || payload.sqli_bypassed) {
      showToast('⚠️ SQLi Bypass Thành Công', payload.message || 'Đăng nhập không cần mật khẩu thành công!');
    } else {
      showToast('Đăng nhập thành công', `Chào mừng ${payload.user.fullName || payload.user.username} (JWT 30 ngày)`);
    }

    // Refresh cart with authenticated context
    fetchCart();
  } else if (res.status === 401) {
    showToast(
      '401 Unauthorized',
      appState.defense.l3_master
        ? 'Khiên L3 BẬT: Đã chặn đứng SQL Injection bằng Prepared Statement!'
        : 'Sai tài khoản hoặc mật khẩu',
    );
  } else if (res.status === 429) {
    showToast('429 Rate Limit', 'Gửi request đăng nhập quá nhanh! Khiên Rate Limit đang kích hoạt');
  } else {
    showToast('Lỗi đăng nhập', res.error || 'Không thể đăng nhập');
  }
}

function handleLogout() {
  localStorage.removeItem('es_access_token');
  localStorage.removeItem('es_user');
  appState.currentUser = null;

  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown) dropdown.classList.add('hidden');

  updateHeaderAuthUI();
  showToast('Đã đăng xuất', 'Hẹn gặp lại bạn!');
  fetchCart();
}

function updateHeaderAuthUI() {
  const authBtn = document.getElementById('header-auth-btn');
  const dropdown = document.getElementById('user-dropdown-menu');
  const nameElem = document.getElementById('user-menu-fullname');
  const roleElem = document.getElementById('user-menu-role');
  const avatarElem = document.getElementById('user-avatar-initials');

  if (!authBtn) return;

  if (appState.currentUser) {
    const user = appState.currentUser;
    const initial = (user.username || 'U').charAt(0).toUpperCase();

    authBtn.innerHTML = `
      <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
      <span class="font-semibold text-slate-900">${user.fullName || user.username}</span>
      <span class="px-1.5 py-0.5 rounded-full bg-slate-100 text-[10px] font-mono font-bold text-slate-600 uppercase">${user.role}</span>
      <span class="material-symbols-outlined text-[16px] text-slate-400">expand_more</span>
    `;

    if (nameElem) nameElem.textContent = user.fullName || user.username;
    if (roleElem) roleElem.textContent = `Vai trò: ${user.role} (ID: ${user.id || user.sub})`;
    if (avatarElem) avatarElem.textContent = initial;
  } else {
    if (dropdown) dropdown.classList.add('hidden');
    authBtn.innerHTML = `
      <span class="material-symbols-outlined text-[17px]">person</span>
      <span>Đăng nhập</span>
    `;
  }
}

/**
 * Xử lý thanh toán đơn hàng - BẢO VỆ BỞI JWT TOKEN
 */
async function handleCheckout() {
  // 1. Kiểm tra trạng thái đăng nhập
  if (!appState.currentUser || !getAuthToken()) {
    showToast('🔒 Yêu cầu Đăng nhập', 'Chức năng thanh toán yêu cầu bạn phải đăng nhập để cấp JWT Token!');
    closeCartModal();
    openAuthModal();
    return;
  }

  const items = appState.cart.items || [];
  if (items.length === 0) {
    showToast('Giỏ hàng trống', 'Vui lòng chọn linh kiện trước khi tiến hành thanh toán!');
    return;
  }

  showToast('Đang xử lý', 'Đang gửi yêu cầu xác thực JWT và khởi tạo đơn hàng...');

  const res = await apiFetch('/cart/checkout', {
    method: 'POST',
    body: {
      shippingAddress: 'PBL4 Lab - Đại học Bách Khoa Đà Nẵng, Việt Nam',
    },
  });

  if (res.ok && res.data) {
    const order = res.data.order;
    showToast(
      '🎉 Thanh toán thành công!',
      res.data.message || `Mã đơn: ${order.order_code}`,
    );

    // Xóa sạch giỏ hàng trên UI
    appState.cart = { total_items: 0, total_price: 0, items: [] };
    updateCartBadge(0);
    renderCartModal();
    closeCartModal();

    // Tự động mở xem hóa đơn vừa tạo
    setTimeout(() => {
      openOrdersModal();
    }, 600);
  } else if (res.status === 401) {
    showToast('401 Unauthorized', 'Phiên đăng nhập JWT đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại!');
    handleLogout();
    openAuthModal();
  } else {
    showToast('Lỗi thanh toán', res.error || 'Không thể tạo đơn hàng');
  }
}

/**
 * Mở modal lịch sử đơn hàng của người dùng (Bảo vệ bởi JWT)
 */
async function openOrdersModal() {
  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown) dropdown.classList.add('hidden');

  if (!appState.currentUser || !getAuthToken()) {
    showToast('🔒 Yêu cầu đăng nhập', 'Vui lòng đăng nhập tài khoản để xem lịch sử đơn hàng!');
    openAuthModal();
    return;
  }

  const modal = document.getElementById('orders-modal');
  const card = document.getElementById('orders-modal-card');
  const container = document.getElementById('orders-list-container');
  if (!modal || !card) return;

  modal.classList.remove('opacity-0', 'pointer-events-none');
  card.classList.remove('scale-95');
  card.classList.add('scale-100');

  if (container) {
    container.innerHTML = '<p class="text-center py-6 text-slate-500 font-mono text-xs">Đang tải lịch sử đơn hàng qua JWT Authorization...</p>';

    const res = await apiFetch('/cart/orders');
    if (!res.ok || !res.data) {
      if (res.status === 401) {
        container.innerHTML = '<p class="text-center py-6 text-rose-500 font-mono text-xs">401 Unauthorized: Phiên đăng nhập đã hết hạn.</p>';
      } else {
        container.innerHTML = '<p class="text-center py-6 text-slate-500 font-mono text-xs">Không thể nạp danh sách đơn hàng.</p>';
      }
      return;
    }

    const orders = res.data.data || [];
    if (orders.length === 0) {
      container.innerHTML = `
        <div class="py-12 text-center text-slate-400">
          <span class="material-symbols-outlined text-4xl mb-2 text-slate-300">receipt_long</span>
          <p class="font-medium text-slate-700">Chưa có đơn hàng nào</p>
          <p class="text-[12px] text-slate-500 mt-1">Thêm linh kiện vào giỏ và thanh toán để tạo hóa đơn đầu tiên</p>
        </div>
      `;
      return;
    }

    container.innerHTML = orders
      .map((ord) => {
        const formattedTotal = new Intl.NumberFormat('vi-VN').format(ord.total_amount) + ' ₫';
        const formattedDate = new Date(ord.created_at).toLocaleString('vi-VN');
        const itemsHtml = (ord.items || [])
          .map(
            (i) => `
            <div class="flex items-center justify-between text-[12px] text-slate-600 py-1 border-b border-slate-100 last:border-none">
              <span class="font-medium truncate max-w-[260px]">${i.product_name} <span class="font-mono text-slate-400">x${i.quantity}</span></span>
              <span class="font-mono text-slate-900 font-semibold">${new Intl.NumberFormat('vi-VN').format(i.subtotal)} ₫</span>
            </div>
          `,
          )
          .join('');

        return `
        <div class="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-2.5">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="font-mono font-bold text-slate-900 text-[13px]">${ord.order_code}</span>
              <span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-bold font-mono">HOÀN TẤT</span>
            </div>
            <span class="text-[11px] text-slate-400 font-mono">${formattedDate}</span>
          </div>
          <div class="bg-white p-2.5 rounded-xl border border-slate-100">
            ${itemsHtml}
          </div>
          <div class="flex items-center justify-between pt-1 text-[13px]">
            <span class="text-slate-500">Tổng thanh toán:</span>
            <span class="font-bold text-slate-900 text-[15px] font-mono">${formattedTotal}</span>
          </div>
        </div>
      `;
      })
      .join('');
  }
}

function closeOrdersModal() {
  const modal = document.getElementById('orders-modal');
  const card = document.getElementById('orders-modal-card');
  if (modal && card) {
    card.classList.remove('scale-100');
    card.classList.add('scale-95');
    modal.classList.add('opacity-0', 'pointer-events-none');
  }
}

// ------------------------------------------------------------------------------
// 5. DEFENSE CONTROL (LAYER 3 MASTER & SHIELDS)
// ------------------------------------------------------------------------------
let defenseQueue = Promise.resolve();
let defensePollPending = false;
function defenseRequest(endpoint, options) {
  const request = defenseQueue.then(() => apiFetch(endpoint, options));
  defenseQueue = request.catch(() => undefined);
  return request;
}
async function fetchDefenseStatus() {
  if (defensePollPending) return;
  defensePollPending = true;
  const res = await defenseRequest('/defense/status');
  defensePollPending = false;
  if (res.ok && res.data && res.data.flags) {
    appState.defense = res.data.flags;
  } else {
    appState.defense = {};
  }
  renderDefenseStatusUI();
}

async function toggleMasterDefense() {
  const res = await defenseRequest('/defense/toggle', { method: 'POST', body: {} });
  if (res.ok && res.data) {
    appState.defense = res.data.current_state;
    renderDefenseStatusUI();
    const msg = appState.defense.l3_master ? 'BẬT (SECURED)' : 'TẮT (VULNERABLE)';
    showToast('Đảo Khiên L3 Master', `Trạng thái hiện tại: ${msg}`);
  } else {
    appState.defense = {};
    renderDefenseStatusUI();
    showToast('Không đổi được khiên', 'Kiểm tra kết nối Target rồi thử lại.');
  }
}

async function toggleSubShield(flagKey) {
  const res = await defenseRequest('/defense/toggle', {
    method: 'POST',
    body: { flag: flagKey },
  });
  if (res.ok && res.data) {
    appState.defense = res.data.current_state;
    renderDefenseStatusUI();
    showToast(`Khiên [${flagKey}]`, `Đã đổi thành: ${appState.defense[flagKey] ? 'BẬT' : 'TẮT'}`);
  } else {
    appState.defense = {};
    renderDefenseStatusUI();
  }
}

function renderDefenseStatusUI() {
  const badge = document.getElementById('fab-state-badge');
  const masterBtn = document.getElementById('defense-master-toggle-btn');
  const sqliPill = document.getElementById('defense-flag-sqli');
  const ratePill = document.getElementById('defense-flag-rate');
  const sanitPill = document.getElementById('defense-flag-sanit');

  const isMasterOn = appState.defense.l3_master;
  if (typeof isMasterOn !== 'boolean') {
    if (badge) badge.textContent = 'L3: CHƯA XÁC NHẬN';
    if (masterBtn) masterBtn.textContent = 'Chưa kết nối được Target — thử lại';
    for (const pill of [sqliPill, ratePill, sanitPill]) {
      if (pill) pill.textContent = 'UNKNOWN';
    }
    return;
  }

  if (badge) {
    badge.textContent = isMasterOn ? 'L3 ON (BẢO VỆ)' : 'L3 OFF (LỖ HỔNG)';
    badge.className = isMasterOn
      ? 'bg-emerald-950 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-800'
      : 'bg-rose-950 text-rose-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-rose-800';
  }

  if (masterBtn) {
    masterBtn.innerHTML = `
      <div class="flex items-center gap-2">
        <span class="w-2.5 h-2.5 rounded-full ${isMasterOn ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}"></span>
        <span class="font-semibold text-[13px]">${isMasterOn ? 'KHIÊN L3: ĐANG BẬT (SECURED)' : 'KHIÊN L3: ĐANG TẮT (VULNERABLE)'}</span>
      </div>
      <span class="material-symbols-outlined text-[18px]">${isMasterOn ? 'shield' : 'shield_with_heart'}</span>
    `;
    masterBtn.className = isMasterOn
      ? 'w-full p-3 rounded-xl border flex items-center justify-between transition-all bg-emerald-950/40 border-emerald-500/50 text-emerald-300 hover:bg-emerald-950/60'
      : 'w-full p-3 rounded-xl border flex items-center justify-between transition-all bg-rose-950/40 border-rose-500/50 text-rose-300 hover:bg-rose-950/60';
  }

  const updateSubPill = (elem, isOn, label) => {
    if (!elem) return;
    elem.className = `px-2.5 py-1 rounded-lg font-mono text-[11px] font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
      isOn
        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
        : 'bg-slate-800 text-slate-400 border border-slate-700'
    }`;
    elem.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${isOn ? 'bg-emerald-400' : 'bg-slate-500'}"></span> ${label}: ${isOn ? 'ON' : 'OFF'}`;
  };

  updateSubPill(sqliPill, appState.defense.anti_sqli, 'Anti-SQLi');
  updateSubPill(ratePill, appState.defense.rate_limit, 'Rate Limit');
  updateSubPill(sanitPill, appState.defense.input_sanitization, 'Sanitize');
}

// ------------------------------------------------------------------------------
// 6. TECHNICAL DOCUMENTS MODAL & EXFILTRATION LAB
// ------------------------------------------------------------------------------
async function openDocumentsModal() {
  const modal = document.getElementById('documents-modal');
  const card = document.getElementById('documents-modal-card');
  if (!modal || !card) return;

  modal.classList.remove('opacity-0', 'pointer-events-none');
  card.classList.remove('scale-95');
  card.classList.add('scale-100');

  const container = document.getElementById('documents-list-container');
  if (container) {
    container.innerHTML = '<p class="text-center py-6 text-slate-500 font-mono text-xs">Đang tải danh sách tài liệu kỹ thuật...</p>';
    const res = await apiFetch('/documents?include_confidential=true');

    if (!res.ok || !res.data) {
      container.innerHTML = '<p class="text-center py-6 text-rose-500 font-mono text-xs">Không thể nạp danh sách tài liệu.</p>';
      return;
    }

    const docs = res.data.data || [];
    container.innerHTML = docs
      .map((doc) => {
        const isConf = doc.is_confidential;
        return `
        <div class="p-3.5 rounded-2xl border ${
          isConf
            ? 'bg-rose-50/70 border-rose-200 text-rose-950'
            : 'bg-slate-50 border-slate-200/80 text-slate-800'
        } flex items-center justify-between gap-3">
          <div class="flex items-start gap-3">
            <div class="w-9 h-9 rounded-xl ${
              isConf ? 'bg-rose-600 text-white' : 'bg-slate-900 text-white'
            } flex items-center justify-center shrink-0">
              <span class="material-symbols-outlined text-[19px]">${isConf ? 'lock' : 'description'}</span>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <h4 class="text-[13px] font-semibold">${doc.title}</h4>
                ${
                  isConf
                    ? '<span class="px-1.5 py-0.5 rounded bg-rose-200 text-rose-800 font-mono text-[9px] font-bold">TUYỆT MẬT</span>'
                    : ''
                }
              </div>
              <p class="text-[11px] text-slate-500 font-mono mt-0.5">${doc.file_name} • ${doc.file_size_kb} KB</p>
            </div>
          </div>
          <button
            class="px-3 py-1.5 rounded-xl ${
              isConf
                ? 'bg-rose-600 hover:bg-rose-700 text-white'
                : 'bg-slate-900 hover:bg-slate-800 text-white'
            } text-[12px] font-medium transition-all shadow-2xs flex items-center gap-1 shrink-0"
            onclick="downloadDocument(${doc.id}, ${isConf})">
            <span class="material-symbols-outlined text-[15px]">download</span>
            <span>Tải về</span>
          </button>
        </div>
      `;
      })
      .join('');
  }
}

function closeDocumentsModal() {
  const modal = document.getElementById('documents-modal');
  const card = document.getElementById('documents-modal-card');
  if (modal && card) {
    card.classList.remove('scale-100');
    card.classList.add('scale-95');
    modal.classList.add('opacity-0', 'pointer-events-none');
  }
}

async function downloadDocument(id, isConfidential) {
  // Đối với tài liệu mật: Bắt buộc kỹ sư phải đăng nhập tài khoản trước
  if (isConfidential && !appState.currentUser) {
    showToast('🔒 Yêu cầu Đăng nhập', 'Tài liệu tuyệt mật R&D yêu cầu đăng nhập tài khoản và xác thực JWT!');
    openAuthModal();
    return;
  }

  const downloadUrl = `${API_BASE}/documents/${id}/download`;

  if (isConfidential && appState.defense.l3_master) {
    showToast('403 Forbidden', 'Khiên L3 BẬT: Đã chặn hành vi rò rỉ bản thiết kế tuyệt mật!');
    apiFetch(`/documents/${id}/download`);
    return;
  }

  if (isConfidential && !appState.defense.l3_master) {
    showToast('⚠️ RÒ RỈ DỮ LIỆU THÀNH CÔNG', 'Khiên L3 TẮT: Đã tải được bản thiết kế mật kèm Flag!');
  }

  // Open direct download stream
  window.open(downloadUrl, '_blank');
}

// ------------------------------------------------------------------------------
// 7. LAB ATTACK SCENARIOS & SYSTEM HEALTH
// ------------------------------------------------------------------------------
async function runAttackScenario(type) {
  if (type === 'sqli') {
    closeLabDrawer();
    openAuthModal();
    prefillSqlPayload();
  } else if (type === 'dos') {
    showToast('Bắt đầu thử nghiệm L7 DoS', 'Đang gửi 15 request CPU-heavy dồn dập...');
    for (let i = 1; i <= 15; i++) {
      apiFetch('/reports/analytics?iterations=50000').then((res) => {
        if (res.status === 429) {
          showToast('429 Too Many Requests', `Request #${i}: Bị Rate Limiting chặn đứng an toàn!`);
        }
      });
    }
  } else if (type === 'path_traversal') {
    showToast('Thử nghiệm Path Traversal', "Đang gửi payload: ?name=../../etc/passwd");
    const res = await apiFetch('/files/download?name=../../etc/passwd');
    if (res.status === 400) {
      showToast('400 Bad Request', 'Khiên L3 BẬT: Đã chặn ký tự điều hướng bất hợp pháp!');
    } else if (res.ok) {
      showToast('⚠️ Path Traversal Thành Công', 'Khiên L3 TẮT: Đã đọc được file hệ thống!');
    }
  } else if (type === 'blueprint') {
    downloadDocument(5, true);
  }
}

async function checkSystemHealthAndPing() {
  const t0 = Date.now();
  const res = await apiFetch(`/system/ping?t=${t0}`);

  const nodeStatusElem = document.getElementById('drawer-node-status');
  const rttElem = document.getElementById('drawer-rtt-ms');
  const baseElem = document.getElementById('drawer-api-base');

  if (baseElem) baseElem.textContent = API_BASE;

  if (res.ok) {
    appState.serverStatus.online = true;
    appState.serverStatus.rttMs = Date.now() - t0;

    if (nodeStatusElem) {
      nodeStatusElem.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Online`;
      nodeStatusElem.className = 'text-emerald-400 flex items-center gap-1';
    }
    if (rttElem) rttElem.textContent = `RTT: ${appState.serverStatus.rttMs}ms`;
  } else {
    appState.serverStatus.online = false;
    if (nodeStatusElem) {
      nodeStatusElem.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-rose-400"></span> Offline`;
      nodeStatusElem.className = 'text-rose-400 flex items-center gap-1';
    }
    if (rttElem) rttElem.textContent = 'RTT: --';
  }
}

// ------------------------------------------------------------------------------
// 8. DRAWER & UI HELPERS
// ------------------------------------------------------------------------------
function toggleLabDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (drawer && backdrop) {
    const isClosed = drawer.classList.contains('translate-x-full');
    if (isClosed) {
      drawer.classList.remove('translate-x-full');
      backdrop.classList.remove('opacity-0', 'pointer-events-none');
    } else {
      drawer.classList.add('translate-x-full');
      backdrop.classList.add('opacity-0', 'pointer-events-none');
    }
  }
}

function openLabDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (drawer && backdrop) {
    drawer.classList.remove('translate-x-full');
    backdrop.classList.remove('opacity-0', 'pointer-events-none');
  }
}

function closeLabDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (drawer && backdrop) {
    drawer.classList.add('translate-x-full');
    backdrop.classList.add('opacity-0', 'pointer-events-none');
  }
}

function setLabSimState(state) {
  appState.activeLabSimState = state;
  const badge = document.getElementById('fab-state-badge');
  if (state === 'normal') {
    badge.textContent = '200 OK';
    badge.className = 'bg-slate-800 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-slate-700';
    showToast('Trạng thái bình thường', 'HTTP/1.1 thông suốt');
  } else if (state === 'syn') {
    badge.textContent = '504 SYN Flood';
    badge.className = 'bg-rose-950 text-rose-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-rose-800';
    showToast('Kích hoạt SYN Flood', 'Socket queue bão hòa (504 Gateway Timeout)');
  }
}

let toastTimer = null;
function showToast(title, subtitle) {
  const toast = document.getElementById('quick-toast');
  const tTitle = document.getElementById('toast-title');
  const tSub = document.getElementById('toast-subtitle');
  if (!toast || !tTitle || !tSub) return;

  tTitle.textContent = title;
  tSub.textContent = subtitle;

  toast.classList.remove('-translate-y-20', 'opacity-0', 'pointer-events-none');
  toast.classList.add('translate-y-0', 'opacity-100');

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('translate-y-0', 'opacity-100');
    toast.classList.add('-translate-y-20', 'opacity-0', 'pointer-events-none');
  }, 3200);
}

// ------------------------------------------------------------------------------
// 9. APP INITIALIZATION ON DOM READY
// ------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // 1. Kiểm tra JWT Token lưu trong localStorage & Xác thực tức thì với /api/auth/profile
  const token = localStorage.getItem('es_access_token');
  if (token) {
    try {
      const cachedUser = localStorage.getItem('es_user');
      if (cachedUser) {
        appState.currentUser = JSON.parse(cachedUser);
        updateHeaderAuthUI();
      }
    } catch {}

    // Gọi API /auth/profile để kiểm tra token còn hạn hay đã bị thu hồi
    apiFetch('/auth/profile').then((res) => {
      if (res.ok && res.data && res.data.user) {
        appState.currentUser = res.data.user;
        localStorage.setItem('es_user', JSON.stringify(res.data.user));
        updateHeaderAuthUI();
      } else if (res.status === 401) {
        // Token không hợp lệ hoặc đã hết hạn -> Tự động dọn dẹp session
        localStorage.removeItem('es_access_token');
        localStorage.removeItem('es_user');
        appState.currentUser = null;
        updateHeaderAuthUI();
        showToast('Phiên hết hạn', 'Phiên làm việc trước đó đã hết hạn, vui lòng đăng nhập lại.');
      }
    });
  } else {
    updateHeaderAuthUI();
  }

  checkSystemHealthAndPing();
  fetchDefenseStatus();
  fetchCategories();
  fetchProducts();
  fetchCart();

  // Periodic ping health check every 10s
  setInterval(checkSystemHealthAndPing, 10000);
  setInterval(fetchDefenseStatus, 2000);
});
