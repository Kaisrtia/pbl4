// ==============================================================================
// ElectroShop - UI Controller & Lab State Management
// ==============================================================================

// State management
let cartTotalCount = 2;
let currentLabState = 'normal'; // 'normal', 'syn', 'rst', 'arp'

// Category Filter controller
function filterItems(category, btnElement) {
  document.querySelectorAll('.category-pill').forEach((btn) => {
    btn.classList.remove('bg-slate-900', 'text-white', 'shadow-xs');
    btn.classList.add('bg-slate-100', 'text-slate-600');
  });
  btnElement.classList.remove('bg-slate-100', 'text-slate-600');
  btnElement.classList.add('bg-slate-900', 'text-white', 'shadow-xs');

  const items = document.querySelectorAll('.product-item');
  items.forEach((item) => {
    if (category === 'all' || item.getAttribute('data-cat') === category) {
      item.classList.remove('hidden');
    } else {
      item.classList.add('hidden');
    }
  });
}

// Auth Modal Handlers
function openAuthModal() {
  const modal = document.getElementById('auth-modal');
  const card = document.getElementById('auth-modal-card');
  modal.classList.remove('opacity-0', 'pointer-events-none');
  card.classList.remove('scale-95');
  card.classList.add('scale-100');
}

function closeAuthModal() {
  const modal = document.getElementById('auth-modal');
  const card = document.getElementById('auth-modal-card');
  card.classList.remove('scale-100');
  card.classList.add('scale-95');
  modal.classList.add('opacity-0', 'pointer-events-none');
}

function prefillSqlPayload() {
  document.getElementById('modal-username').value = "admin' OR 1=1 --";
  document.getElementById('modal-password').value = 'arbitrary_secret';
  showToast('Đã điền payload SQLi', 'Bấm Đăng nhập để mô phỏng Auth Bypass');
}

function handleAuthSubmit(e) {
  e.preventDefault();
  const user = document.getElementById('modal-username').value;
  const wireBox = document.getElementById('drawer-wire-box');

  if (currentLabState === 'syn') {
    showToast('504 Gateway Timeout', 'Target server không phản hồi do SYN flood');
    if (wireBox) {
      wireBox.innerHTML = `
        <p class="text-rose-400">> POST /api/v1/auth/login [SYN SENT]</p>
        <p class="text-rose-400">Error: 504 Gateway Timeout (Backlog full)</p>
      `;
    }
    return;
  }

  if (currentLabState === 'rst') {
    showToast('ERR_CONNECTION_RESET', 'Gói tin RST đã ép đóng phiên TCP');
    if (wireBox) {
      wireBox.innerHTML = `
        <p class="text-amber-400">> POST /api/v1/auth/login [RST RECEIVED]</p>
        <p class="text-amber-400">Error: ECONNRESET by peer on port 8080</p>
      `;
    }
    return;
  }

  // Normal or MITM
  showToast('Đăng nhập thành công', `Chào mừng quay trở lại: ${user}`);
  closeAuthModal();

  if (wireBox) {
    wireBox.innerHTML = `
      <p class="text-emerald-400">> POST /api/v1/auth/login HTTP/1.1</p>
      <p class="text-slate-400">Host: 172.20.0.20:8080</p>
      <p class="text-slate-300">Payload: user=${encodeURIComponent(user)}&remember=true</p>
      <p class="text-emerald-400">Status: 200 OK (Cookie: es_session_id=usr_8821_plain)</p>
    `;
  }
}

// Lab Drawer Handlers
function toggleLabDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const isClosed = drawer.classList.contains('translate-x-full');

  if (isClosed) {
    openLabDrawer();
  } else {
    closeLabDrawer();
  }
}

function openLabDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  drawer.classList.remove('translate-x-full');
  backdrop.classList.remove('opacity-0', 'pointer-events-none');
}

function closeLabDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  drawer.classList.add('translate-x-full');
  backdrop.classList.add('opacity-0', 'pointer-events-none');
}

function setLabState(state) {
  currentLabState = state;
  const fabBadge = document.getElementById('fab-state-badge');
  const wireBox = document.getElementById('drawer-wire-box');

  // Reset all buttons
  document.querySelectorAll('.lab-toggle-btn').forEach((btn) => {
    btn.className =
      'lab-toggle-btn w-full p-3 rounded-xl border border-slate-800 hover:border-slate-700 bg-slate-950/40 text-slate-300 text-left flex items-center justify-between transition-all';
    const icon = btn.querySelector('.material-symbols-outlined');
    if (icon) icon.className = 'material-symbols-outlined text-[18px] text-slate-600';
  });

  const activeBtn = document.getElementById('state-btn-' + state);

  if (state === 'normal') {
    fabBadge.textContent = '200 OK';
    fabBadge.className =
      'bg-slate-800 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-slate-700';
    if (activeBtn) {
      activeBtn.className =
        'lab-toggle-btn w-full p-3 rounded-xl border text-left flex items-center justify-between transition-all bg-emerald-950/30 border-emerald-500/40 text-emerald-300';
      activeBtn.querySelector('.material-symbols-outlined').className =
        'material-symbols-outlined text-[18px] text-emerald-400';
    }
    if (wireBox) {
      wireBox.innerHTML = `
        <p class="text-emerald-400">> TCP 3-Way Handshake SYN -> SYN/ACK -> ACK [OK]</p>
        <p class="text-slate-400">Queue: 2/1024 safe. Drop rate: 0.00%</p>
      `;
    }
    showToast('Chuyển trạng thái Lab', '200 OK - Mạng phản hồi thông suốt');
  } else if (state === 'syn') {
    fabBadge.textContent = '504 SYN Flood';
    fabBadge.className =
      'bg-rose-950 text-rose-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-rose-800';
    if (activeBtn) {
      activeBtn.className =
        'lab-toggle-btn w-full p-3 rounded-xl border text-left flex items-center justify-between transition-all bg-rose-950/30 border-rose-500/40 text-rose-300';
      activeBtn.querySelector('.material-symbols-outlined').className =
        'material-symbols-outlined text-[18px] text-rose-400';
    }
    if (wireBox) {
      wireBox.innerHTML = `
        <p class="text-rose-400">> ALERT: tcp_max_syn_backlog 1024/1024 saturated</p>
        <p class="text-rose-300">504 Gateway Timeout injected on br0 port 8080</p>
      `;
    }
    showToast('Kích hoạt SYN Flood', 'Socket queue 100% đầy, kết nối sẽ bị nghẽn (504)');
  } else if (state === 'rst') {
    fabBadge.textContent = 'TCP RST';
    fabBadge.className =
      'bg-amber-950 text-amber-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-amber-800';
    if (activeBtn) {
      activeBtn.className =
        'lab-toggle-btn w-full p-3 rounded-xl border text-left flex items-center justify-between transition-all bg-amber-950/30 border-amber-500/40 text-amber-300';
      activeBtn.querySelector('.material-symbols-outlined').className =
        'material-symbols-outlined text-[18px] text-amber-400';
    }
    if (wireBox) {
      wireBox.innerHTML = `
        <p class="text-amber-400">> INJECT: Spoofed TCP frame with flag [RST, ACK]</p>
        <p class="text-slate-400">Target drops connection mid-flight (ECONNRESET)</p>
      `;
    }
    showToast('Kích hoạt TCP RST', 'Kết nối HTTP sẽ bị hủy đột ngột');
  } else if (state === 'arp') {
    fabBadge.textContent = 'ARP Spoof';
    fabBadge.className =
      'bg-violet-950 text-violet-400 text-[10px] font-mono px-2 py-0.5 rounded-full border border-violet-800';
    if (activeBtn) {
      activeBtn.className =
        'lab-toggle-btn w-full p-3 rounded-xl border text-left flex items-center justify-between transition-all bg-violet-950/30 border-violet-500/40 text-violet-300';
      activeBtn.querySelector('.material-symbols-outlined').className =
        'material-symbols-outlined text-[18px] text-violet-400';
    }
    if (wireBox) {
      wireBox.innerHTML = `
        <p class="text-violet-400">> ARP cache poisoned for 172.20.0.1</p>
        <p class="text-slate-300">Packets routed via Attacker MAC 02:42:ac:14:00:fe</p>
      `;
    }
    showToast('Kích hoạt ARP Spoofing', 'Bảng ARP đã bị đầu độc, MITM đang bắt gói');
  }
}

// Add to cart & Quick notification
function triggerCartAdd(productName, price) {
  if (currentLabState === 'syn') {
    showToast('Lỗi 504 Gateway Timeout', 'Không thể thêm sản phẩm: Máy chủ đang bị tấn công SYN Flood');
    return;
  }
  cartTotalCount += 1;
  document.getElementById('header-cart-count').textContent = cartTotalCount;
  const formatted = new Intl.NumberFormat('vi-VN').format(price) + ' ₫';
  showToast('Đã thêm vào giỏ hàng', `${productName} • ${formatted}`);
}

function showCartQuickToast() {
  showToast('Giỏ hàng của bạn', `Hiện có ${cartTotalCount} linh kiện đã được chọn`);
}

let toastTimer = null;
function showToast(title, subtitle) {
  const toast = document.getElementById('quick-toast');
  const tTitle = document.getElementById('toast-title');
  const tSub = document.getElementById('toast-subtitle');

  tTitle.textContent = title;
  tSub.textContent = subtitle;

  toast.classList.remove('-translate-y-20', 'opacity-0', 'pointer-events-none');
  toast.classList.add('translate-y-0', 'opacity-100');

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('translate-y-0', 'opacity-100');
    toast.classList.add('-translate-y-20', 'opacity-0', 'pointer-events-none');
  }, 3000);
}
