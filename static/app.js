/**
 * CYBERSHIELD - PREMIUM ENTERPRISE CLIENT SCRIPT
 * Production-grade frontend interactivity:
 * - 1-Click Fast Demo Fillers
 * - Real-time Client Telemetry Ingestion (Device, Geolocation, Time)
 * - Document Center: Instant Search, Category Filtering & In-Browser Preview Modal
 * - Live SOC Clock & Threat Feed Controls
 * - Keyboard Accessibility & Modal Focus Traps
 */

// =========================================================
// 1. LIVE SOC CLOCK & TELEMETRY BEACON
// =========================================================
function initLiveClock() {
    function updateClock() {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
        const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        
        const clockEls = document.querySelectorAll('.live-clock');
        clockEls.forEach(el => {
            el.textContent = `${timeStr} UTC+5:30`;
        });

        const dateEls = document.querySelectorAll('.live-date');
        dateEls.forEach(el => {
            el.textContent = dateStr;
        });
    }
    updateClock();
    setInterval(updateClock, 1000);
}

// =========================================================
// 2. CLIENT-SIDE TELEMETRY CAPTURE
// =========================================================
function initClientTelemetry() {
    // 1. Device / OS
    const ua = navigator.userAgent;
    let device = "Desktop (Web)";
    if (/mobile/i.test(ua)) device = "Mobile Device";
    else if (/windows/i.test(ua)) device = "Desktop (Windows)";
    else if (/mac/i.test(ua)) device = "Desktop (macOS)";
    else if (/linux/i.test(ua)) device = "Desktop (Linux)";

    const deviceInput = document.getElementById('real_device');
    if (deviceInput) deviceInput.value = device;

    const deviceChip = document.getElementById('chip_device');
    if (deviceChip) deviceChip.textContent = device;

    // 2. Time
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const timeVal = `${hours}:${minutes}`;

    const timeInput = document.getElementById('real_time');
    if (timeInput) timeInput.value = timeVal;

    const timeChip = document.getElementById('chip_time');
    if (timeChip) timeChip.textContent = `${timeVal} Local`;

    // 3. Location / Public IP City
    const locInput = document.getElementById('real_location');
    const locChip = document.getElementById('chip_location');

    fetch('https://ipapi.co/json/')
        .then(res => res.json())
        .then(data => {
            if (data && data.city) {
                const loc = `${data.city}, ${data.country_name || data.country_code || ''}`.trim();
                if (locInput) locInput.value = loc;
                if (locChip) locChip.textContent = loc;
            }
        })
        .catch(() => {
            try {
                const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                if (tz) {
                    const city = tz.split('/').pop().replace('_', ' ');
                    if (locInput) locInput.value = city;
                    if (locChip) locChip.textContent = city;
                }
            } catch(e) {}
        });
}

// =========================================================
// 3. 1-CLICK DEMO ACCOUNT AUTOFILL
// =========================================================
function fillDemoAccount(role) {
    const userField = document.getElementById('username');
    const passField = document.getElementById('password');
    if (!userField || !passField) return;

    if (role === 'student') {
        userField.value = 'student';
        passField.value = 'student123';
    } else if (role === 'admin') {
        userField.value = 'admin';
        passField.value = 'admin123';
    }

    // Highlight fields subtly
    userField.classList.add('field-autofilled');
    passField.classList.add('field-autofilled');
    setTimeout(() => {
        userField.classList.remove('field-autofilled');
        passField.classList.remove('field-autofilled');
    }, 1200);

    // Update active tab button style
    document.querySelectorAll('.demo-tab-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.getElementById(`demo-tab-${role}`);
    if (activeBtn) activeBtn.classList.add('active');
}

// =========================================================
// 4. PASSWORD VISIBILITY TOGGLE
// =========================================================
function togglePasswordVisibility(fieldId, btnId) {
    const field = document.getElementById(fieldId);
    const btn = document.getElementById(btnId);
    if (!field) return;

    if (field.type === 'password') {
        field.type = 'text';
        if (btn) btn.innerHTML = '👁️‍🗨️';
    } else {
        field.type = 'password';
        if (btn) btn.innerHTML = '👁️';
    }
}

// =========================================================
// 5. DOCUMENT CENTER: SEARCH & TAB FILTERING
// =========================================================
let currentDocCategory = 'all';

function filterDocCategory(category, buttonEl) {
    currentDocCategory = category;
    
    // Update active button
    document.querySelectorAll('.doc-tab-btn').forEach(btn => btn.classList.remove('active'));
    if (buttonEl) buttonEl.classList.add('active');

    applyDocFilters();
}

function searchDocuments() {
    applyDocFilters();
}

function applyDocFilters() {
    const searchInput = document.getElementById('docSearchInput');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const cards = document.querySelectorAll('.doc-card');
    let visibleCount = 0;

    cards.forEach(card => {
        const cardCat = card.getAttribute('data-category') || '';
        const cardText = card.innerText.toLowerCase();

        const matchesCat = (currentDocCategory === 'all') || (cardCat === currentDocCategory);
        const matchesSearch = (!query) || (cardText.includes(query));

        if (matchesCat && matchesSearch) {
            card.style.display = 'flex';
            visibleCount++;
        } else {
            card.style.display = 'none';
        }
    });

    const emptyMsg = document.getElementById('docEmptyState');
    if (emptyMsg) {
        emptyMsg.style.display = visibleCount === 0 ? 'block' : 'none';
    }
}

// =========================================================
// 6. IN-BROWSER DOCUMENT PREVIEW MODAL
// =========================================================
function openDocPreview(filename) {
    const modal = document.getElementById('docPreviewModal');
    if (!modal) return;

    // Show loading state in modal
    document.getElementById('modalDocTitle').textContent = "Loading Document Security Profile...";
    document.getElementById('modalDocIssuer').textContent = "Authenticating with Central Registry...";
    document.getElementById('modalDocClassification').textContent = "Verifying Clearance...";
    document.getElementById('modalDocCategory').textContent = "Categorizing...";
    document.getElementById('modalDocContent').textContent = "Retrieving encrypted content from secure repository. Please wait...";
    document.getElementById('modalDownloadLink').href = `/download/file/${encodeURIComponent(filename)}`;

    modal.classList.add('open');
    document.body.style.overflow = 'hidden';

    fetch(`/api/document/preview/${encodeURIComponent(filename)}`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById('modalDocTitle').textContent = data.title;
                document.getElementById('modalDocIssuer').textContent = data.issuer;
                document.getElementById('modalDocClassification').textContent = data.classification;
                document.getElementById('modalDocCategory').textContent = data.category;
                document.getElementById('modalDocContent').textContent = data.content;
            } else {
                document.getElementById('modalDocContent').textContent = "Error: Unable to load document preview. " + (data.error || "");
            }
        })
        .catch(err => {
            document.getElementById('modalDocContent').textContent = "Network error loading preview: " + err.message;
        });
}

function closeDocPreview() {
    const modal = document.getElementById('docPreviewModal');
    if (!modal) return;
    modal.classList.remove('open');
    document.body.style.overflow = '';
}

// Keyboard ESC to close modal
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeDocPreview();
        const notifDropdown = document.getElementById('notifDropdown');
        if (notifDropdown && notifDropdown.classList.contains('show')) {
            notifDropdown.classList.remove('show');
        }
    }
});

// Close modal when clicking outside dialog
document.addEventListener('click', (e) => {
    const modal = document.getElementById('docPreviewModal');
    if (modal && e.target === modal) {
        closeDocPreview();
    }
});

// =========================================================
// 7. NOTIFICATION DROPDOWN TOGGLE
// =========================================================
function toggleNotifications() {
    const dropdown = document.getElementById('notifDropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

// Close notifications when clicking outside
document.addEventListener('click', (e) => {
    const wrapper = document.querySelector('.notif-wrapper');
    const dropdown = document.getElementById('notifDropdown');
    if (wrapper && dropdown && !wrapper.contains(e.target)) {
        dropdown.classList.remove('show');
    }
});

// =========================================================
// 8. ADMIN DASHBOARD: EVENT SEARCH & FILTERING
// =========================================================
function filterAdminEvents() {
    const searchInput = document.getElementById('adminEventSearch');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const levelFilter = document.getElementById('adminLevelFilter');
    const selectedLevel = levelFilter ? levelFilter.value.toLowerCase() : 'all';

    const rows = document.querySelectorAll('#activityTableBody tr');
    let visibleRows = 0;

    rows.forEach(row => {
        const rowText = row.innerText.toLowerCase();
        const rowLevel = (row.getAttribute('data-level') || '').toLowerCase();

        const matchesQuery = (!query) || rowText.includes(query);
        const matchesLevel = (selectedLevel === 'all') || (rowLevel === selectedLevel);

        if (matchesQuery && matchesLevel) {
            row.style.display = '';
            visibleRows++;
        } else {
            row.style.display = 'none';
        }
    });

    const noMatch = document.getElementById('noMatchMessage');
    if (noMatch) {
        noMatch.style.display = visibleRows === 0 ? 'block' : 'none';
    }
}

// =========================================================
// 9. INITIALIZATION ON DOM READY
// =========================================================
document.addEventListener('DOMContentLoaded', () => {
    initLiveClock();
    initClientTelemetry();

    // Register service worker if supported
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/static/sw.js').catch(() => {});
    }
});
