// ChronQuest — app.js

// ── Device registration form ───────────────────────────────
const form    = document.getElementById('registerForm');
const success = document.getElementById('registerSuccess');

if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value.trim();
    const mac   = document.getElementById('mac').value.trim().toUpperCase();

    // Basic MAC validation
    if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac)) {
      alert('Please enter a valid Device ID in the format AA:BB:CC:DD:EE:FF');
      return;
    }

    const btn = form.querySelector('button[type="submit"]');
    btn.textContent = 'Registering…';
    btn.disabled = true;

    try {
      // TODO: replace with real Worker endpoint once backend is wired
      // For now, simulate success after a short delay
      await new Promise(r => setTimeout(r, 900));

      form.hidden   = true;
      success.hidden = false;

      console.log('Registration submitted:', { email, mac });
    } catch (err) {
      btn.textContent = 'Register Device';
      btn.disabled = false;
      alert('Something went wrong — please try again or email support@chronquest.com');
    }
  });
}

// ── MAC input auto-format ──────────────────────────────────
const macInput = document.getElementById('mac');
if (macInput) {
  macInput.addEventListener('input', (e) => {
    let v = e.target.value.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
    // Insert colons every two hex chars
    v = v.match(/.{1,2}/g)?.join(':') ?? v;
    if (v.length > 17) v = v.slice(0, 17);
    e.target.value = v;
  });
}

// ── Smooth nav highlight ───────────────────────────────────
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-links a');

const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(a => {
        a.style.color = a.getAttribute('href') === `#${entry.target.id}`
          ? 'var(--text)' : '';
      });
    }
  });
}, { threshold: 0.4 });

sections.forEach(s => observer.observe(s));
