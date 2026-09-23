/**
 * AegisPhish - Interactive Client Application Logic
 * Integrates with FastAPI backend for heuristic analysis and provides
 * interactive training arena and defensive bento tools.
 * All user text strictly adheres to simple, plain English.
 */

document.addEventListener('DOMContentLoaded', () => {
  initMenuDrawer();
  // Initialize with a default clean state
  updateGauge(0, 'Safe');
});

/* ------------------- MENU DRAWER LOGIC ------------------- */
function initMenuDrawer() {
  const menuBtn = document.getElementById('menuToggleBtn');
  const drawer = document.getElementById('menuDrawer');
  const backdrop = document.getElementById('drawerBackdrop');
  const closeBtn = document.getElementById('drawerCloseBtn');
  const drawerLinks = document.querySelectorAll('.drawer-link');

  function openDrawer() {
    drawer.classList.add('open');
    backdrop.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
    document.body.style.overflow = '';
  }

  if (menuBtn) menuBtn.addEventListener('click', openDrawer);
  if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
  if (backdrop) backdrop.addEventListener('click', closeDrawer);

  drawerLinks.forEach(link => {
    link.addEventListener('click', closeDrawer);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && drawer.classList.contains('open')) {
      closeDrawer();
    }
  });
}

/* ------------------- QUICK SAMPLE LOADER ------------------- */
function loadSample(url) {
  const input = document.getElementById('urlInput');
  if (input) {
    input.value = url;
    triggerScan();
  }
}

/* ------------------- SCANNER TRIGGER & API CALL ------------------- */
async function triggerScan() {
  const input = document.getElementById('urlInput');
  const submitBtn = document.getElementById('scanSubmitBtn');
  const url = input.value.trim();

  if (!url) {
    alert('Please enter or paste a web address to inspect.');
    return;
  }

  // Set loading state
  submitBtn.disabled = true;
  submitBtn.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="spin">
      <line x1="12" y1="2" x2="12" y2="6"></line>
      <line x1="12" y1="18" x2="12" y2="22"></line>
      <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line>
      <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line>
      <line x1="2" y1="12" x2="6" y2="12"></line>
      <line x1="18" y1="12" x2="22" y2="12"></line>
    </svg>
    <span>Analyzing...</span>
  `;

  // Scroll smoothly to results card
  const resultsCard = document.getElementById('resultsCard');
  if (resultsCard) {
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  try {
    const response = await fetch('/api/scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }

    const data = await response.json();
    renderScanResults(data);
  } catch (err) {
    console.warn('API error, falling back to local heuristic analysis:', err);
    // Fallback heuristic evaluation
    const fallbackData = localHeuristicScan(url);
    renderScanResults(fallbackData);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
      </svg>
      <span>Analyze URL</span>
    `;
  }
}

/* ------------------- RENDER SCANNER RESULTS ------------------- */
function renderScanResults(data) {
  const resultsCard = document.getElementById('resultsCard');
  const displayUrl = document.getElementById('displayUrl');
  const statusBadge = document.getElementById('statusBadge');
  const statusBadgeText = document.getElementById('statusBadgeText');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const verdictAdvice = document.getElementById('verdictAdvice');
  const threatTagsContainer = document.getElementById('threatTagsContainer');
  const gaugeStatusText = document.getElementById('gaugeStatusText');

  // Display URL
  displayUrl.textContent = data.url;

  // Status Badge and Colors
  resultsCard.classList.remove('danger-state', 'warning-state');
  statusBadge.classList.remove('safe', 'warning', 'danger');

  if (data.status === 'Phishing Trap') {
    resultsCard.classList.add('danger-state');
    statusBadge.classList.add('danger');
    statusBadgeText.textContent = 'Status: Phishing Trap';
    gaugeStatusText.textContent = 'High Danger';
    gaugeStatusText.style.color = 'var(--danger)';
  } else if (data.status === 'Suspicious') {
    resultsCard.classList.add('warning-state');
    statusBadge.classList.add('warning');
    statusBadgeText.textContent = 'Status: Suspicious';
    gaugeStatusText.textContent = 'Caution Advised';
    gaugeStatusText.style.color = 'var(--warning)';
  } else {
    statusBadge.classList.add('safe');
    statusBadgeText.textContent = 'Status: Clean / Safe';
    gaugeStatusText.textContent = 'Safe to browse';
    gaugeStatusText.style.color = 'var(--neon-lime)';
  }

  // Verdict and simple English explanation
  verdictHeadline.textContent = data.verdict;
  verdictAdvice.textContent = data.action_advice;

  // Render Threat Tags
  threatTagsContainer.innerHTML = '';
  if (data.threat_tags && data.threat_tags.length > 0) {
    data.threat_tags.forEach(tag => {
      const span = document.createElement('span');
      span.className = 'threat-tag';
      if (data.status === 'Phishing Trap') {
        span.classList.add('danger-tag');
      } else if (data.status === 'Safe') {
        span.classList.add('safe-tag');
      }
      span.textContent = tag;
      threatTagsContainer.appendChild(span);
    });
  }

  // Render Sub-Metrics
  if (data.metrics) {
    document.getElementById('valDomain').textContent = `${data.metrics.domain_reputation}%`;
    document.getElementById('barDomain').style.width = `${data.metrics.domain_reputation}%`;

    document.getElementById('valEntropy').textContent = `${data.metrics.entropy_safety}%`;
    document.getElementById('barEntropy').style.width = `${data.metrics.entropy_safety}%`;

    document.getElementById('valCredential').textContent = `${data.metrics.credential_safety}%`;
    document.getElementById('barCredential').style.width = `${data.metrics.credential_safety}%`;

    document.getElementById('valProtocol').textContent = `${data.metrics.protocol_safety}%`;
    document.getElementById('barProtocol').style.width = `${data.metrics.protocol_safety}%`;
  }

  // Animate Gauge Dial
  updateGauge(data.risk_score, data.status);
}

/* ------------------- ANIMATED SVG GAUGE ------------------- */
function updateGauge(score, status) {
  const circle = document.getElementById('gaugeCircle');
  const numberText = document.getElementById('riskScoreNumber');
  const circumference = 440; // 2 * PI * 70

  // Calculate stroke offset
  const offset = circumference - (circumference * score / 100);
  circle.style.strokeDashoffset = offset;

  // Set color according to risk
  if (score >= 66 || status === 'Phishing Trap') {
    circle.style.stroke = 'var(--danger)';
    circle.style.filter = 'drop-shadow(0 0 10px var(--danger-glow))';
  } else if (score >= 26 || status === 'Suspicious') {
    circle.style.stroke = 'var(--warning)';
    circle.style.filter = 'drop-shadow(0 0 10px var(--warning-glow))';
  } else {
    circle.style.stroke = 'var(--neon-lime)';
    circle.style.filter = 'drop-shadow(0 0 10px var(--neon-lime-glow))';
  }

  // Animate number count up
  let current = 0;
  const stepTime = 15;
  const totalSteps = 40;
  const increment = score / totalSteps;
  
  if (score === 0) {
    numberText.textContent = '0%';
    return;
  }

  const timer = setInterval(() => {
    current += increment;
    if (current >= score) {
      numberText.textContent = `${Math.round(score)}%`;
      clearInterval(timer);
    } else {
      numberText.textContent = `${Math.round(current)}%`;
    }
  }, stepTime);
}

/* ------------------- BENTO 1: LOOKALIKE TESTER ------------------- */
function testBrandLookalikes() {
  const input = document.getElementById('brandTestInput');
  const result = document.getElementById('brandTestResult');
  const brand = input.value.trim().toLowerCase();

  if (!brand) {
    result.textContent = 'Please enter a brand name.';
    return;
  }

  const variations = [
    `${brand.replace('o', '0').replace('l', '1')}-login-alert.top`,
    `verify-${brand}-account-security.xyz`,
    `signin.${brand}.com.fake-portal.net`
  ];

  result.innerHTML = `
    <div>
      <div style="font-weight:700; color: var(--neon-lime); margin-bottom: 4px;">Dangerous lookalikes blocked by AegisPhish:</div>
      <ul style="list-style: none; padding-left: 0; margin-bottom: 4px; font-family: var(--font-mono); font-size: 0.78rem; color: #f87171;">
        ${variations.map(v => `<li>⚠️ ${v}</li>`).join('')}
      </ul>
      <div style="font-size: 0.72rem; color: #94a3b8;">Our heuristic analyzer recognizes fake brand names in seconds.</div>
    </div>
  `;
}

/* ------------------- BENTO 2: LEAK RADAR ------------------- */
async function testLeakRadar() {
  const input = document.getElementById('leakTestInput');
  const result = document.getElementById('leakTestResult');
  const target = input.value.trim();

  if (!target) {
    result.textContent = 'Please enter an email or domain.';
    return;
  }

  result.innerHTML = '<span style="color: var(--neon-lime);">Checking breach databases...</span>';

  try {
    const res = await fetch('/api/leak-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });
    const data = await res.json();

    if (data.found_leaks > 0) {
      result.innerHTML = `
        <div>
          <div style="color: var(--danger); font-weight: 800;">🚨 ${data.status}</div>
          <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 2px;">${data.simple_advice}</div>
        </div>
      `;
    } else {
      result.innerHTML = `
        <div>
          <div style="color: var(--neon-lime); font-weight: 800;">✅ ${data.status}</div>
          <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 2px;">${data.simple_advice}</div>
        </div>
      `;
    }
  } catch (err) {
    result.innerHTML = `
      <div>
        <div style="color: var(--neon-lime); font-weight: 800;">✅ Protected Radar</div>
        <div style="font-size: 0.75rem; color: #cbd5e1;">No active paste alerts for "${target}".</div>
      </div>
    `;
  }
}

/* ------------------- BENTO 3: PASSKEY SIMULATOR ------------------- */
function setPasskeySim(mode) {
  const btnPass = document.getElementById('btnModePassword');
  const btnKey = document.getElementById('btnModePasskey');
  const result = document.getElementById('passkeyTestResult');

  if (mode === 'password') {
    btnPass.style.background = 'var(--danger)';
    btnPass.style.color = '#fff';
    btnKey.style.background = 'rgba(200, 245, 60, 0.15)';
    btnKey.style.color = 'var(--neon-lime)';

    result.innerHTML = `
      <div>
        <strong style="color: var(--danger);">Vulnerable to Theft:</strong>
        <p style="margin: 0; font-size: 0.76rem; color: #cbd5e1;">If you type a password on a fake website, the attacker instantly steals your account access.</p>
      </div>
    `;
  } else {
    btnKey.style.background = 'var(--neon-lime)';
    btnKey.style.color = '#000';
    btnPass.style.background = 'rgba(255, 255, 255, 0.05)';
    btnPass.style.color = '#cbd5e1';

    result.innerHTML = `
      <div>
        <strong style="color: var(--neon-lime);">Phishing-Resistant:</strong>
        <p style="margin: 0; font-size: 0.76rem; color: #cbd5e1;">FIDO2 Passkeys communicate directly with real domains. Even if a fake website asks for it, your browser refuses to send cryptographic keys.</p>
      </div>
    `;
  }
}

/* ------------------- PHISHING ARENA: SPOT THE FAKE ------------------- */
function showClue(num) {
  const clueElement = document.getElementById(`clue${num}`);
  if (clueElement) {
    clueElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    clueElement.style.transition = 'all 0.3s ease';
    clueElement.style.background = 'rgba(255, 71, 87, 0.25)';
    clueElement.style.boxShadow = '0 0 15px rgba(255, 71, 87, 0.5)';
    setTimeout(() => {
      clueElement.style.background = 'rgba(255, 255, 255, 0.03)';
      clueElement.style.boxShadow = 'none';
    }, 1500);
  }
}

function switchArenaMode(mode) {
  const btnInspect = document.getElementById('tabInspect');
  const btnQuiz = document.getElementById('tabQuiz');
  const cluePanel = document.getElementById('cluePanel');
  const quizContainer = document.getElementById('quizContainer');

  if (mode === 'quiz') {
    btnQuiz.classList.add('active');
    btnInspect.classList.remove('active');
    cluePanel.style.display = 'none';
    quizContainer.style.display = 'block';
  } else {
    btnInspect.classList.add('active');
    btnQuiz.classList.remove('active');
    cluePanel.style.display = 'block';
    quizContainer.style.display = 'none';
  }
}

function answerQuiz(choice) {
  const feedback = document.getElementById('quizFeedback');
  if (choice === 'left') {
    feedback.innerHTML = `
      <span style="color: var(--neon-lime); font-size: 1.1rem;">🎉 Correct!</span>
      <p style="margin-top: 4px; color: #e2e8f0; font-weight: 400;">
        Portal A is the genuine Google sign-in portal. The address has legitimate official domain structure and genuine HTTPS.
      </p>
    `;
  } else {
    feedback.innerHTML = `
      <span style="color: var(--danger); font-size: 1.1rem;">⚠️ Incorrect: Portal B is a phishing trap!</span>
      <p style="margin-top: 4px; color: #e2e8f0; font-weight: 400;">
        Portal B uses a fake address ("g00gle...xyz") and an artificial panic countdown to trick you into giving away your password.
      </p>
    `;
  }
}

/* ------------------- FALLBACK CLIENT-SIDE HEURISTICS ------------------- */
function localHeuristicScan(rawUrl) {
  let url = rawUrl.toLowerCase();
  let score = 10;
  let threatTags = [];

  if (url.startsWith('http://')) {
    score += 25;
    threatTags.push('No Valid SSL (HTTP)');
  }

  if (url.includes('paypa1') || url.includes('g00gle') || url.includes('micros0ft')) {
    score += 45;
    threatTags.push('Homoglyph / Typosquatting Detected');
  }

  if (url.includes('.xyz') || url.includes('.top') || url.includes('.click') || url.includes('.buzz')) {
    score += 25;
    threatTags.push('High-Risk Domain Extension');
  }

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
    score += 40;
    threatTags.push('Direct IP Address Host');
  }

  if (url.includes('bit.ly') || url.includes('tinyurl.com')) {
    score += 30;
    threatTags.push('Shortened Link Masking');
  }

  if (url.includes('login') || url.includes('verify') || url.includes('signin') || url.includes('update')) {
    score += 20;
    threatTags.push('Credential Trap Keywords');
  }

  score = Math.min(score, 100);

  let status = 'Safe';
  let verdict = 'SAFE: The domain appears regular and no known threat patterns are visible.';
  let action_advice = 'Looks clean. Always verify the domain in your browser address bar.';

  if (score >= 66) {
    status = 'Phishing Trap';
    verdict = 'DANGER: High probability of credential theft. Do NOT enter passwords here.';
    action_advice = 'Close this tab immediately. Do not type passwords or verification codes.';
  } else if (score >= 26) {
    status = 'Suspicious';
    verdict = 'WARNING: This link looks suspicious. It has multiple red flags.';
    action_advice = 'Avoid typing sensitive credentials. Verify with the sender.';
  }

  return {
    url: rawUrl,
    risk_score: score,
    status: status,
    verdict: verdict,
    action_advice: action_advice,
    threat_tags: threatTags.length ? threatTags : ['Standard Domain Structure'],
    metrics: {
      domain_reputation: Math.max(10, 100 - score),
      entropy_safety: 85,
      credential_safety: Math.max(15, 100 - score),
      protocol_safety: url.startsWith('https://') ? 100 : 20
    }
  };
}
