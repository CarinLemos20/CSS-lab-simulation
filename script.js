// ==========================================
// RSA Virtual Lab: Core Script
// Features: Dynamic Modulus Generation, Factoring Challenge,
// Complete RSA Flow, Chosen Ciphertext Attack & Tab Navigation
// ==========================================

// --- MATHEMATICAL HELPERS ---

// Greatest Common Divisor
function gcd(a, b) {
    while (b !== 0) {
        let t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Extended Euclidean Algorithm
function extendedGCD(a, b) {
    if (b === 0) return { gcd: a, x: 1, y: 0 };
    const { gcd: g, x: x1, y: y1 } = extendedGCD(b, a % b);
    const x = y1;
    const y = x1 - Math.floor(a / b) * y1;
    return { gcd: g, x, y };
}

// Modular Multiplicative Inverse (a^-1 mod m)
function modInverse(a, m) {
    const { gcd: g, x } = extendedGCD(a, m);
    if (g !== 1) return null;
    return ((x % m) + m) % m;
}

// Modular Exponentiation: (base^exp) % mod
function modExp(base, exp, mod) {
    let result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 === 1) result = (result * base) % mod;
        exp = Math.floor(exp / 2);
        base = (base * base) % mod;
    }
    return result;
}

// Check if a number is prime
function isPrime(num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 === 0 || num % 3 === 0) return false;
    for (let i = 5; i * i <= num; i += 6) {
        if (num % i === 0 || num % (i + 2) === 0) return false;
    }
    return true;
}

// --- DYNAMIC PARAMETER GENERATION ---

// Curated list of small prime pairs suitable for manual arithmetic & student learning
const PRIME_PAIRS = [
    { p: 3, q: 11 }, // n = 33, phi = 20
    { p: 3, q: 17 }, // n = 51, phi = 32
    { p: 3, q: 19 }, // n = 57, phi = 36
    { p: 3, q: 23 }, // n = 69, phi = 44
    { p: 5, q: 11 }, // n = 55, phi = 40
    { p: 5, q: 13 }, // n = 65, phi = 48
    { p: 5, q: 17 }, // n = 85, phi = 64
    { p: 5, q: 19 }, // n = 95, phi = 72
    { p: 7, q: 11 }, // n = 77, phi = 60
    { p: 7, q: 13 }, // n = 91, phi = 72
    { p: 7, q: 17 }, // n = 119, phi = 96
    { p: 7, q: 19 }, // n = 133, phi = 108
    { p: 11, q: 13 }, // n = 143, phi = 120
    { p: 11, q: 17 }, // n = 187, phi = 160
    { p: 11, q: 19 }, // n = 209, phi = 180
    { p: 13, q: 17 }  // n = 221, phi = 192
];

// Candidates for public exponent e
const E_CANDIDATES = [3, 5, 7, 11, 13, 17];

// State variables for current simulation instance
let currentP = null;
let currentQ = null;
let currentN = null;
let currentPhi = null;
let currentE = null;
let currentD = null;
let userM = null;
let correctC = null;

// Initialize or regenerate random modulus & RSA state
function initDynamicRSA(forceNew = false) {
    // Read the previously used n from sessionStorage
    const lastN = sessionStorage.getItem('rsa_last_n');
    let availablePairs = PRIME_PAIRS;

    // Ensure that every page load generates a DIFFERENT value from the previous one
    if (lastN && PRIME_PAIRS.length > 1) {
        availablePairs = PRIME_PAIRS.filter(pair => (pair.p * pair.q) !== parseInt(lastN));
    }

    // Select a random pair from the available candidates
    const chosenIndex = Math.floor(Math.random() * availablePairs.length);
    const chosenPair = availablePairs[chosenIndex];

    currentP = chosenPair.p;
    currentQ = chosenPair.q;
    currentN = currentP * currentQ;
    currentPhi = (currentP - 1) * (currentQ - 1);

    // Persist this newly generated n to guarantee the next reload is different
    sessionStorage.setItem('rsa_last_n', currentN.toString());

    // Select suitable public exponent e (coprime to phi, ideally e != d)
    currentE = null;
    currentD = null;
    for (const testE of E_CANDIDATES) {
        if (testE < currentPhi && gcd(testE, currentPhi) === 1) {
            const d = modInverse(testE, currentPhi);
            if (d && d !== testE) {
                currentE = testE;
                currentD = d;
                break;
            }
        }
    }
    // Fallback if no e != d found
    if (!currentE) {
        for (const testE of E_CANDIDATES) {
            if (testE < currentPhi && gcd(testE, currentPhi) === 1) {
                currentE = testE;
                currentD = modInverse(testE, currentPhi);
                break;
            }
        }
    }

    // Reset user progress state
    userM = null;
    correctC = null;

    // Update UI elements for the Factoring Challenge
    document.getElementById('display-target-n').innerText = currentN;
    document.getElementById('input-p').value = '';
    document.getElementById('input-q').value = '';
    document.getElementById('input-p').disabled = false;
    document.getElementById('input-q').disabled = false;
    document.getElementById('btn-check-factors').disabled = false;

    // Reset feedback messages
    setFeedback('msg-factors', '', '');
    setFeedback('msg-phi', '', '');
    setFeedback('msg-d', '', '');
    setFeedback('msg-c', '', '');
    setFeedback('msg-dec', '', '');

    // Reset hints
    document.getElementById('hint-box').style.display = 'none';
    document.getElementById('hint-d-box').style.display = 'none';
    const maxPrimeCheck = Math.floor(Math.sqrt(currentN));
    document.getElementById('hint-text').innerHTML = 
        `💡 <strong>Factorization Hint:</strong> Since <em>n</em> = ${currentN}, test prime numbers up to &lfloor;&radic;${currentN}&rfloor; = ${maxPrimeCheck}. Try dividing ${currentN} by 3, 5, 7, 11, or 13.`;

    // Lock subsequent sections until factoring challenge is solved
    document.getElementById('section-phi').classList.add('disabled-section');
    document.getElementById('input-phi').value = '';

    document.getElementById('section-d').classList.add('disabled-section');
    document.getElementById('input-d').value = '';
    document.getElementById('display-e').innerText = currentE;
    document.getElementById('label-e-in-d').innerText = currentE;
    document.getElementById('label-phi-in-d').innerText = `\u03D5(n)`;

    document.getElementById('phase2').classList.add('disabled-section');
    document.getElementById('display-e-phase2').innerText = currentE;
    document.getElementById('display-n-phase2').innerText = currentN;
    document.getElementById('display-e-exp').innerText = currentE;
    document.getElementById('display-n-mod').innerText = currentN;
    document.getElementById('max-m-label').innerText = currentN - 1;
    const inputM = document.getElementById('input-m');
    inputM.value = '';
    inputM.max = currentN - 1;
    document.getElementById('input-c').value = '';

    document.getElementById('phase3').classList.add('disabled-section');
    document.getElementById('display-received-c').innerText = '?';
    document.getElementById('display-bob-d').innerText = currentD;
    document.getElementById('display-d-exp').innerText = currentD;
    document.getElementById('display-n-dec').innerText = currentN;
    document.getElementById('input-dec-m').value = '';

    document.getElementById('phase4').classList.add('disabled-section');
    document.getElementById('display-intercepted-c').innerText = '?';
    document.getElementById('label-attack-n').innerText = currentN;
    document.getElementById('attack-results').style.display = 'none';

    // Hint for d calculation
    const kVal = (currentE * currentD - 1) / currentPhi;
    document.getElementById('hint-d-text').innerHTML = 
        `💡 <strong>Hint for d:</strong> The equation is (<em>d</em> &times; ${currentE}) mod ${currentPhi} = 1. ` +
        `This means <em>d</em> = (<em>k</em> &times; ${currentPhi} + 1) / ${currentE} for an integer <em>k</em>. For <em>k</em> = ${kVal}: ` +
        `(${kVal} &times; ${currentPhi} + 1) / ${currentE} = <strong>${currentD}</strong>.`;
}

// Helper to set message text and status class
function setFeedback(elementId, text, status) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = text;
    el.className = 'feedback-msg ' + (status || '');
}

// ==========================================
// SIMULATION EVENT HANDLERS
// ==========================================

// --- Step 1a: Factoring Challenge Verification ---
document.getElementById('btn-check-factors').addEventListener('click', () => {
    const userP = parseInt(document.getElementById('input-p').value);
    const userQ = parseInt(document.getElementById('input-q').value);

    if (isNaN(userP) || isNaN(userQ)) {
        setFeedback('msg-factors', 'Please enter valid integer values for both p and q.', 'error');
        return;
    }

    if (userP <= 1 || userQ <= 1) {
        setFeedback('msg-factors', 'Prime factors must be greater than 1.', 'error');
        return;
    }

    if (userP === currentN || userQ === currentN) {
        setFeedback('msg-factors', `${currentN} is a composite semiprime. You must find non-trivial prime factors p and q where 1 < p, q < ${currentN}.`, 'error');
        return;
    }

    // Check if the product matches the modulus
    if (userP * userQ !== currentN) {
        setFeedback('msg-factors', `Incorrect: ${userP} &times; ${userQ} = ${userP * userQ}, but target n = ${currentN}. Keep searching!`, 'error');
        return;
    }

    // Check if both factors are prime
    if (!isPrime(userP) || !isPrime(userQ)) {
        setFeedback('msg-factors', `While ${userP} &times; ${userQ} = ${currentN}, both factors must be prime numbers!`, 'error');
        return;
    }

    // Verification successful!
    const factorMin = Math.min(userP, userQ);
    const factorMax = Math.max(userP, userQ);
    setFeedback('msg-factors', `&#10004; <strong>Success!</strong> You successfully factored <em>n</em> = ${currentN} into primes <em>p</em> = ${factorMin} and <em>q</em> = ${factorMax}. Bob's secret factors are compromised! Proceed to Step 1b.`, 'success');

    // Lock factor inputs and unlock Step 1b
    document.getElementById('input-p').disabled = true;
    document.getElementById('input-q').disabled = true;
    document.getElementById('btn-check-factors').disabled = true;

    document.getElementById('label-p').innerText = factorMin;
    document.getElementById('label-q').innerText = factorMax;
    document.getElementById('section-phi').classList.remove('disabled-section');
});

// Toggle Factoring Hint
document.getElementById('btn-toggle-hint').addEventListener('click', () => {
    const hintBox = document.getElementById('hint-box');
    hintBox.style.display = (hintBox.style.display === 'none' || hintBox.style.display === '') ? 'block' : 'none';
});

// Regenerate Random Modulus Button
document.getElementById('btn-regenerate-n').addEventListener('click', () => {
    if (confirm('Generate a new random modulus n? This will reset the current simulation progress.')) {
        initDynamicRSA(true);
    }
});

// --- Step 1b: Euler's Totient phi(n) Check ---
document.getElementById('btn-check-phi').addEventListener('click', () => {
    const userPhi = parseInt(document.getElementById('input-phi').value);
    if (isNaN(userPhi)) {
        setFeedback('msg-phi', 'Please enter a number for &phi;(n).', 'error');
        return;
    }

    if (userPhi === currentPhi) {
        setFeedback('msg-phi', `&#10004; Correct! &phi;(${currentN}) = (${currentP} &minus; 1) &times; (${currentQ} &minus; 1) = ${currentPhi}. Proceed to Step 1c.`, 'success');
        document.getElementById('label-phi-in-d').innerText = currentPhi;
        document.getElementById('section-d').classList.remove('disabled-section');
    } else {
        setFeedback('msg-phi', `Incorrect. Remember: &phi;(n) = (p &minus; 1) &times; (q &minus; 1). Check your arithmetic.`, 'error');
    }
});

// --- Step 1c: Private Key d Check ---
document.getElementById('btn-check-d').addEventListener('click', () => {
    const userD = parseInt(document.getElementById('input-d').value);
    if (isNaN(userD)) {
        setFeedback('msg-d', 'Please enter a number for private key d.', 'error');
        return;
    }

    if (userD === currentD) {
        setFeedback('msg-d', `&#10004; Correct! Public Key: (e = ${currentE}, n = ${currentN}). Private Key: (d = ${currentD}, n = ${currentN}). Phase 2 is now unlocked!`, 'success');
        document.getElementById('phase2').classList.remove('disabled-section');
    } else {
        const productMod = (userD * currentE) % currentPhi;
        setFeedback('msg-d', `Incorrect. (${userD} &times; ${currentE}) mod ${currentPhi} = ${productMod} &ne; 1. Need assistance? Click "Hint for d".`, 'error');
    }
});

// Toggle Hint for d
document.getElementById('btn-hint-d').addEventListener('click', () => {
    const hintBox = document.getElementById('hint-d-box');
    hintBox.style.display = (hintBox.style.display === 'none' || hintBox.style.display === '') ? 'block' : 'none';
});

// --- Step 2: Alice Encrypts Message M ---
document.getElementById('btn-check-c').addEventListener('click', () => {
    userM = parseInt(document.getElementById('input-m').value);
    const userC = parseInt(document.getElementById('input-c').value);

    if (isNaN(userM) || userM < 2 || userM >= currentN) {
        setFeedback('msg-c', `Please choose an integer message M strictly between 2 and ${currentN - 1}.`, 'error');
        return;
    }

    if (isNaN(userC)) {
        setFeedback('msg-c', 'Please enter your calculated ciphertext C.', 'error');
        return;
    }

    correctC = modExp(userM, currentE, currentN);

    if (userC === correctC) {
        setFeedback('msg-c', `&#10004; Correct! Ciphertext C = ${correctC} is encrypted and sent across the network. Phase 3 unlocked.`, 'success');
        document.getElementById('display-received-c').innerText = correctC;
        document.getElementById('display-intercepted-c').innerText = correctC;
        document.getElementById('phase3').classList.remove('disabled-section');
    } else {
        setFeedback('msg-c', `Incorrect. Ciphertext C = ${userM}<sup>${currentE}</sup> mod ${currentN}. You entered ${userC}, but expected ${correctC}.`, 'error');
    }
});

// --- Step 3: Bob Decrypts Ciphertext C ---
document.getElementById('btn-check-dec').addEventListener('click', () => {
    const userDecM = parseInt(document.getElementById('input-dec-m').value);

    if (isNaN(userDecM)) {
        setFeedback('msg-dec', 'Please enter the decrypted message M.', 'error');
        return;
    }

    if (userDecM === userM) {
        setFeedback('msg-dec', `&#10004; <strong>Success!</strong> Bob computed ${correctC}<sup>${currentD}</sup> mod ${currentN} = ${userM}. Alice's original message is recovered! Phase 4 unlocked.`, 'success');
        document.getElementById('phase4').classList.remove('disabled-section');
    } else {
        setFeedback('msg-dec', `Incorrect. Calculate ${correctC}<sup>${currentD}</sup> mod ${currentN}. It must match Alice's original plaintext (${userM}).`, 'error');
    }
});

// --- Step 4: Chosen Ciphertext Attack Execution ---
document.getElementById('btn-execute-attack').addEventListener('click', () => {
    let R = parseInt(document.getElementById('input-attack-r').value);

    if (isNaN(R) || R < 2) {
        alert('Please choose a valid integer multiplier R \u2265 2.');
        return;
    }

    if (gcd(R, currentN) !== 1) {
        alert(`Multiplier R (${R}) must be coprime to modulus n (${currentN}). Since gcd(${R}, ${currentN}) \u2260 1, choose a different R.`);
        return;
    }

    // Attacker Mallory computes blinded ciphertext: C' = (C * R^e) mod n
    const R_exp_e = modExp(R, currentE, currentN);
    const C_prime = (correctC * R_exp_e) % currentN;

    // Bob (Oracle) decrypts blinded C': M' = (C')^d mod n = (M * R) mod n
    const M_prime = modExp(C_prime, currentD, currentN);

    // Attacker computes modular inverse of R modulo n: R^-1 mod n
    const R_inv = modInverse(R, currentN);

    // Attacker recovers original plaintext: M = (M' * R^-1) mod n
    const recoveredM = (M_prime * R_inv) % currentN;

    // Populate attack calculation details in UI
    document.getElementById('calc-c').innerText = correctC;
    document.getElementById('calc-r').innerText = R;
    document.getElementById('calc-e').innerText = currentE;
    document.getElementById('calc-n').innerText = currentN;
    document.getElementById('calc-c-prime').innerText = C_prime;

    document.getElementById('calc-c-prime-2').innerText = C_prime;
    document.getElementById('calc-d').innerText = currentD;
    document.getElementById('calc-n-2').innerText = currentN;
    document.getElementById('calc-m-prime').innerText = M_prime;

    document.getElementById('calc-r-inv').innerText = R_inv;
    document.getElementById('calc-m-prime-2').innerText = M_prime;
    document.getElementById('calc-r-inv-2').innerText = R_inv;
    document.getElementById('calc-n-3').innerText = currentN;
    document.getElementById('calc-recovered-m').innerText = recoveredM;

    document.getElementById('attack-results').style.display = 'block';
});

// ==========================================
// NAVIGATION MENU & TAB SWITCHING
// ==========================================

const navItems = document.querySelectorAll('.nav-menu .nav-item');
const tabContents = document.querySelectorAll('.tab-content');

function switchTab(tabId) {
    if (!tabId) return;

    // Update active class on nav items
    navItems.forEach(item => {
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Update active class on tab contents
    tabContents.forEach(content => {
        if (content.id === tabId) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });

    // Save active tab in sessionStorage
    sessionStorage.setItem('rsa_active_tab', tabId);

    // Update URL hash without jumping
    if (history.replaceState) {
        history.replaceState(null, null, '#' + tabId);
    }
}

// Attach click listeners to sidebar nav items
navItems.forEach(item => {
    item.addEventListener('click', () => {
        const tabId = item.getAttribute('data-tab');
        switchTab(tabId);
    });
});

// Quick in-page triggers (e.g. "Go to Simulation" buttons)
document.querySelectorAll('.btn-nav-trigger').forEach(btn => {
    btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-target');
        switchTab(target);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
});

// Sidebar Filter Buttons: All vs Interactive
const filterAllBtn = document.getElementById('filter-all');
const filterInteractiveBtn = document.getElementById('filter-interactive');

filterAllBtn.addEventListener('click', () => {
    filterAllBtn.classList.add('active');
    filterInteractiveBtn.classList.remove('active');
    navItems.forEach(item => item.style.display = 'block');
});

filterInteractiveBtn.addEventListener('click', () => {
    filterInteractiveBtn.classList.add('active');
    filterAllBtn.classList.remove('active');
    // Interactive tabs: simulation, assignment, feedback
    const interactiveTabs = ['simulation', 'assignment', 'feedback'];
    navItems.forEach(item => {
        const tab = item.getAttribute('data-tab');
        item.style.display = interactiveTabs.includes(tab) ? 'block' : 'none';
    });
});

// ==========================================
// ASSIGNMENT QUIZ FUNCTIONALITY
// ==========================================

const CORRECT_ANSWERS = {
    q1: { answer: 'B', explanation: '\u03D5(n) = (7 - 1) \u00D7 (13 - 1) = 6 \u00D7 12 = 72.' },
    q2: { answer: 'B', explanation: 'e must be coprime to \u03D5(n). Since gcd(3, 36) = 3 \u2260 1, 3 is invalid.' },
    q3: { answer: 'A', explanation: 'Textbook RSA is multiplicatively homomorphic: (M\u2081\u1D49) \u00D7 (M\u2082\u1D49) \u2261 (M\u2081 \u00D7 M\u2082)\u1D49 mod n.' },
    q4: { answer: 'B', explanation: 'Optimal Asymmetric Encryption Padding (OAEP) injects randomized padding that destroys algebraic malleability.' }
};

document.getElementById('btn-submit-quiz').addEventListener('click', () => {
    let score = 0;
    const total = Object.keys(CORRECT_ANSWERS).length;

    for (const [qId, data] of Object.entries(CORRECT_ANSWERS)) {
        const selected = document.querySelector(`input[name="${qId}"]:checked`);
        const feedbackEl = document.getElementById(`feedback-${qId}`);

        if (!selected) {
            feedbackEl.innerHTML = `<span class="error">&#9888; Please select an answer.</span>`;
            continue;
        }

        if (selected.value === data.answer) {
            score++;
            feedbackEl.innerHTML = `<span class="success">&#10004; Correct! ${data.explanation}</span>`;
        } else {
            feedbackEl.innerHTML = `<span class="error">&#10008; Incorrect. Correct answer is <strong>${data.answer}</strong>: ${data.explanation}</span>`;
        }
    }

    const badge = document.getElementById('quiz-score-badge');
    badge.style.display = 'inline-block';
    badge.innerText = `Score: ${score} / ${total} (${Math.round((score / total) * 100)}%)`;
    badge.className = 'score-badge ' + (score === total ? 'score-perfect' : 'score-good');
});

document.getElementById('btn-reset-quiz').addEventListener('click', () => {
    document.getElementById('quiz-form').reset();
    for (const qId of Object.keys(CORRECT_ANSWERS)) {
        document.getElementById(`feedback-${qId}`).innerHTML = '';
    }
    const badge = document.getElementById('quiz-score-badge');
    badge.style.display = 'none';
});

// ==========================================
// FEEDBACK FORM FUNCTIONALITY
// ==========================================

const starElements = document.querySelectorAll('#star-rating .star');
const ratingInput = document.getElementById('fb-rating');

starElements.forEach(star => {
    star.addEventListener('click', () => {
        const rating = parseInt(star.getAttribute('data-rating'));
        ratingInput.value = rating;
        starElements.forEach((s, idx) => {
            if (idx < rating) {
                s.classList.add('selected');
            } else {
                s.classList.remove('selected');
            }
        });
    });
});

// Default 5 stars selected
starElements.forEach(s => s.classList.add('selected'));

document.getElementById('feedback-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = document.getElementById('fb-name').value.trim();
    const email = document.getElementById('fb-email').value.trim();
    const rating = ratingInput.value;
    const difficulty = document.getElementById('fb-difficulty').value;

    const statusMsg = document.getElementById('msg-feedback-status');
    statusMsg.className = 'feedback-msg success';
    statusMsg.innerHTML = `&#10004; Thank you, <strong>${name}</strong>! Your feedback (${rating} &#9733;) has been recorded successfully.`;

    // Clear text inputs
    document.getElementById('fb-comments').value = '';
});

// ==========================================
// TOOLBAR: READ ALOUD, ZOOM, SHARE
// ==========================================

let isReading = false;
const readAloudBtn = document.getElementById('btn-read-aloud');
const speedSelect = document.getElementById('select-speech-speed');
const voiceSelect = document.getElementById('select-speech-voice');

// Populate speech synthesis voices if supported
function populateVoices() {
    if ('speechSynthesis' in window) {
        const voices = window.speechSynthesis.getVoices();
        voiceSelect.innerHTML = '<option value="default">Default Voice</option>';
        voices.forEach((voice, index) => {
            const option = document.createElement('option');
            option.value = index;
            option.textContent = `${voice.name} (${voice.lang})`;
            voiceSelect.appendChild(option);
        });
    }
}

if ('speechSynthesis' in window) {
    window.speechSynthesis.onvoiceschanged = populateVoices;
    populateVoices();
}

readAloudBtn.addEventListener('click', () => {
    if (!('speechSynthesis' in window)) {
        alert('Text-to-speech is not supported by your browser.');
        return;
    }

    if (isReading) {
        window.speechSynthesis.cancel();
        isReading = false;
        readAloudBtn.innerHTML = '&#128266; Read Aloud';
        return;
    }

    const activeTab = document.querySelector('.tab-content.active');
    if (!activeTab) return;

    const textToRead = activeTab.innerText;
    const utterance = new SpeechSynthesisUtterance(textToRead);
    utterance.rate = parseFloat(speedSelect.value) || 1.0;

    const voices = window.speechSynthesis.getVoices();
    if (voiceSelect.value !== 'default' && voices[voiceSelect.value]) {
        utterance.voice = voices[voiceSelect.value];
    }

    utterance.onend = () => {
        isReading = false;
        readAloudBtn.innerHTML = '&#128266; Read Aloud';
    };

    utterance.onerror = () => {
        isReading = false;
        readAloudBtn.innerHTML = '&#128266; Read Aloud';
    };

    window.speechSynthesis.speak(utterance);
    isReading = true;
    readAloudBtn.innerHTML = '&#9209; Stop Reading';
});

// Zoom in / Zoom out
let currentFontSize = 16;
document.getElementById('btn-zoom-in').addEventListener('click', () => {
    if (currentFontSize < 22) {
        currentFontSize += 1;
        document.getElementById('main-content').style.fontSize = currentFontSize + 'px';
    }
});

document.getElementById('btn-zoom-out').addEventListener('click', () => {
    if (currentFontSize > 13) {
        currentFontSize -= 1;
        document.getElementById('main-content').style.fontSize = currentFontSize + 'px';
    }
});

// Share button
document.getElementById('btn-share').addEventListener('click', () => {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(window.location.href).then(() => {
            alert('Lab URL copied to clipboard!');
        }).catch(() => {
            alert('Lab URL: ' + window.location.href);
        });
    } else {
        alert('Lab URL: ' + window.location.href);
    }
});

// Header back button
document.getElementById('btn-header-back').addEventListener('click', () => {
    switchTab('aim');
    window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ==========================================
// PAGE INITIALIZATION
// ==========================================

window.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize RSA parameters dynamically (every page load generates a new random n)
    initDynamicRSA();

    // 2. Determine initial active tab:
    // If URL hash matches one of the tabs, use it; otherwise check saved tab or default to 'simulation'
    const hash = window.location.hash.replace('#', '');
    const validTabs = ['aim', 'theory', 'objective', 'procedure', 'simulation', 'assignment', 'references', 'feedback'];
    
    if (validTabs.includes(hash)) {
        switchTab(hash);
    } else {
        const savedTab = sessionStorage.getItem('rsa_active_tab');
        if (savedTab && validTabs.includes(savedTab)) {
            switchTab(savedTab);
        } else {
            switchTab('simulation');
        }
    }
});
