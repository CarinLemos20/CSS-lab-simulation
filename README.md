<<<<<<< HEAD
# Experiment ID: EXP_RSA_KCA
## Experiment Name: RSA Cryptosystem, Factoring Challenge & Chosen Ciphertext Attack
**Group**: Cryptography - RSA Attacks  
**Folder**: `/experiments/rsa-ciphertext-attack/`  
**Entry File**: `index.html`  
**Navigation Title**: RSA Virtual Lab  

### Short Description
A self-contained, interactive Virtual Lab manual on the RSA Public-Key Cryptosystem, prime factorization vulnerability, and Chosen Ciphertext Attack (CCA) on unpadded RSA. 

### Key Features
1. **Dynamic Generation**: Every page load dynamically generates a different semiprime modulus $n$ from a pool of distinct prime pairs $(p, q)$, eliminating hardcoded values.
2. **Factoring Challenge**: The target modulus $n$ is presented to the student, who must determine the underlying secret prime factors $p$ and $q$ ($n = p \times q$) before subsequent key generation steps are unlocked.
3. **Complete Navigation Menu**: Standard Virtual Labs sidebar navigation matching the canonical specification:
   - **Aim**: Purpose and learning goals of the lab.
   - **Theory**: Comprehensive mathematical foundation of RSA, Euler's totient, prime factorization complexity, and the homomorphic chosen ciphertext attack.
   - **Objective**: Pedagogical learning outcomes based on Bloom's taxonomy.
   - **Procedure**: Step-by-step experimental instructions.
   - **Simulation**: Interactive simulation engine featuring the Factoring Challenge, totient calculation, private key derivation, message encryption, decryption, and interactive Chosen Ciphertext Attack.
   - **Assignment**: Self-assessment quiz with automatic grading and detailed mathematical explanations.
   - **References**: Academic bibliography, original 1978 RSA paper, and IETF RFC 8017.
   - **Feedback**: Interactive 5-star rating and evaluation form.

### Required Libraries
None (Self-contained HTML5, CSS3, JavaScript - vanilla implementation without external dependencies).

### Input
* Secret prime factors $p$ and $q$ (solved by student in Factoring Challenge)
* Euler totient $\phi(n)$ and private key exponent $d$
* Plaintext Message ($M$) selected by user ($2 \le M < n$)
* Ciphertext ($C$) and recovered plaintext ($M$)
* Random Blinding Multiplier ($R$) selected by attacker in CCA demo

### Output
* Public modulus $n$ and public key $(e, n)$
* Euler totient $\phi(n)$ and private key $(d, n)$
* Transmitted Ciphertext ($C$)
* Blinded Ciphertext ($C' = (C \times R^e) \bmod n$)
* Decryption Oracle Response ($M' = (C')^d \bmod n$)
* Recovered Plaintext ($M = (M' \times R^{-1}) \bmod n$)

### Accessibility & Usability Features
* Web Speech API "Read Aloud" functionality with adjustable reading speed and voice selection.
* Dynamic zoom controls (+ and -) for adjusting font size.
* Share button to copy the experiment URL to the clipboard.
* Mobile-responsive layout supporting desktop, tablet, and mobile viewport sizes.
=======
# CSS-lab-simulation
>>>>>>> c9df3f11b0617656f6618b46d51093bbde88b8ee
