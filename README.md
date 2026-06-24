# Ouroboros-
# OuroborosArchitect: A Human-AI Co-Designed Ternary Cipher

Developed by Eleni Diakogianni.

I have no formal background in cryptography or advanced mathematics. This project is an experimental proof-of-concept in human-AI collaboration, showing how an ambitious non-expert can architect a mathematically sound cryptographic system through structured AI interaction.

### Features

* **Base-3 Logic:** Natively encrypts and processes information using ternary digits (`0`, `1`, `2`) instead of binary bits.
* **Post-Quantum Scaffold:** Employs a Radix-3 Number Theoretic Transform (NTT) loop across Galois Field GF(17497) for internal permutation.
* **Zero Bias Optimization:** Implements strict cryptographic rejection sampling to completely eliminate statistical modulo-3 key bias.
* **Production Standards:** Equipped with `HMAC-SHA256` integrity verifications, constant-time verification checks, and standard type hinting.

### Disclaimer

This code serves strictly educational and scientific purposes. Never deploy custom cryptography routines ("roll your own crypto") for high-stakes production data security.
