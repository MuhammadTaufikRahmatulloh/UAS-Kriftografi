// ================================================================
//  1.  ALGORITMA S-DES (LENGKAP)
// ================================================================
const SDES = {
    P10: [2, 4, 1, 6, 3, 9, 0, 8, 7, 5],
    P8: [5, 2, 6, 3, 7, 4, 9, 8],
    IP: [1, 5, 2, 0, 3, 7, 4, 6],
    IP_INV: [3, 0, 2, 4, 6, 1, 7, 5],
    EP: [3, 0, 1, 2, 1, 2, 3, 0],
    P4: [1, 3, 2, 0],
    S0: [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ],
    S1: [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ],

    permute(bits, table) { return table.map(i => bits[i]); },
    split(bits, n) { return [bits.slice(0, n), bits.slice(n)]; },
    leftShift(bits, n) { return bits.slice(n).concat(bits.slice(0, n)); },
    xor(a, b) { return a.map((x, i) => x ^ b[i]); },

    generateKeys(key10) {
        const p10 = this.permute(key10, this.P10);
        let [l, r] = this.split(p10, 5);
        l = this.leftShift(l, 1);
        r = this.leftShift(r, 1);
        const k1 = this.permute(l.concat(r), this.P8);
        l = this.leftShift(l, 2);
        r = this.leftShift(r, 2);
        const k2 = this.permute(l.concat(r), this.P8);
        return { k1, k2 };
    },

    fk(bits, key) {
        const [l, r] = this.split(bits, 4);
        const ep = this.permute(r, this.EP);
        const x = this.xor(ep, key);
        const [x0, x1] = this.split(x, 4);
        const row0 = (x0[0] << 1) | x0[3],
            col0 = (x0[1] << 1) | x0[2];
        const v0 = this.S0[row0][col0];
        const row1 = (x1[0] << 1) | x1[3],
            col1 = (x1[1] << 1) | x1[2];
        const v1 = this.S1[row1][col1];
        let sOut = [(v0 >> 1) & 1, v0 & 1, (v1 >> 1) & 1, v1 & 1];
        const p4 = this.permute(sOut, this.P4);
        const out = this.xor(l, p4);
        return out.concat(r);
    },

    encrypt(plain8, key10) {
        const keys = this.generateKeys(key10);
        return this._cipher(plain8, keys.k1, keys.k2);
    },
    decrypt(cipher8, key10) {
        const keys = this.generateKeys(key10);
        return this._cipher(cipher8, keys.k2, keys.k1);
    },
    _cipher(input, kFirst, kSecond) {
        const ip = this.permute(input, this.IP);
        let step1 = this.fk(ip, kFirst);
        const [l, r] = this.split(step1, 4);
        const swapped = r.concat(l);
        let step2 = this.fk(swapped, kSecond);
        return this.permute(step2, this.IP_INV);
    },

    getSteps(inputBits, keyBits, mode) {
        const steps = [];
        const push = (t, d) => steps.push({ title: t, data: d });
        const keys = this.generateKeys(keyBits);
        push('🔑 Key Generation (P10 → P8)', `K1: ${keys.k1.join('')}  |  K2: ${keys.k2.join('')}`);
        const ip = this.permute(inputBits, this.IP);
        push('📌 Initial Permutation (IP)', `${inputBits.join('')} → ${ip.join('')}`);
        const kFirst = mode === 'encrypt' ? keys.k1 : keys.k2;
        const kSecond = mode === 'encrypt' ? keys.k2 : keys.k1;
        let state = ip;
        const fk1 = this.fk(state, kFirst);
        push(` Round 1 (K${mode === 'encrypt' ? '1' : '2'})`, `Expansion → XOR → S-Box → P4 → XOR → ${fk1.join('')}`);
        const [l1, r1] = this.split(fk1, 4);
        const swapped1 = r1.concat(l1);
        push(' Swap', `L=${l1.join('')}  R=${r1.join('')}  →  ${swapped1.join('')}`);
        const fk2 = this.fk(swapped1, kSecond);
        push(` Round 2 (K${mode === 'encrypt' ? '2' : '1'})`, `Expansion → XOR → S-Box → P4 → XOR → ${fk2.join('')}`);
        const out = this.permute(fk2, this.IP_INV);
        push(' Final Permutation (IP⁻¹)', `${fk2.join('')} → ${out.join('')}`);
        return steps;
    }
};

// ================================================================
//  2.  ALGORITMA S-AES (LENGKAP)
// ================================================================
const SAES = {
    SBOX: [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7],
    RCON: [0x8, 0x3],
    xorNib(a, b) { return a ^ b; },
    subNib(n) { return this.SBOX[n]; },

    keyExpansion(key16) {
        const w0 = key16.slice(0, 4),
            w1 = key16.slice(4, 8);
        const rot = [w1[1], w1[2], w1[3], w1[0]];
        const subRot = rot.map(n => this.subNib(n));
        const w2 = w0.map((n, i) => this.xorNib(n, this.xorNib(subRot[i], this.RCON[0])));
        const w3 = w1.map((n, i) => this.xorNib(n, w2[i]));
        const rot2 = [w3[1], w3[2], w3[3], w3[0]];
        const subRot2 = rot2.map(n => this.subNib(n));
        const w4 = w2.map((n, i) => this.xorNib(n, this.xorNib(subRot2[i], this.RCON[1])));
        const w5 = w3.map((n, i) => this.xorNib(n, w4[i]));
        return { k0: w0.concat(w1), k1: w2.concat(w3), k2: w4.concat(w5) };
    },

    addRoundKey(state, key) { return state.map((n, i) => this.xorNib(n, key[i])); },
    subNibState(state) { return state.map(n => this.subNib(n)); },
    shiftRows(state) { return [state[0], state[1], state[3], state[2]]; },

    mixColumns(state) {
        const [a, b, c, d] = state;
        const gfMul2 = (x) => { let r = x << 1; if (r & 0x10) r ^= 0x3; return r & 0xF; };
        const gfMul3 = (x) => this.xorNib(gfMul2(x), x);
        return [
            this.xorNib(gfMul2(a), gfMul3(b)),
            this.xorNib(gfMul3(a), gfMul2(b)),
            this.xorNib(gfMul2(c), gfMul3(d)),
            this.xorNib(gfMul3(c), gfMul2(d))
        ];
    },

    encrypt(plain16, key16) {
        const keys = this.keyExpansion(key16);
        let state = this.addRoundKey(plain16, keys.k0);
        state = this.subNibState(state);
        state = this.shiftRows(state);
        state = this.mixColumns(state);
        state = this.addRoundKey(state, keys.k1);
        state = this.subNibState(state);
        state = this.shiftRows(state);
        state = this.addRoundKey(state, keys.k2);
        return state;
    },

    decrypt(cipher16, key16) {
        const keys = this.keyExpansion(key16);
        let state = this.addRoundKey(cipher16, keys.k2);
        state = this.shiftRows(state);
        state = this.subNibState(state);
        state = this.addRoundKey(state, keys.k1);
        state = this.mixColumns(state);
        state = this.shiftRows(state);
        state = this.subNibState(state);
        state = this.addRoundKey(state, keys.k0);
        return state;
    },

    getSteps(input, key, mode) {
        const steps = [];
        const push = (t, d) => steps.push({ title: t, data: d });
        const keys = this.keyExpansion(key);
        push('🔑 Key Expansion', `K0: ${keys.k0.join('')}  K1: ${keys.k1.join('')}  K2: ${keys.k2.join('')}`);
        let state;
        if (mode === 'encrypt') {
            state = this.addRoundKey(input, keys.k0);
            push('🔀 Initial AddRoundKey (K0)', `State XOR K0 → ${state.join('')}`);
            state = this.subNibState(state);
            push('🧩 SubNib', state.join(''));
            state = this.shiftRows(state);
            push('↕ ShiftRows', state.join(''));
            state = this.mixColumns(state);
            push('🌀 MixColumns (GF(2⁴))', state.join(''));
            state = this.addRoundKey(state, keys.k1);
            push('🔀 AddRoundKey K1', state.join(''));
            state = this.subNibState(state);
            push('🧩 SubNib', state.join(''));
            state = this.shiftRows(state);
            push('↕ ShiftRows', state.join(''));
            state = this.addRoundKey(state, keys.k2);
            push('🔀 AddRoundKey K2 (Final)', state.join(''));
        } else {
            state = this.addRoundKey(input, keys.k2);
            push('🔀 AddRoundKey K2 (Mulai Dekripsi)', state.join(''));
            state = this.shiftRows(state);
            push('↕ InvShiftRows', state.join(''));
            state = this.subNibState(state);
            push('🧩 SubNib (Inv)', state.join(''));
            state = this.addRoundKey(state, keys.k1);
            push('🔀 AddRoundKey K1', state.join(''));
            state = this.mixColumns(state);
            push('🌀 MixColumns (Inv)', state.join(''));
            state = this.shiftRows(state);
            push('↕ InvShiftRows', state.join(''));
            state = this.subNibState(state);
            push('🧩 SubNib (Inv)', state.join(''));
            state = this.addRoundKey(state, keys.k0);
            push('🔀 AddRoundKey K0 (Final)', state.join(''));
        }
        push('✅ Hasil Akhir', state.join(''));
        return steps;
    }
};

// ================================================================
//  3.  AES-128 (LENGKAP DENGAN STEP) — sesuai spesifikasi PDF
// ================================================================
const AES128 = {
    SBOX: [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ],

    RCON: [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36],

    keyExpansion(key) {
        const words = [];
        for (let i = 0; i < 4; i++) {
            words.push(key.slice(i * 4, i * 4 + 4));
        }
        for (let i = 4; i < 44; i++) {
            let temp = words[i - 1].slice();
            if (i % 4 === 0) {
                const rot = [temp[1], temp[2], temp[3], temp[0]];
                const sub = rot.map(b => this.SBOX[b]);
                sub[0] ^= this.RCON[(i / 4) - 1];
                temp = sub;
            }
            words[i] = words[i - 4].map((b, j) => b ^ temp[j]);
        }
        const roundKeys = [];
        for (let i = 0; i < 11; i++) {
            roundKeys.push(words.slice(i * 4, i * 4 + 4).flat());
        }
        return roundKeys;
    },

    subBytes(state) { return state.map(b => this.SBOX[b]); },
    
    shiftRows(state) {
        const s = state.slice();
        [s[1], s[5], s[9], s[13]] = [s[5], s[9], s[13], s[1]];
        [s[2], s[6], s[10], s[14]] = [s[10], s[14], s[2], s[6]];
        [s[3], s[7], s[11], s[15]] = [s[15], s[3], s[7], s[11]];
        return s;
    },

    mixColumns(state) {
        const s = state.slice();
        const gfMul2 = (x) => {
            let r = x << 1;
            if (r > 0xFF) r ^= 0x1B;
            return r & 0xFF;
        };
        const gfMul3 = (x) => gfMul2(x) ^ x;
        
        for (let c = 0; c < 4; c++) {
            const i = c * 4;
            const a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
            s[i] = gfMul2(a0) ^ gfMul3(a1) ^ a2 ^ a3;
            s[i+1] = a0 ^ gfMul2(a1) ^ gfMul3(a2) ^ a3;
            s[i+2] = a0 ^ a1 ^ gfMul2(a2) ^ gfMul3(a3);
            s[i+3] = gfMul3(a0) ^ a1 ^ a2 ^ gfMul2(a3);
        }
        return s;
    },

    addRoundKey(state, key) { return state.map((b, i) => b ^ key[i]); },

    encrypt(plain, key) {
        const rk = this.keyExpansion(key);
        let state = this.addRoundKey(plain, rk[0]);
        for (let r = 1; r < 10; r++) {
            state = this.subBytes(state);
            state = this.shiftRows(state);
            state = this.mixColumns(state);
            state = this.addRoundKey(state, rk[r]);
        }
        state = this.subBytes(state);
        state = this.shiftRows(state);
        state = this.addRoundKey(state, rk[10]);
        return state;
    },

    decrypt(cipher, key) {
        const rk = this.keyExpansion(key);
        let state = this.addRoundKey(cipher, rk[10]);
        for (let r = 9; r > 0; r--) {
            state = this.shiftRows(state);
            state = this.subBytes(state);
            state = this.addRoundKey(state, rk[r]);
            state = this.mixColumns(state);
        }
        state = this.shiftRows(state);
        state = this.subBytes(state);
        state = this.addRoundKey(state, rk[0]);
        return state;
    },

    getSteps(input, key, mode) {
        const steps = [];
        const push = (t, d) => steps.push({ title: t, data: d });
        const rk = this.keyExpansion(key);
        let state = this.addRoundKey(input, rk[0]);
        
        push('🔑 Key Expansion (11 round keys)', 
            rk.map((k, i) => `K${i}: ${k.map(b => b.toString(16).padStart(2,'0')).join(' ')}`).join('\n'));
        
        push('🔀 Initial Round - AddRoundKey (K0)', 
            state.map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        for (let r = 1; r < 10; r++) {
            state = this.subBytes(state);
            push(`🧩 Round ${r} - SubBytes`, 
                state.map(b => b.toString(16).padStart(2, '0')).join(' '));
            state = this.shiftRows(state);
            push(`↕ Round ${r} - ShiftRows`, 
                state.map(b => b.toString(16).padStart(2, '0')).join(' '));
            state = this.mixColumns(state);
            push(`🌀 Round ${r} - MixColumns`, 
                state.map(b => b.toString(16).padStart(2, '0')).join(' '));
            state = this.addRoundKey(state, rk[r]);
            push(`🔀 Round ${r} - AddRoundKey (K${r})`, 
                state.map(b => b.toString(16).padStart(2, '0')).join(' '));
        }
        
        state = this.subBytes(state);
        push('🧩 Round 10 - SubBytes (Final)', 
            state.map(b => b.toString(16).padStart(2, '0')).join(' '));
        state = this.shiftRows(state);
        push('↕ Round 10 - ShiftRows (Final)', 
            state.map(b => b.toString(16).padStart(2, '0')).join(' '));
        state = this.addRoundKey(state, rk[10]);
        push('🔀 Round 10 - AddRoundKey (K10) — Tanpa MixColumns', 
            state.map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        const result = mode === 'encrypt' ? this.encrypt(input, key) : this.decrypt(input, key);
        push('✅ Hasil Akhir', 
            result.map(b => b.toString(16).padStart(2, '0')).join(' '));
        return steps;
    }
};

// ================================================================
//  4.  DES (LENGKAP DENGAN STEP)
// ================================================================
const DES = {
    IP: [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ],
    
    IP_INV: [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ],
    
    E: [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ],
    
    P: [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ],
    
    PC1: [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ],
    
    PC2: [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ],
    
    SHIFTS: [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1],
    
    SBOX: [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ],

    permute(bits, table) { return table.map(i => bits[i - 1]); },
    split(bits, n) { return [bits.slice(0, n), bits.slice(n)]; },
    xor(a, b) { return a.map((x, i) => x ^ b[i]); },
    
    bytesToBits(bytes) {
        const bits = [];
        for (const b of bytes) {
            for (let i = 7; i >= 0; i--) {
                bits.push((b >> i) & 1);
            }
        }
        return bits;
    },
    
    bitsToBytes(bits) {
        const bytes = [];
        for (let i = 0; i < bits.length; i += 8) {
            let b = 0;
            for (let j = 0; j < 8; j++) {
                b = (b << 1) | bits[i + j];
            }
            bytes.push(b);
        }
        return bytes;
    },

    generateKeys(keyBits) {
        const pc1 = this.permute(keyBits, this.PC1);
        let [c, d] = this.split(pc1, 28);
        const subkeys = [];
        for (let i = 0; i < 16; i++) {
            const shift = this.SHIFTS[i];
            c = c.slice(shift).concat(c.slice(0, shift));
            d = d.slice(shift).concat(d.slice(0, shift));
            const cd = c.concat(d);
            const subkey = this.permute(cd, this.PC2);
            subkeys.push(subkey);
        }
        return subkeys;
    },

    fk(bits, key) {
        const [l, r] = this.split(bits, 32);
        const expanded = this.permute(r, this.E);
        const xored = this.xor(expanded, key);
        let sOut = [];
        for (let i = 0; i < 8; i++) {
            const sixBits = xored.slice(i * 6, i * 6 + 6);
            const row = (sixBits[0] << 1) | sixBits[5];
            const col = (sixBits[1] << 3) | (sixBits[2] << 2) | (sixBits[3] << 1) | sixBits[4];
            const val = this.SBOX[i][row][col];
            sOut.push((val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1);
        }
        const p = this.permute(sOut, this.P);
        const result = this.xor(l, p);
        return result.concat(r);
    },

    encrypt(plainBytes, keyBytes) {
        const plainBits = this.bytesToBits(plainBytes);
        const keyBits = this.bytesToBits(keyBytes);
        const subkeys = this.generateKeys(keyBits);
        return this._cipher(plainBits, subkeys);
    },

    decrypt(cipherBytes, keyBytes) {
        const cipherBits = this.bytesToBits(cipherBytes);
        const keyBits = this.bytesToBits(keyBytes);
        const subkeys = this.generateKeys(keyBits).reverse();
        return this._cipher(cipherBits, subkeys);
    },

    _cipher(input, subkeys) {
        let bits = this.permute(input, this.IP);
        for (let i = 0; i < 16; i++) {
            bits = this.fk(bits, subkeys[i]);
            if (i < 15) {
                const [l, r] = this.split(bits, 32);
                bits = r.concat(l);
            }
        }
        const output = this.permute(bits, this.IP_INV);
        return this.bitsToBytes(output);
    },

    getSteps(inputBytes, keyBytes, mode) {
        const steps = [];
        const push = (t, d) => steps.push({ title: t, data: d });
        
        const inputBits = this.bytesToBits(inputBytes);
        const keyBits = this.bytesToBits(keyBytes);
        const subkeys = this.generateKeys(keyBits);
        
        push('🔑 Generate Keys (PC-1 → Left Shift → PC-2)', 
            subkeys.map((k, i) => `K${i+1}: ${k.join('')}`).join('\n'));
        
        const ip = this.permute(inputBits, this.IP);
        push('📌 Initial Permutation (IP)', 
            `${inputBits.join('')} → ${ip.join('')}`);
        
        let bits = ip;
        for (let i = 0; i < 16; i++) {
            const keyIdx = mode === 'encrypt' ? i : 15 - i;
            const before = bits.join('');
            bits = this.fk(bits, subkeys[keyIdx]);
            push(`🔁 Round ${i+1} (K${keyIdx+1}) — Expansion → XOR → S-Box → P → XOR`, 
                `${before} → ${bits.join('')}`);
            if (i < 15) {
                const [l, r] = this.split(bits, 32);
                bits = r.concat(l);
                push(`🔄 Swap after R${i+1}`, `L=${l.join('')} R=${r.join('')} → ${bits.join('')}`);
            }
        }
        
        const final = this.permute(bits, this.IP_INV);
        push('✅ Final Permutation (IP⁻¹)', 
            `${bits.join('')} → ${final.join('')}`);
        
        const result = this.bitsToBytes(final);
        push('📦 Hasil Akhir (bytes)', 
            result.map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        return steps;
    }
};

// ================================================================
//  5.  RENDERER UI
// ================================================================
const algoConfig = {
    des: {
        name: 'DES',
        module: DES,
        inputLabel: 'Plaintext/Ciphertext (hex, 64-bit / 8 byte)',
        keyLabel: 'Key (hex, 64-bit / 8 byte)',
        inputPlaceholder: '0123456789abcdef',
        keyPlaceholder: 'fedcba9876543210',
        parseInput: (s) => {
            const bytes = [];
            for (let i = 0; i < s.length; i += 2) {
                bytes.push(parseInt(s.substr(i, 2), 16));
            }
            return bytes;
        },
        formatResult: (result) => result.map(b => b.toString(16).padStart(2, '0')).join(''),
        validate: (input, key) => {
            if (input.length !== 16) throw new Error('Input harus 16 karakter hex (8 byte)');
            if (key.length !== 16) throw new Error('Key harus 16 karakter hex (8 byte)');
        }
    },
    sdes: {
        name: 'S-DES',
        module: SDES,
        inputLabel: 'Plaintext/Ciphertext (8-bit biner)',
        keyLabel: 'Key (10-bit biner)',
        inputPlaceholder: '10101010',
        keyPlaceholder: '1010101010',
        parseInput: (s) => s.split('').map(c => parseInt(c)),
        formatResult: (result) => result.join(''),
        validate: (input, key) => {
            if (input.length !== 8) throw new Error('Input harus 8 bit biner');
            if (key.length !== 10) throw new Error('Key harus 10 bit biner');
            if (input.some(b => isNaN(b) || b < 0 || b > 1)) throw new Error('Hanya boleh 0 atau 1');
            if (key.some(b => isNaN(b) || b < 0 || b > 1)) throw new Error('Hanya boleh 0 atau 1');
        }
    },
    aes: {
        name: 'AES',
        module: AES128,
        inputLabel: 'Plaintext/Ciphertext (hex, 128-bit / 16 byte)',
        keyLabel: 'Key (hex, 128-bit / 16 byte)',
        inputPlaceholder: '00112233445566778899aabbccddeeff',
        keyPlaceholder: '000102030405060708090a0b0c0d0e0f',
        parseInput: (s) => {
            const bytes = [];
            for (let i = 0; i < s.length; i += 2) {
                bytes.push(parseInt(s.substr(i, 2), 16));
            }
            return bytes;
        },
        formatResult: (result) => result.map(b => b.toString(16).padStart(2, '0')).join(''),
        validate: (input, key) => {
            if (input.length !== 32) throw new Error('Input harus 32 karakter hex (16 byte)');
            if (key.length !== 32) throw new Error('Key harus 32 karakter hex (16 byte)');
        }
    },
    saes: {
        name: 'S-AES',
        module: SAES,
        inputLabel: 'Plaintext/Ciphertext (hex, 16-bit / 4 nibble)',
        keyLabel: 'Key (hex, 16-bit / 4 nibble)',
        inputPlaceholder: 'a1b2',
        keyPlaceholder: 'c3d4',
        parseInput: (s) => s.split('').map(c => parseInt(c, 16)),
        formatResult: (result) => result.map(n => n.toString(16).toUpperCase()).join(''),
        validate: (input, key) => {
            if (input.length !== 4) throw new Error('Input harus 4 karakter hex (4 nibble)');
            if (key.length !== 4) throw new Error('Key harus 4 karakter hex (4 nibble)');
        }
    }
};

let currentAlgo = 'des';
let currentResult = null;
let currentSteps = [];

function renderApp() {
    const content = document.getElementById('appContent');
    const config = algoConfig[currentAlgo];
    const m = config.module;

    content.innerHTML = `
        <div class="card">
            <h2>${config.name}</h2>
            <div class="card-sub">Enkripsi / Dekripsi dengan tampilan step-by-step</div>

            <form id="cryptoForm">
                <div class="form-group">
                    <label>${config.inputLabel}</label>
                    <input type="text" id="inputData" 
                           placeholder="${config.inputPlaceholder}" 
                           value="${config.inputPlaceholder}">
                </div>
                <div class="form-group">
                    <label>${config.keyLabel}</label>
                    <input type="text" id="keyData" 
                           placeholder="${config.keyPlaceholder}" 
                           value="${config.keyPlaceholder}">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Mode</label>
                        <select id="modeSelect">
                            <option value="encrypt">🔒 Enkripsi</option>
                            <option value="decrypt">🔓 Dekripsi</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex:0 0 auto;">
                        <div class="btn-group" style="margin-top:0;">
                            <button type="submit" class="btn btn-primary">▶ Submit</button>
                            <button type="reset" class="btn btn-secondary" id="resetBtn">↺ Reset</button>
                        </div>
                    </div>
                </div>
            </form>
        </div>

        <div class="card" id="resultCard" style="display:none;">
            <h3>📊 Hasil</h3>
            <div id="resultDisplay"></div>

            <div class="solution-toggle" id="solutionToggle">
                <span class="icon">📖</span>
                <span>Tampilkan Solusi Penyelesaian</span>
                <span id="toggleIcon">▸</span>
            </div>
            <div class="solution-content" id="solutionContent"></div>
        </div>
    `;

    document.getElementById('cryptoForm').addEventListener('submit', function(e) {
        e.preventDefault();
        processCrypto();
    });

    document.getElementById('resetBtn').addEventListener('click', function() {
        document.getElementById('inputData').value = config.inputPlaceholder;
        document.getElementById('keyData').value = config.keyPlaceholder;
        document.getElementById('resultCard').style.display = 'none';
        currentResult = null;
        currentSteps = [];
    });

    document.getElementById('solutionToggle').addEventListener('click', function() {
        const content = document.getElementById('solutionContent');
        const icon = document.getElementById('toggleIcon');
        content.classList.toggle('show');
        icon.textContent = content.classList.contains('show') ? '▾' : '▸';
    });
}

function processCrypto() {
    const config = algoConfig[currentAlgo];
    const m = config.module;
    const inputStr = document.getElementById('inputData').value.trim();
    const keyStr = document.getElementById('keyData').value.trim();
    const mode = document.getElementById('modeSelect').value;

    try {
        config.validate(inputStr, keyStr);
        const input = config.parseInput(inputStr);
        const key = config.parseInput(keyStr);
        
        let result, steps;
        if (mode === 'encrypt') {
            result = m.encrypt(input, key);
            steps = m.getSteps(input, key, 'encrypt');
        } else {
            result = m.decrypt(input, key);
            steps = m.getSteps(input, key, 'decrypt');
        }

        currentResult = result;
        currentSteps = steps;
        displayResult(result, steps, mode);

    } catch (err) {
        alert('❌ Error: ' + err.message);
    }
}

function displayResult(result, steps, mode) {
    const card = document.getElementById('resultCard');
    const display = document.getElementById('resultDisplay');
    const solution = document.getElementById('solutionContent');
    const config = algoConfig[currentAlgo];

    card.style.display = 'block';
    const resultStr = config.formatResult(result);
    const label = mode === 'encrypt' ? 'Ciphertext' : 'Plaintext';

    display.innerHTML = `
        <div class="result-box">
            <div class="label">${label}</div>
            <div class="value highlight">${resultStr}</div>
        </div>
    `;

    let html = '';
    steps.forEach((s) => {
        html += `<div class="step">
                    <div class="step-title">${s.title}</div>
                    <div class="step-data">${s.data}</div>
                </div>`;
    });
    solution.innerHTML = html;
    solution.classList.remove('show');
    document.getElementById('toggleIcon').textContent = '▸';
}

// ================================================================
//  6.  NAVIGASI
// ================================================================
document.getElementById('navTabs').addEventListener('click', function(e) {
    const btn = e.target.closest('button');
    if (!btn) return;
    const algo = btn.dataset.algo;
    if (!algo) return;
    
    document.querySelectorAll('#navTabs button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentAlgo = algo;
    renderApp();
    document.getElementById('resultCard').style.display = 'none';
    currentResult = null;
    currentSteps = [];
});

// ================================================================
//  7.  INIT
// ================================================================
renderApp();