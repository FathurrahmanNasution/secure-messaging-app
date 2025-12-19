const http = require('http');
const fs = require('fs');
const path = require('path');

// ==================== PURE MANUAL AES-256 IMPLEMENTATION ====================

// AES S-Box
const SBOX = [
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
];

// AES Inverse S-Box
const INV_SBOX = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Rcon for key expansion
const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// Galois Field multiplication
function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

// AES Key Expansion
function keyExpansion(key) {
  const w = [];
  const Nk = 8; // 256-bit key = 8 words
  const Nr = 14; // 14 rounds for AES-256
  
  for (let i = 0; i < Nk; i++) {
    w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
  }
  
  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    let temp = w[i-1].slice();
    if (i % Nk === 0) {
      temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]];
      temp[0] ^= RCON[i/Nk - 1];
    } else if (Nk > 6 && i % Nk === 4) {
      temp = temp.map(b => SBOX[b]);
    }
    w[i] = w[i-Nk].map((b, j) => b ^ temp[j]);
  }
  
  return w;
}

// AES SubBytes
function subBytes(state) {
  return state.map(row => row.map(b => SBOX[b]));
}

function invSubBytes(state) {
  return state.map(row => row.map(b => INV_SBOX[b]));
}

// AES ShiftRows
function shiftRows(state) {
  return [
    state[0],
    [state[1][1], state[1][2], state[1][3], state[1][0]],
    [state[2][2], state[2][3], state[2][0], state[2][1]],
    [state[3][3], state[3][0], state[3][1], state[3][2]]
  ];
}

function invShiftRows(state) {
  return [
    state[0],
    [state[1][3], state[1][0], state[1][1], state[1][2]],
    [state[2][2], state[2][3], state[2][0], state[2][1]],
    [state[3][1], state[3][2], state[3][3], state[3][0]]
  ];
}

// AES MixColumns
function mixColumns(state) {
  const result = [[], [], [], []];
  for (let c = 0; c < 4; c++) {
    result[0][c] = gmul(0x02, state[0][c]) ^ gmul(0x03, state[1][c]) ^ state[2][c] ^ state[3][c];
    result[1][c] = state[0][c] ^ gmul(0x02, state[1][c]) ^ gmul(0x03, state[2][c]) ^ state[3][c];
    result[2][c] = state[0][c] ^ state[1][c] ^ gmul(0x02, state[2][c]) ^ gmul(0x03, state[3][c]);
    result[3][c] = gmul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ gmul(0x02, state[3][c]);
  }
  return result;
}

function invMixColumns(state) {
  const result = [[], [], [], []];
  for (let c = 0; c < 4; c++) {
    result[0][c] = gmul(0x0e, state[0][c]) ^ gmul(0x0b, state[1][c]) ^ gmul(0x0d, state[2][c]) ^ gmul(0x09, state[3][c]);
    result[1][c] = gmul(0x09, state[0][c]) ^ gmul(0x0e, state[1][c]) ^ gmul(0x0b, state[2][c]) ^ gmul(0x0d, state[3][c]);
    result[2][c] = gmul(0x0d, state[0][c]) ^ gmul(0x09, state[1][c]) ^ gmul(0x0e, state[2][c]) ^ gmul(0x0b, state[3][c]);
    result[3][c] = gmul(0x0b, state[0][c]) ^ gmul(0x0d, state[1][c]) ^ gmul(0x09, state[2][c]) ^ gmul(0x0e, state[3][c]);
  }
  return result;
}

// AES AddRoundKey
function addRoundKey(state, roundKey) {
  return state.map((row, i) => row.map((b, j) => b ^ roundKey[j*4 + i]));
}

// Convert bytes to state matrix
function bytesToState(bytes) {
  const state = [[], [], [], []];
  for (let i = 0; i < 16; i++) {
    state[i % 4][Math.floor(i / 4)] = bytes[i];
  }
  return state;
}

// Convert state matrix to bytes
function stateToBytes(state) {
  const bytes = [];
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      bytes.push(state[j][i]);
    }
  }
  return bytes;
}

// AES Encrypt Block
function aesEncryptBlock(block, expandedKey) {
  let state = bytesToState(block);
  const Nr = 14;
  
  // Initial round
  state = addRoundKey(state, expandedKey.slice(0, 4).flat());
  
  // Main rounds
  for (let round = 1; round < Nr; round++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = mixColumns(state);
    state = addRoundKey(state, expandedKey.slice(round*4, (round+1)*4).flat());
  }
  
  // Final round
  state = subBytes(state);
  state = shiftRows(state);
  state = addRoundKey(state, expandedKey.slice(Nr*4, (Nr+1)*4).flat());
  
  return stateToBytes(state);
}

// AES Decrypt Block
function aesDecryptBlock(block, expandedKey) {
  let state = bytesToState(block);
  const Nr = 14;
  
  // Initial round
  state = addRoundKey(state, expandedKey.slice(Nr*4, (Nr+1)*4).flat());
  
  // Main rounds
  for (let round = Nr - 1; round > 0; round--) {
    state = invShiftRows(state);
    state = invSubBytes(state);
    state = addRoundKey(state, expandedKey.slice(round*4, (round+1)*4).flat());
    state = invMixColumns(state);
  }
  
  // Final round
  state = invShiftRows(state);
  state = invSubBytes(state);
  state = addRoundKey(state, expandedKey.slice(0, 4).flat());
  
  return stateToBytes(state);
}

// PKCS7 Padding
function pkcs7Pad(data, blockSize = 16) {
  const padding = blockSize - (data.length % blockSize);
  return Buffer.concat([data, Buffer.alloc(padding, padding)]);
}

function pkcs7Unpad(data) {
  const padding = data[data.length - 1];
  
  // Validate padding
  if (padding < 1 || padding > 16) {
    throw new Error('Invalid PKCS7 padding');
  }
  
  // Verify all padding bytes are correct
  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) {
      throw new Error('Invalid PKCS7 padding bytes');
    }
  }
  
  return data.slice(0, data.length - padding);
}

// AES-256-CBC Encryption
function aesEncrypt(plaintext, key, iv) {
  const expandedKey = keyExpansion(Array.from(key));
  const paddedData = pkcs7Pad(Buffer.from(plaintext, 'utf8'));
  const encrypted = [];
  let prevBlock = Array.from(iv);
  
  for (let i = 0; i < paddedData.length; i += 16) {
    const block = Array.from(paddedData.slice(i, i + 16));
    const xored = block.map((b, j) => b ^ prevBlock[j]);
    const encBlock = aesEncryptBlock(xored, expandedKey);
    encrypted.push(...encBlock);
    prevBlock = encBlock;
  }
  
  return Buffer.from(encrypted).toString('hex');
}

// AES-256-CBC Decryption
function aesDecrypt(ciphertext, key, iv) {
  const expandedKey = keyExpansion(Array.from(key));
  const encrypted = Buffer.from(ciphertext, 'hex');
  const decrypted = [];
  let prevBlock = Array.from(iv);
  
  for (let i = 0; i < encrypted.length; i += 16) {
    const block = Array.from(encrypted.slice(i, i + 16));
    const decBlock = aesDecryptBlock(block, expandedKey);
    const xored = decBlock.map((b, j) => b ^ prevBlock[j]);
    decrypted.push(...xored);
    prevBlock = block;
  }
  
  const unpadded = pkcs7Unpad(Buffer.from(decrypted));
  return unpadded.toString('utf8');
}

// ==================== PURE MANUAL RSA IMPLEMENTATION ====================

// Generate random bytes
function randomBytes(length) {
  const bytes = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

// BigInt modular exponentiation
function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

// Miller-Rabin primality test
function isProbablyPrime(n, k = 10) {
  if (n === 2n || n === 3n) return true;
  if (n < 2n || n % 2n === 0n) return false;
  
  let r = 0n, d = n - 1n;
  while (d % 2n === 0n) {
    r++;
    d /= 2n;
  }
  
  for (let i = 0; i < k; i++) {
    const a = 2n + BigInt(Math.floor(Math.random() * Number(n - 4n)));
    let x = modPow(a, d, n);
    
    if (x === 1n || x === n - 1n) continue;
    
    let continueLoop = false;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        continueLoop = true;
        break;
      }
    }
    if (!continueLoop) return false;
  }
  return true;
}

// Generate random prime
function generatePrime(bits) {
  while (true) {
    let num = 0n;
    for (let i = 0; i < bits; i++) {
      num = (num << 1n) | BigInt(Math.floor(Math.random() * 2));
    }
    num |= (1n << BigInt(bits - 1)) | 1n; // Set MSB and LSB
    if (isProbablyPrime(num)) return num;
  }
}

// Extended Euclidean Algorithm
function extendedGCD(a, b) {
  if (b === 0n) return { gcd: a, x: 1n, y: 0n };
  const result = extendedGCD(b, a % b);
  return { gcd: result.gcd, x: result.y, y: result.x - (a / b) * result.y };
}

// Modular inverse
function modInverse(a, m) {
  const result = extendedGCD(a, m);
  if (result.gcd !== 1n) return null;
  return ((result.x % m) + m) % m;
}

// Generate RSA key pair
function generateRSAKeyPair() {
  const p = generatePrime(512);
  const q = generatePrime(512);
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = 65537n;
  const d = modInverse(e, phi);
  
  return {
    publicKey: { e, n },
    privateKey: { d, n }
  };
}

// RSA Encryption
function rsaEncrypt(message, publicKey) {
  const msgBigInt = BigInt('0x' + Buffer.from(message).toString('hex'));
  const encrypted = modPow(msgBigInt, publicKey.e, publicKey.n);
  return encrypted.toString(16);
}

// RSA Decryption
function rsaDecrypt(ciphertext, privateKey) {
  const cipherBigInt = BigInt('0x' + ciphertext);
  const decrypted = modPow(cipherBigInt, privateKey.d, privateKey.n);
  const hex = decrypted.toString(16);
  return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
}

// SHA-256 Implementation
function sha256(message) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  
  const rotr = (n, x) => (x >>> n) | (x << (32 - n));
  const msg = Buffer.from(message, 'utf8');
  const bits = msg.length * 8;
  
  // Calculate correct padding length
  let paddingLength = (55 - msg.length) % 64;
  if (paddingLength < 0) paddingLength += 64;
  
  const padded = Buffer.concat([msg, Buffer.from([0x80]), Buffer.alloc(paddingLength), Buffer.alloc(8)]);
  padded.writeBigUInt64BE(BigInt(bits), padded.length - 8);
  
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  
  for (let i = 0; i < padded.length; i += 64) {
    const w = [];
    for (let j = 0; j < 16; j++) w[j] = padded.readUInt32BE(i + j * 4);
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(7, w[j-15]) ^ rotr(18, w[j-15]) ^ (w[j-15] >>> 3);
      const s1 = rotr(17, w[j-2]) ^ rotr(19, w[j-2]) ^ (w[j-2] >>> 10);
      w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
    }
    
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let j = 0; j < 64; j++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  
  const hash = Buffer.alloc(32);
  hash.writeUInt32BE(h0, 0); hash.writeUInt32BE(h1, 4); hash.writeUInt32BE(h2, 8); hash.writeUInt32BE(h3, 12);
  hash.writeUInt32BE(h4, 16); hash.writeUInt32BE(h5, 20); hash.writeUInt32BE(h6, 24); hash.writeUInt32BE(h7, 28);
  return hash.toString('hex');
}

// RSA Sign
function rsaSign(message, privateKey) {
  const hash = sha256(message);
  const hashBuffer = Buffer.from(hash, 'hex');
  return rsaEncrypt(hashBuffer, { e: privateKey.d, n: privateKey.n });
}

// RSA Verify
function rsaVerify(message, signature, publicKey) {
  const hash = sha256(message);
  try {
    const decrypted = rsaDecrypt(signature, { d: publicKey.e, n: publicKey.n });
    return decrypted.toString('hex') === hash;
  } catch {
    return false;
  }
}

// Store for user keys
const users = {};

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method === 'GET' && req.url === '/') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading page');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/styles.css') {
    fs.readFile(path.join(__dirname, 'styles.css'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading CSS');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/css' });
      res.end(data);
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/test.html') {
    fs.readFile(path.join(__dirname, 'test.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading test page');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/visualizations.html') {
    fs.readFile(path.join(__dirname, 'visualizations.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading visualizations page');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/latest-test-results') {
    fs.readdir(__dirname, (err, files) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to read directory' }));
        return;
      }
      
      const testFiles = files.filter(f => f.startsWith('test-results-') && f.endsWith('.json'));
      if (testFiles.length === 0) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No test results found' }));
        return;
      }
      
      testFiles.sort().reverse();
      const latestFile = testFiles[0];
      
      fs.readFile(path.join(__dirname, latestFile), (err, data) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to read test results' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(data);
      });
    });
    return;
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      const data = JSON.parse(body);

      if (req.url === '/save-test-results') {
        const results = data;
        const timestamp = new Date().toISOString().replace(/:/g, '_');
        const filename = `test-results-${timestamp}.json`;
        const filepath = path.join(__dirname, filename);
        
        fs.writeFile(filepath, JSON.stringify(results, null, 2), (err) => {
          if (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to save results' }));
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Results saved successfully', filename }));
        });
        return;
      }

      if (req.url === '/generate-keys') {
        const userId = data.userId;
        const keys = generateRSAKeyPair();
        users[userId] = keys;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          publicKey: { e: keys.publicKey.e.toString(), n: keys.publicKey.n.toString() },
          message: 'Keys generated successfully'
        }));
      }

      else if (req.url === '/encrypt') {
        const { message, recipientId, senderId } = data;
        
        if (!users[recipientId] || !users[senderId]) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'User not found' }));
          return;
        }

        // Generate AES key
        const aesKey = randomBytes(32);
        const iv = randomBytes(16);
        
        // Encrypt message with AES
        const encrypted = aesEncrypt(message, aesKey, iv);
        
        // Encrypt AES key with recipient's RSA public key
        const encryptedKey = rsaEncrypt(aesKey, users[recipientId].publicKey);
        
        // Sign the encrypted message with sender's private key (Encrypt-Then-Sign)
        const signature = rsaSign(encrypted, users[senderId].privateKey);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          encryptedMessage: encrypted,
          encryptedKey,
          iv: iv.toString('hex'),
          signature,
          senderId
        }));
      }

      else if (req.url === '/decrypt') {
        const { encryptedMessage, encryptedKey, iv, signature, senderId, recipientId } = data;
        
        if (!users[recipientId] || !users[senderId]) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'User not found' }));
          return;
        }

        try {
          // First, try to decrypt (only correct recipient can do this)
          const aesKey = rsaDecrypt(encryptedKey, users[recipientId].privateKey);
          
          // Validate AES key length (must be 32 bytes for AES-256)
          if (!aesKey || aesKey.length !== 32) {
            throw new Error('Invalid AES key length');
          }
          
          const decryptedMessage = aesDecrypt(encryptedMessage, aesKey, Buffer.from(iv, 'hex'));
          
          // Additional validation: check if decrypted message contains only valid UTF-8
          if (!decryptedMessage || decryptedMessage.length === 0) {
            throw new Error('Decryption produced empty result');
          }
          
          // Check for excessive non-printable characters (indicates wrong key)
          let nonPrintableCount = 0;
          for (let i = 0; i < Math.min(decryptedMessage.length, 50); i++) {
            const code = decryptedMessage.charCodeAt(i);
            // Count characters that are not printable ASCII or common whitespace
            if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
              nonPrintableCount++;
            }
          }
          
          // If more than 30% of checked characters are non-printable, likely wrong key
          if (nonPrintableCount / Math.min(decryptedMessage.length, 50) > 0.3) {
            throw new Error('Decrypted data contains invalid characters');
          }
          
          // Only verify signature if decryption succeeded (Encrypt-Then-Sign)
          const isValid = rsaVerify(encryptedMessage, signature, users[senderId].publicKey);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            decryptedMessage,
            signatureValid: isValid
          }));
        } catch (error) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            error: 'Decryption failed - you are not the intended recipient',
            details: error.message 
          }));
        }
      }

      else if (req.url === '/get-users') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ users: Object.keys(users) }));
      }

      else {
        res.writeHead(404);
        res.end('Not found');
      }
    });
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Pure manual AES-256 + RSA-1024 implementation');
});