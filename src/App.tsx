import React, { useState, useEffect } from 'react';
import CryptoJS from 'crypto-js';
import forge from 'node-forge';
import { Copy, Lock, Unlock, Shield, Settings, Key, LogIn, LogOut, User as UserIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { auth, googleProvider, signInWithPopup, signOut, onAuthStateChanged, User } from './firebase';

type Algorithm = 'One-Time Pad (OTP)' | '3DES' | 'AES' | 'RSA (OpenSSL)';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [algorithm, setAlgorithm] = useState<Algorithm>('AES');
  
  // Encryption State
  const [encryptMessage, setEncryptMessage] = useState('');
  const [encryptKey, setEncryptKey] = useState('');
  const [encryptedResult, setEncryptedResult] = useState('');
  
  // Decryption State
  const [decryptMessage, setDecryptMessage] = useState('');
  const [decryptKey, setDecryptKey] = useState('');
  const [decryptedResult, setDecryptedResult] = useState('');

  const [copyStatus, setCopyStatus] = useState<'idle' | 'encrypt' | 'decrypt' | 'keys'>('idle');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setAuthLoading(false);
    });
    return () => unsubscribe();
  }, []);

  const handleLogin = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (e: any) {
      setError("Login Error: " + e.message);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
    } catch (e: any) {
      setError("Logout Error: " + e.message);
    }
  };

  // Helper to repeat/pad key as done in Java code for symmetric algos
  const prepareKey = (key: string, length: number) => {
    let finalKey = new Uint8Array(length);
    const keyBytes = new TextEncoder().encode(key);
    for (let i = 0; i < length; i++) {
      finalKey[i] = keyBytes[i % keyBytes.length];
    }
    return CryptoJS.lib.WordArray.create(finalKey as any);
  };

  const generateRSAKeys = () => {
    setError(null);
    try {
      const pair = forge.pki.rsa.generateKeyPair(2048);
      const pub = forge.pki.publicKeyToPem(pair.publicKey);
      const priv = forge.pki.privateKeyToPem(pair.privateKey);
      
      setEncryptKey(pub);
      setDecryptKey(priv);
      setCopyStatus('keys');
      setTimeout(() => setCopyStatus('idle'), 2000);
    } catch (e: any) {
      setError("Key Gen Error: " + e.message);
    }
  };

  // OTP Implementation matching Java logic
  const otpEncrypt = (text: string, key: string) => {
    if (text.length !== key.length) {
      throw new Error("Key length must equal plaintext length for OTP");
    }
    const ptBytes = new TextEncoder().encode(text);
    const keyBytes = new TextEncoder().encode(key);
    const ctBytes = new Uint8Array(ptBytes.length);
    for (let i = 0; i < ptBytes.length; i++) {
        ctBytes[i] = ptBytes[i] ^ keyBytes[i];
    }
    return btoa(String.fromCharCode(...ctBytes));
  };

  const otpDecrypt = (encoded: string, key: string) => {
    const ctBytes = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
    if (ctBytes.length !== key.length) {
      throw new Error("Key length must equal ciphertext length for OTP");
    }
    const keyBytes = new TextEncoder().encode(key);
    const ptBytes = new Uint8Array(ctBytes.length);
    for (let i = 0; i < ctBytes.length; i++) {
        ptBytes[i] = ctBytes[i] ^ keyBytes[i];
    }
    return new TextDecoder().decode(ptBytes);
  };

  const handleEncrypt = () => {
    setError(null);
    if (!encryptMessage || !encryptKey) return;
    
    try {
      let result = '';
      if (algorithm === 'One-Time Pad (OTP)') {
        result = otpEncrypt(encryptMessage, encryptKey);
      } else if (algorithm === '3DES') {
        const key = prepareKey(encryptKey, 24);
        const iv = CryptoJS.lib.WordArray.random(8);
        const encrypted = CryptoJS.TripleDES.encrypt(encryptMessage, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        });
        const combined = iv.clone();
        combined.concat(encrypted.ciphertext);
        result = CryptoJS.enc.Base64.stringify(combined);
      } else if (algorithm === 'AES') {
        const key = prepareKey(encryptKey, 16);
        const iv = CryptoJS.lib.WordArray.random(16);
        const encrypted = CryptoJS.AES.encrypt(encryptMessage, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        });
        const combined = iv.clone();
        combined.concat(encrypted.ciphertext);
        result = CryptoJS.enc.Base64.stringify(combined);
      } else if (algorithm === 'RSA (OpenSSL)') {
        const publicKey = forge.pki.publicKeyFromPem(encryptKey);
        const bytes = forge.util.encodeUtf8(encryptMessage);
        const encrypted = publicKey.encrypt(bytes, 'RSA-OAEP', {
          md: forge.md.sha256.create(),
          mgf1: {
            md: forge.md.sha1.create()
          }
        });
        result = forge.util.encode64(encrypted);
      }
      setEncryptedResult(result);
    } catch (e: any) {
      setError("Encryption Error: " + e.message);
    }
  };

  const handleDecrypt = () => {
    setError(null);
    if (!decryptMessage || !decryptKey) return;
    
    try {
      let result = '';
      if (algorithm === 'One-Time Pad (OTP)') {
        result = otpDecrypt(decryptMessage, decryptKey);
      } else if (algorithm === '3DES') {
        const combined = CryptoJS.enc.Base64.parse(decryptMessage);
        const iv = CryptoJS.lib.WordArray.create(combined.words.slice(0, 2), 8);
        const ciphertext = CryptoJS.lib.WordArray.create(combined.words.slice(2), combined.sigBytes - 8);
        const key = prepareKey(decryptKey, 24);
        const decrypted = CryptoJS.TripleDES.decrypt({ ciphertext: ciphertext } as any, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        });
        result = decrypted.toString(CryptoJS.enc.Utf8);
      } else if (algorithm === 'AES') {
        const combined = CryptoJS.enc.Base64.parse(decryptMessage);
        const iv = CryptoJS.lib.WordArray.create(combined.words.slice(0, 4), 16);
        const ciphertext = CryptoJS.lib.WordArray.create(combined.words.slice(4), combined.sigBytes - 16);
        const key = prepareKey(decryptKey, 16);
        const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertext } as any, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        });
        result = decrypted.toString(CryptoJS.enc.Utf8);
      } else if (algorithm === 'RSA (OpenSSL)') {
        const privateKey = forge.pki.privateKeyFromPem(decryptKey);
        const encryptedBytes = forge.util.decode64(decryptMessage);
        const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP', {
          md: forge.md.sha256.create(),
          mgf1: {
            md: forge.md.sha1.create()
          }
        });
        result = forge.util.decodeUtf8(decrypted);
      }
      setDecryptedResult(result || "Decryption failed (check key or algorithm)");
    } catch (e: any) {
      setError("Decryption Error: " + e.message);
    }
  };

  const copyToClipboard = (text: string, type: 'encrypt' | 'decrypt') => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopyStatus(type);
    setTimeout(() => setCopyStatus('idle'), 2000);
  };

  const isRSA = algorithm === 'RSA (OpenSSL)';

  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#CFD8DC] flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="font-bold text-[#141414] animate-pulse">Authenticating...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#CFD8DC] text-[#333] font-sans flex flex-col items-center">
      <div className="w-full max-w-[1100px] my-8 bg-[#E0E0E0] shadow-xl border border-gray-300 p-8 rounded-sm relative overflow-hidden">
        
        {/* Login Gate Overlay */}
        <AnimatePresence>
          {!user && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 z-50 bg-[#E0E0E0]/95 backdrop-blur-sm flex flex-col items-center justify-center p-8 text-center"
            >
              <motion.div 
                initial={{ scale: 0.9, y: 20 }}
                animate={{ scale: 1, y: 0 }}
                className="max-w-md w-full bg-white border border-gray-300 shadow-2xl p-10 flex flex-col gap-8 rounded-sm"
              >
                <div className="flex flex-col gap-2">
                  <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center self-center mb-2">
                    <Shield className="w-8 h-8" />
                  </div>
                  <h2 className="text-2xl font-bold text-[#141414]">Restricted Access</h2>
                  <p className="text-sm text-gray-500">Security Requirement:<br/>Federated Identity Management is Active.</p>
                </div>

                <div className="flex flex-col gap-4">
                  <p className="text-xs text-gray-400 italic">Sign in with your Google account to unlock the symmetric & asymmetric encryption tools.</p>
                  <button 
                    onClick={handleLogin}
                    className="flex items-center justify-center gap-3 bg-white hover:bg-gray-50 text-[#141414] font-bold py-3 border border-gray-300 shadow-md transition-all active:scale-[0.98] rounded-sm"
                  >
                    <svg className="w-5 h-5" viewBox="0 0 24 24">
                      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" />
                      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                    </svg>
                    Sign in with Google
                  </button>
                </div>

                <div className="text-[10px] text-gray-400 font-mono text-center">
                  Secure Access Protocol | Identity Federation
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Header with Padlocks */}
        <div className="flex items-center justify-between gap-3 mb-6 pb-4 border-b border-gray-400">
          <div className="flex items-center gap-3">
             <span className="text-2xl">🔒</span>
             <h1 className="text-2xl font-bold text-[#141414] tracking-wide">Secure Crypto Dashboard</h1>
          </div>

          <div className="flex items-center gap-4">
            {user && (
              <div className="flex items-center gap-3 bg-gray-200 border border-gray-300 p-1 pr-4 rounded-sm shadow-sm group">
                <img 
                  src={user.photoURL || ''} 
                  alt="Profile" 
                  className="w-10 h-10 border border-gray-400"
                  referrerPolicy="no-referrer"
                />
                <div className="flex flex-col text-right">
                  <span className="text-[10px] font-bold text-[#DE5622] leading-none mb-1">LOGGED AS {user.displayName?.split(' ')[0].toUpperCase()}</span>
                  <button 
                    onClick={handleLogout}
                    className="text-[9px] font-bold text-gray-500 hover:text-red-700 flex items-center justify-end gap-1 transition-colors"
                  >
                    <LogOut className="w-2.5 h-2.5" />
                    LOGOUT
                  </button>
                </div>
              </div>
            )}
            <span className="text-2xl">🔒</span>
          </div>
        </div>

        {error && (
          <div className="mb-6 bg-red-100 border border-red-400 text-red-700 px-4 py-2 rounded text-sm font-bold animate-pulse flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-xs hover:underline">Dismiss</button>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-10">
          
          {/* Left Column: Encrypt */}
          <div className="flex flex-col gap-4">
            <h2 className="text-[#3F558D] font-bold text-lg text-center underline decoration-dotted underline-offset-4">Message to Encrypt</h2>
            <textarea 
              value={encryptMessage}
              onChange={(e) => setEncryptMessage(e.target.value)}
              className="w-full h-44 p-3 bg-white border border-gray-400 focus:ring-1 focus:ring-blue-400 outline-none shadow-inner resize-none font-sans text-sm"
              placeholder={isRSA ? "Enter plaintext (OpenSSL RSA logic)..." : "Enter plaintext message..."}
            />
            
            <div className="flex flex-col gap-2 mt-2">
              <div className="flex items-center gap-3">
                <label className="text-[#DE5622] font-bold whitespace-nowrap border border-gray-400 px-3 py-2 bg-gray-200 min-w-[150px] text-center">
                  {isRSA ? 'Public Key (PEM)' : 'Encryption Key'}
                </label>
                <textarea 
                  value={encryptKey}
                  onChange={(e) => setEncryptKey(e.target.value)}
                  className={`flex-1 p-2 bg-white border border-gray-400 shadow-inner outline-none text-xs font-mono ${isRSA ? 'h-32' : 'h-10 leading-tight'}`}
                  placeholder={isRSA ? "-----BEGIN PUBLIC KEY-----..." : "Enter secret key..."}
                />
              </div>
              {isRSA && (
                <button 
                  onClick={generateRSAKeys}
                  className="self-end text-xs font-bold text-blue-700 hover:underline flex items-center gap-1"
                >
                  <Key className="w-3 h-3" />
                  {copyStatus === 'keys' ? 'New Keys Generated!' : 'Generate 2048-bit RSA Key Pair'}
                </button>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 mt-2">
              <button 
                onClick={handleEncrypt}
                className="bg-[#004D40] hover:bg-[#003d33] text-white py-3 flex items-center justify-center gap-2 font-bold transition-all shadow border border-black/20"
              >
                <Lock className="w-4 h-4" />
                Encrypt
              </button>
              <button 
                onClick={() => copyToClipboard(encryptedResult, 'encrypt')}
                className="bg-[#7B1D1D] hover:bg-[#681919] text-white py-3 flex items-center justify-center gap-2 font-bold transition-all shadow border border-black/20"
              >
                <Copy className="w-4 h-4" />
                {copyStatus === 'encrypt' ? 'Copied!' : 'Copy Encryption'}
              </button>
            </div>

            <textarea 
              readOnly
              value={encryptedResult}
              placeholder="Result will appear here..."
              className="w-full h-36 p-3 bg-white border border-gray-400 mt-2 outline-none shadow-sm font-sans text-xs break-all"
            />
          </div>

          {/* Right Column: Decrypt */}
          <div className="flex flex-col gap-4">
            <h2 className="text-[#3F558D] font-bold text-lg text-center underline decoration-dotted underline-offset-4">Message to Decrypt</h2>
            <textarea 
              value={decryptMessage}
              onChange={(e) => setDecryptMessage(e.target.value)}
              className="w-full h-44 p-3 bg-white border border-gray-400 focus:ring-1 focus:ring-blue-400 outline-none shadow-inner resize-none font-sans text-sm"
              placeholder="Enter encrypted Base64 string..."
            />
            
            <div className="flex flex-col gap-2 mt-2">
              <div className="flex items-center gap-3">
                <label className="text-[#DE5622] font-bold whitespace-nowrap border border-gray-400 px-3 py-2 bg-gray-200 min-w-[150px] text-center">
                  {isRSA ? 'Private Key (PEM)' : 'Decryption Key'}
                </label>
                <textarea 
                  value={decryptKey}
                  onChange={(e) => setDecryptKey(e.target.value)}
                  className={`flex-1 p-2 bg-white border border-gray-400 shadow-inner outline-none text-xs font-mono ${isRSA ? 'h-32' : 'h-10 leading-tight'}`}
                  placeholder={isRSA ? "-----BEGIN PRIVATE KEY-----..." : "Enter secret key..."}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 mt-2">
              <button 
                onClick={handleDecrypt}
                className="bg-[#004D40] hover:bg-[#003d33] text-white py-3 flex items-center justify-center gap-2 font-bold transition-all shadow border border-black/20"
              >
                <Unlock className="w-4 h-4" />
                Decrypt
              </button>
              <button 
                onClick={() => copyToClipboard(decryptedResult, 'decrypt')}
                className="bg-[#7B1D1D] hover:bg-[#681919] text-white py-3 flex items-center justify-center gap-2 font-bold transition-all shadow border border-black/20"
              >
                <Copy className="w-4 h-4" />
                {copyStatus === 'decrypt' ? 'Copied!' : 'Copy Decryption'}
              </button>
            </div>

            <textarea 
              readOnly
              value={decryptedResult}
              placeholder="Result will appear here..."
              className="w-full h-36 p-3 bg-white border border-gray-400 mt-2 outline-none shadow-sm font-sans text-sm"
            />
          </div>
        </div>

        {/* Algorithm Picker Footer Section */}
        <div className="mt-12 flex items-center justify-center">
          <div className="flex items-stretch shadow-md">
            <div className="flex items-center gap-2 bg-[#7590B0] text-white px-6 py-3 font-bold border border-[#5d7396]">
              <Settings className="w-4 h-4" />
              Choose Algorithm
            </div>
            <select 
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value as Algorithm)}
              className="bg-white px-6 py-3 border border-gray-400 border-l-0 font-bold focus:outline-none cursor-pointer hover:bg-gray-50 min-w-[280px]"
            >
              <option value="One-Time Pad (OTP)">One-Time Pad (OTP)</option>
              <option value="3DES">3DES</option>
              <option value="AES">AES</option>
              <option value="RSA (OpenSSL)">RSA (OpenSSL Style)</option>
            </select>
          </div>
        </div>

        <div className="mt-12 text-center text-xs text-slate-500 font-mono tracking-tight pb-2 border-t border-gray-300 pt-6">
          Advanced Encryption Suite | Symmetric & Asymmetric Protocol Implementation
        </div>
      </div>
    </div>
  );
}
