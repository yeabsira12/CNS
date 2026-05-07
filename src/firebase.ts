import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut, onAuthStateChanged, User } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

const firebaseConfig = {
  apiKey: "AIzaSyBpxMNPbyH-_DrCtg8VZC2WfBtdo85o9D0",
  authDomain: "c-n-s-f7175.firebaseapp.com",
  projectId: "c-n-s-f7175",
  storageBucket: "c-n-s-f7175.firebasestorage.app",
  messagingSenderId: "724796544045",
  appId: "1:724796544045:web:f3fbc7c7c2b5eefff754a4"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

export const googleProvider = new GoogleAuthProvider();

export { signInWithPopup, signOut, onAuthStateChanged };
export type { User };