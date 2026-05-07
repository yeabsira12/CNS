# Cryptographic Toolset with Federated Authentication

This is a comprehensive tool developed to explore and implement various cryptographic standards. It provides a user-friendly interface for both symmetric and asymmetric encryption methods, secured behind a modern identity management system.

## Key Features

- Federated Identity: This tool uses Google Authentication to manage user access, demonstrating a decentralized approach to identity management.
- Asymmetric Encryption: Support for RSA 2048-bit encryption and decryption. This implementation follows standard PEM format for keys and uses secure OAEP padding.
- Symmetric Algorithms:
    - Advanced Encryption Standard (AES) in CBC mode with Pkcs7 padding.
    - Triple DES (3DES) for legacy system compatibility.
    - One-Time Pad (OTP) for theoretically unbreakable XOR-based encryption.
- Local Key Management: Integrated utility for generating 2048-bit RSA key pairs directly in the browser.

## Technical Implementation

The application is built using React and TypeScript for a robust frontend experience. Cryptographic operations are handled locally using industry-standard libraries like crypto-js and node-forge to ensure data privacy.

For the backend, Firebase provides the authentication gateway and a secure database structure governed by granular security rules. This ensures that only authenticated users can access their encryption work sessions.

## Setup Instructions

To get this project running locally, you will need a modern Node.js environment.

1. Clone the repository to your local machine.
2. Run `npm install` to set up all necessary dependencies.
3. You will need to link a Firebase project for the authentication to function:
   - Create a project on the Firebase console.
   - Enable Google as an authentication provider.
   - Set up a Firestore database.
   - Place your unique configuration in a file named `firebase-applet-config.json` at the project root.
4. Start the development server with `npm run dev`.
5. For a production-ready build, use `npm run build`.

## Project Security

The database is protected by specific Firestore rules that enforce identity-based access control. No user can read or modify data belonging to another user, maintaining strict isolation of cryptographic assets.

Try it live for the better experience.  https://cns-amb2.onrender.com/
