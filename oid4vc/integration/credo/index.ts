/**
 * Simplified Credo OID4VC Agent
 * 
 * This service acts as a holder/verifier that can:
 * - Receive credentials from ACA-Py OID4VCI issuer  
 * - Present credentials to ACA-Py OID4VP verifier
 * 
 * Supports both mso_mdoc and SD-JWT credential formats.
 */

// IMPORTANT: Import askar-nodejs first to register the native bindings
// before any credo-ts packages that depend on @openwallet-foundation/askar-shared
import '@openwallet-foundation/askar-nodejs';

import express from 'express';
import issuanceRouter from './issuance.js';
import verificationRouter from './verification.js';
import { initializeAgent } from './agent.js';

const app = express();
const PORT = 3020;

// Middleware
app.use(express.json());
app.use((req: any, res: any, next: any) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }
  next();
});

// Health check endpoint
app.get('/health', (req: any, res: any) => {
  res.json({
    status: 'healthy',
    service: 'credo-oid4vc-agent',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Mount routers
app.use('/oid4vci', issuanceRouter);
app.use('/oid4vp', verificationRouter);

// Start server
const startServer = async () => {
  try {
    await initializeAgent(PORT);
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Credo OID4VC Agent running on port ${PORT}`);
      console.log(`📋 Health check: http://localhost:${PORT}/health`);
      console.log(`🎫 Accept credentials: POST http://localhost:${PORT}/oid4vci/accept-offer`);
      console.log(`📤 Present credentials: POST http://localhost:${PORT}/oid4vp/present`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer().catch(console.error);
