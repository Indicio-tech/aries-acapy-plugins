// IMPORTANT: Import askar-nodejs first to register the native bindings
// before any credo-ts packages that depend on @openwallet-foundation/askar-shared
import { askar } from '@openwallet-foundation/askar-nodejs';

import {
  Agent,
  ConsoleLogger,
  LogLevel,
  W3cCredentialsModule,
  DidsModule,
  SdJwtVcModule,
  MdocModule,
  X509Module,
} from '@credo-ts/core';
import type { InitConfig } from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { OpenId4VcModule } from '@credo-ts/openid4vc';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';

// Load trusted certificates from the certs directory
const loadTrustedCertificates = (): string[] => {
  const trustAnchorsDir = process.env.TRUST_ANCHORS_PATH || '/etc/credo/certs/trust-anchors';
  const certificates: string[] = [];
  
  try {
    if (fs.existsSync(trustAnchorsDir)) {
      const files = fs.readdirSync(trustAnchorsDir);
      for (const file of files) {
        if (file.endsWith('.pem')) {
          const certPath = path.join(trustAnchorsDir, file);
          const certPem = fs.readFileSync(certPath, 'utf-8').trim();
          // Credo 0.6.0 X509Module accepts PEM strings directly via X509Certificate.fromEncodedCertificate()
          // Do NOT base64 encode the PEM - pass it as-is
          certificates.push(certPem);
          console.log(`Loaded trust anchor: ${file}`);
        }
      }
    } else {
      console.warn(`Trust anchors directory not found: ${trustAnchorsDir}`);
    }
  } catch (error) {
    console.error(`Error loading trust anchors: ${error}`);
  }
  
  return certificates;
};

let agent: Agent | null = null;

export const getAgent = () => {
  if (!agent) {
    throw new Error('Agent not initialized');
  }
  return agent;
}

export const initializeAgent = async (port: number) => {
  if (agent) {
    console.log('Agent already initialized');
    return agent;
  }

  const config: InitConfig = {
    logger: new ConsoleLogger(LogLevel.info),
    allowInsecureHttpUrls: true,
  };

  const walletId = `credo-test-wallet-${uuidv4()}`;
  const walletKey = askar.storeGenerateRawKey({});

  const modules = {
    askar: new AskarModule({
      askar,
      store: {
        id: walletId,
        key: walletKey,
        keyDerivationMethod: 'raw',
        database: {
          type: 'sqlite',
          config: {
            inMemory: true,
          },
        },
      },
    }),
    w3cCredentials: new W3cCredentialsModule(),
    sdJwtVc: new SdJwtVcModule(),
    mdoc: new MdocModule(),
    x509: new X509Module({
      trustedCertificates: loadTrustedCertificates(),
    }),
    openid4vc: new OpenId4VcModule(),
    dids: new DidsModule(),
  };

  console.log('Modules passed:', Object.keys(modules));
  agent = new Agent({
    config,
    dependencies: agentDependencies,
    modules,
  });
  console.log('Agent modules:', Object.keys(agent.modules));

  await agent.initialize();
  console.log('🚀 Credo agent initialized');
  return agent;
};
