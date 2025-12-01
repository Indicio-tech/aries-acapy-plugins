import {
  InitConfig,
  Agent,
  KeyDerivationMethod,
  ConsoleLogger,
  LogLevel,
  W3cCredentialsModule,
  DidsModule,
  SdJwtVcModule,
} from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { OpenId4VcHolderModule, OpenId4VcVerifierModule } from '@credo-ts/openid4vc';
import { v4 as uuidv4 } from 'uuid';

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

  const key = ariesAskar.storeGenerateRawKey({});

  const config: InitConfig = {
    label: 'credo-oid4vc-test-agent',
    logger: new ConsoleLogger(LogLevel.info),
    walletConfig: {
      id: `credo-test-wallet-${uuidv4()}`,
      key: key,
      keyDerivationMethod: KeyDerivationMethod.Raw,
      storage: {
        type: 'sqlite',
        inMemory: true,
      },
    },
  };

  const modules = {
    askar: new AskarModule({ ariesAskar }),
    w3cCredentials: new W3cCredentialsModule(),
    sdJwtVc: new SdJwtVcModule(),
    openId4VcHolder: new OpenId4VcHolderModule(),
    openId4VcVerifier: new OpenId4VcVerifierModule({
      baseUrl: `http://localhost:${port}`
    }),
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
