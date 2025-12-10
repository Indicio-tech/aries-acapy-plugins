import {
  InitConfig,
  Agent,
  KeyDerivationMethod,
  ConsoleLogger,
  LogLevel,
  W3cCredentialsModule,
  DidsModule,
  SdJwtVcModule,
  MdocModule,
  X509Module,
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
    mdoc: new MdocModule(),
    x509: new X509Module({
      trustedCertificates: [
        'MIICXTCCAgOgAwIBAgIUePdJY46IznbuvLsX8eYVnelHs3YwCgYIKoZIzj0EAwIwRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI1MTIwNTIyMDYxOFoXDTM1MTIwMzIyMDYxOFowRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEVMBMGA1UEAwwMVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGmSK+PqHTS+HFNTjJJXmSv18BTdcL8Eq6IXKlBeiNwTlDe3dva8ODxHFHOYyTR15+aiHFBDJAoHMrRIwrnmqb6OB0jCBzzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU6gbaUZDNZktdorDFiKVr9ZfaUzYwHwYDVR0jBBgwFoAU6gbaUZDNZktdorDFiKVr9ZfaUzYwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cHM6Ly9pbnRlcm9wZXZlbnQuc3BydWNlaWQuY29tL2ludGVyb3AuY3JsMCwGA1UdEgQlMCOGIWh0dHBzOi8vaW50ZXJvcGV2ZW50LnNwcnVjZWlkLmNvbTAKBggqhkjOPQQDAgNIADBFAiB9kJxELCZCD8BhiDeUtyxHhfUz4swkEuYHPg4ADNw5WAIhAOS73QdTv6iEGiveagYsOrAtZeH5m9GMLAkTCWoL7iCu',
        'MIICZDCCAgugAwIBAgIUfAWSwMngjar6yr0MtQJV59SJi6IwCgYIKoZIzj0EAwIwRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI1MTIwNTIyMDYxOFoXDTM1MTIwMzIyMDYxOFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATCdWy7razXv79GJ7I92RJOZFeikErfB+i8mmRMU6/MJT8b9g7osljuJ/wa64BChiQ6GCxTEAGdxzP5RC1cqzc5o4HSMIHPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQhZUn1zfTCG0KA1woVViZwrh5v7zAfBgNVHSMEGDAWgBTqBtpRkM1mS12isMWIpWv1l9pTNjA+BgNVHR8ENzA1MDOgMaAvhi1odHRwczovL2ludGVyb3BldmVudC5zcHJ1Y2VpZC5jb20vaW50ZXJvcC5jcmwwLAYDVR0SBCUwI4YhaHR0cHM6Ly9pbnRlcm9wZXZlbnQuc3BydWNlaWQuY29tMAoGCCqGSM49BAMCA0cAMEQCIEgqMGV1ElKbtWuq9jZc05gi0KwVGcntbfyoitjtUMRzAiANUxI312sfK2kZUp993TbiXXhVBv0oed90/2T9pC7W3A=='
      ]
    }),
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
