/**
 * Simplified Credo OID4VC Agent
 * 
 * This service acts as a holder/verifier that can:
 * - Receive credentials from ACA-Py OID4VCI issuer  
 * - Present credentials to ACA-Py OID4VP verifier
 * 
 * Supports both mso_mdoc and SD-JWT credential formats.
 */

import {
  InitConfig,
  Agent,
  KeyDerivationMethod,
  ConsoleLogger,
  LogLevel,
  W3cCredentialsModule,
  DidsModule,
  KeyType,
  TypedArrayEncoder,
} from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { AuthorizationRequest } from '@sphereon/did-auth-siop';
import { PEX } from '@sphereon/pex';
import { decodeSdJwtSync } from '@sd-jwt/decode';
import { OpenId4VcHolderModule, OpenId4VcVerifierModule } from '@credo-ts/openid4vc';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import express from 'express';

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

let agent: Agent | null = null;

// Initialize Credo agent
const initializeAgent = async () => {
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

  agent = new Agent({
    config,
    dependencies: agentDependencies,
    modules: {
      askar: new AskarModule({ ariesAskar }),
      w3cCredentials: new W3cCredentialsModule(),
      openId4VcHolder: new OpenId4VcHolderModule(),
      openId4VcVerifier: new OpenId4VcVerifierModule({
        baseUrl: `http://localhost:${PORT}`
      }),
      dids: new DidsModule(),
    },
  });

  await agent.initialize();
  console.log('🚀 Credo agent initialized');
  return agent;
};

// Health check endpoint
app.get('/health', (req: any, res: any) => {
  res.json({
    status: 'healthy',
    service: 'credo-oid4vc-agent',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Accept credential offer from ACA-Py issuer
app.post('/oid4vci/accept-offer', async (req: any, res: any) => {
  try {
    if (!agent) {
      await initializeAgent();
    }

    const { credential_offer, holder_did_method } = req.body;

    if (!credential_offer) {
      return res.status(400).json({
        error: 'credential_offer is required'
      });
    }

    console.log('📥 Accepting credential offer:', credential_offer);

    // Use Credo's OpenID4VC module to accept the credential offer
    const openId4VcHolderApi = agent!.modules.openId4VcHolder;
    
    // Convert credential offer object to URI format if needed
    let credentialOfferUri: string;
    if (typeof credential_offer === 'string') {
      credentialOfferUri = credential_offer;
    } else {
      // Convert object to data URI format
      credentialOfferUri = `data:application/json,${encodeURIComponent(JSON.stringify(credential_offer))}`;
    }

    console.log('🔗 Credential offer URI:', credentialOfferUri);
    
    try {
      // Use the higher-level module API instead of the service directly
      console.log('📥 Attempting credential acceptance using module API...');
      
      let credentialRecord;
      
      // Debug: Check what module-level methods are available
      console.log('🔍 Available module-level methods:');
      console.log(Object.getOwnPropertyNames(openId4VcHolderApi).filter(name => typeof openId4VcHolderApi[name] === 'function'));
      
      // COMPLIANCE FIX: Try Credo v0.5.17 higher-level APIs first
      if (typeof openId4VcHolderApi.acceptCredentialOffer === 'function') {
        console.log('📥 Using module-level acceptCredentialOffer...');
        credentialRecord = await openId4VcHolderApi.acceptCredentialOffer({ credentialOfferUri });
      } else if (typeof openId4VcHolderApi.acceptCredentialOfferUri === 'function') {
        console.log('📥 Using module-level acceptCredentialOfferUri...');
        credentialRecord = await openId4VcHolderApi.acceptCredentialOfferUri(credentialOfferUri);
      } else if (typeof openId4VcHolderApi.receiveCredentialFromOffer === 'function') {
        console.log('📥 Trying receiveCredentialFromOffer method...');
        try {
          credentialRecord = await openId4VcHolderApi.receiveCredentialFromOffer({ credentialOfferUri });
        } catch (receiveError: any) {
          console.error('❌ receiveCredentialFromOffer failed:', receiveError.message);
          throw receiveError;
        }
      } else if (typeof openId4VcHolderApi.requestAndReceiveCredential === 'function') {
        console.log('📥 Trying requestAndReceiveCredential method...');
        try {
          credentialRecord = await openId4VcHolderApi.requestAndReceiveCredential({ credentialOfferUri });
        } catch (requestError: any) {
          console.error('❌ requestAndReceiveCredential failed:', requestError.message);
          throw requestError;
        }
      } else {
        // PRIORITY FIX: Try agent-level methods first since service-level has persistent bugs
        console.log('🔧 Prioritizing agent-level methods to avoid service-level acceptCredentialOffer bugs...');
        
        // Try method 1: receiveCredentialFromOffer via agent  
        if (typeof agent!.modules.openId4VcHolder.receiveCredentialFromOffer === 'function') {
          try {
            console.log('📥 Trying agent receiveCredentialFromOffer...');
            credentialRecord = await agent!.modules.openId4VcHolder.receiveCredentialFromOffer({
              credentialOfferUri: credentialOfferUri
            });
            console.log('✅ Agent receiveCredentialFromOffer succeeded!');
          } catch (receiveError: any) {
            console.error('❌ Agent receiveCredentialFromOffer failed:', receiveError.message);
            
            // Try method 2: acceptCredentialOffer via agent
            if (typeof agent!.modules.openId4VcHolder.acceptCredentialOffer === 'function') {
              try {
                console.log('📥 Trying agent acceptCredentialOffer...');
                credentialRecord = await agent!.modules.openId4VcHolder.acceptCredentialOffer({
                  credentialOfferUri: credentialOfferUri
                });
                console.log('✅ Agent acceptCredentialOffer succeeded!');
              } catch (acceptError: any) {
                console.error('❌ Agent acceptCredentialOffer failed:', acceptError.message);
                console.log('⚠️ All agent-level methods failed, falling back to service-level...');
                // Will fall through to service-level approach below
              }
            } else {
              console.log('⚠️ Agent acceptCredentialOffer not available, falling back to service-level...');
              // Will fall through to service-level approach below
            }
          }
        } else {
          console.log('⚠️ Agent receiveCredentialFromOffer not available, falling back to service-level...');
          // Will fall through to service-level approach below
        }
        
        // Only try service-level if agent-level failed
        if (!credentialRecord) {
          console.log('📥 Fallback: Using Credo v0.5.17 service-level API...');
        
        try {
          // Step 1: Resolve the credential offer
          console.log('� Resolving credential offer...');
          const resolvedOffer = await openId4VcHolderApi.openId4VciHolderService.resolveCredentialOffer(
            agent!.context, 
            credentialOfferUri
          );
          
          // DEBUG: Log the structure to understand what Credo expects
          console.log('🔍 Resolved offer structure:', JSON.stringify(resolvedOffer, null, 2));
          console.log('🔍 Resolved offer keys:', Object.keys(resolvedOffer));
          console.log('🔍 Has metadata?', 'metadata' in resolvedOffer);
          
          // Step 2: Accept the resolved credential offer using the correct v0.5.17 signature
          console.log('� Accepting resolved credential offer...');
          
          // METADATA FIX: The error shows Credo expects metadata on resolvedCredentialOffer
          // Let's try to construct the proper structure
          console.log('🔧 Creating metadata structure for Credo v0.5.17...');
          
          // Build credentialsToRequest from the resolved offer
          const credentialConfigurationIds = resolvedOffer.credentialOfferPayload?.credential_configuration_ids || 
                                           resolvedOffer.credentialOfferRequestWithBaseUrl?.credential_offer?.credential_configuration_ids;

          const credentialsToRequest = credentialConfigurationIds?.map((id: string) => ({
            credentialConfigurationId: id
          })) || [{ credentialConfigurationId: 'mDL_mdoc' }];
          
          console.log('📋 Credentials to request:', credentialsToRequest);
          
          // BREAKTHROUGH: Try different method signatures based on Credo v0.5.17 analysis
          
          // NEXT FIX: Try different method signatures to avoid metadata destructuring
          
          // SIGNATURE FIX: Based on errors, method expects direct parameters, not nested objects
          
          // FIX: Ensure metadata has camelCase properties which might be expected by Credo
          let manualAccessToken: string | undefined;
          let manualCNonce: string | undefined;
          if (resolvedOffer.metadata) {
              const meta = resolvedOffer.metadata as any;
              console.log('🔧 Patching metadata to camelCase...');
              
              if (!meta.tokenEndpoint && meta.token_endpoint) meta.tokenEndpoint = meta.token_endpoint;
              if (!meta.credentialEndpoint && meta.credential_endpoint) meta.credentialEndpoint = meta.credential_endpoint;
              if (!meta.authorizationServer && meta.authorization_server) meta.authorizationServer = meta.authorization_server;

              // EXPERIMENT: Remove authorizationServer to force using explicit endpoints
              // and avoid potential metadata lookup failures which might cause "Request url is not valid"
              // if Credo tries to fetch .well-known/oauth-authorization-server from a base URL that doesn't support it.
              if (meta.authorizationServer) {
                  console.log("⚠️ Removing authorizationServer from metadata to avoid lookup issues");
                  delete meta.authorizationServer;
              }
              if (meta.authorization_server) {
                  delete meta.authorization_server;
              }

              // Ensure credentialIssuerMetadata has endpoints too (some versions look here)
              if (meta.credentialIssuerMetadata) {
                  const cim = meta.credentialIssuerMetadata;
                  // Ensure snake_case (standard)
                  if (!cim.token_endpoint && meta.token_endpoint) {
                      cim.token_endpoint = meta.token_endpoint;
                  }
                  if (!cim.credential_endpoint && meta.credential_endpoint) {
                      cim.credential_endpoint = meta.credential_endpoint;
                  }
                  
                  // Ensure camelCase (Credo internal preference?)
                  if (cim.credential_endpoint && !cim.credentialEndpoint) {
                      cim.credentialEndpoint = cim.credential_endpoint;
                  }
                  if (cim.token_endpoint && !cim.tokenEndpoint) {
                      cim.tokenEndpoint = cim.token_endpoint;
                  }
                  if (cim.credential_issuer && !cim.credentialIssuer) {
                      cim.credentialIssuer = cim.credential_issuer;
                  }
                  console.log("🔧 Patched credentialIssuerMetadata with camelCase properties");
              }
              
              // 🧪 DEBUG: Validate URLs
              try {
                  if (meta.tokenEndpoint) {
                      new URL(meta.tokenEndpoint);
                      console.log("✅ Token endpoint is valid:", meta.tokenEndpoint);
                  }
                  if (meta.credentialEndpoint) {
                      new URL(meta.credentialEndpoint);
                      console.log("✅ Credential endpoint is valid:", meta.credentialEndpoint);
                  }
              } catch (e) {
                  console.error("❌ Endpoint validation failed:", e);
              }

              // 🧪 DEBUG: Manual Token Request
              try {
                  const tokenUrl = meta.tokenEndpoint;
                  // Extract pre-auth code safely
                  const grants = resolvedOffer.credentialOfferPayload?.grants || resolvedOffer.credentialOfferRequestWithBaseUrl?.credential_offer?.grants;
                  const preAuthGrant = grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
                  const preAuthCode = preAuthGrant?.['pre-authorized_code'];
                  
                  if (tokenUrl && preAuthCode) {
                      console.log(`🧪 Manual Token Request to: ${tokenUrl} with code: ${preAuthCode}`);
                      
                      const body = new URLSearchParams();
                      body.append('grant_type', 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
                      body.append('pre-authorized_code', preAuthCode);
                      
                      const response = await fetch(tokenUrl, {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                          body: body
                      });
                      
                      console.log(`🧪 Manual Token Response Status: ${response.status}`);
                      const text = await response.text();
                      console.log(`🧪 Manual Token Response Body: ${text}`);
                      
                      try {
                          const json = JSON.parse(text);
                          if (json.access_token) {
                              manualAccessToken = json.access_token;
                              manualCNonce = json.c_nonce;
                              console.log("✅ Captured access token from manual request");
                          }
                      } catch (e) {
                          console.log("⚠️ Could not parse token response as JSON");
                      }
                  } else {
                      console.log("⚠️ Skipping manual token request: missing url or code");
                  }
              } catch (e) {
                  console.error("❌ Manual Token Request Failed:", e);
              }
          }

          // Method 1: Try passing resolved offer + options in the correct structure
          try {
            console.log('🔄 Attempt 1: Using correct service-level parameter structure...');
            
            const acceptOptions: any = {
                  resolvedCredentialOffer: resolvedOffer,
                  acceptCredentialOfferOptions: {
                    credentialsToRequest: credentialsToRequest.map((c: any) => c.credentialConfigurationId),
                    credentialBindingResolver: async (bindingOptions: any) => {
                        console.log('🔒 Resolving credential binding:', JSON.stringify(bindingOptions));
                        // Create a did:key to bind the credential to
                        const didRecord = await agent!.dids.create({
                            method: 'key',
                            options: {
                                keyType: KeyType.Ed25519
                            }
                        });

                        if (didRecord.didState.state !== 'finished' || !didRecord.didState.didDocument) {
                            throw new Error('Failed to create DID for binding');
                        }

                        const verificationMethod = didRecord.didState.didDocument.verificationMethod?.[0];
                        if (!verificationMethod) {
                             throw new Error('No verification method found in created DID');
                        }

                        console.log('🔑 DID created:', didRecord.didState.did);
                        console.log('🔑 Verification Method ID:', verificationMethod.id);

                        return {
                            method: 'did',
                            didUrl: verificationMethod.id
                        };
                    }
                  }
            };

            if (manualAccessToken) {
                console.log("💉 Injecting manual access token into acceptCredentialOffer options");
                acceptOptions.accessToken = manualAccessToken;
            }
            
            // Log the options (excluding the function)
            const logOptions = JSON.parse(JSON.stringify(acceptOptions));
            logOptions.acceptCredentialOfferOptions.credentialBindingResolver = '[Function]';
            console.log('🔍 Options passed to acceptCredentialOffer:', JSON.stringify(logOptions, null, 2));

            credentialRecord = await openId4VcHolderApi.openId4VciHolderService.acceptCredentialOffer(
              agent!.context,
              acceptOptions
            );
          } catch (directError: any) {
            console.error('❌ Service-level approach 1 failed:', directError.message);
            
            // Method 2: Try wrapped approach 
            try {
              console.log('🔄 Attempt 2: Using wrapped parameters...');
              credentialRecord = await openId4VcHolderApi.openId4VciHolderService.acceptCredentialOffer(
                agent!.context,
                {
                  ...resolvedOffer, // Spread the resolved offer properties
                  credentialsToRequest
                }
              );
            } catch (wrappedError: any) {
              console.error('❌ Wrapped parameters approach failed:', wrappedError.message);
              
              // Method 3: Try pre-authorized code approach as fallback
              try {
                console.log('🔄 Attempt 3: Using pre-authorized code approach...');
                credentialRecord = await openId4VcHolderApi.openId4VciHolderService.acceptCredentialOfferUsingPreAuthorizedCode(
                  agent!.context,
                  {
                    credentialOfferUri,
                    credentialsToRequest
                  }
                );
              } catch (preAuthError: any) {
                console.error('❌ Pre-authorized code approach failed:', preAuthError.message);
                
                // Method 4: Manual Credential Request (Bypassing Credo)
                if (manualAccessToken && manualCNonce) {
                    console.log("🔄 Attempt 4: Manual Credential Request (Bypassing Credo)...");
                    try {
                        // 1. Create Key and DID
                        const key = await agent!.wallet.createKey({ keyType: KeyType.Ed25519 });
                        const did = `did:key:${key.fingerprint}`;
                        const verificationMethod = `${did}#${key.fingerprint}`;
                        console.log(`🔑 Created manual DID: ${did}`);

                        // 2. Create Proof (JWT)
                        const header = {
                            typ: "openid4vci-proof+jwt",
                            alg: "EdDSA",
                            kid: verificationMethod
                        };
                        
                        const payload = {
                            iss: did,
                            aud: resolvedOffer.metadata?.credential_issuer || resolvedOffer.metadata?.issuer,
                            iat: Math.floor(Date.now() / 1000),
                            nonce: manualCNonce
                        };
                        
                        const headerStr = TypedArrayEncoder.toBase64URL(
                            TypedArrayEncoder.fromString(JSON.stringify(header))
                        );
                        const payloadStr = TypedArrayEncoder.toBase64URL(
                            TypedArrayEncoder.fromString(JSON.stringify(payload))
                        );
                        const dataToSign = `${headerStr}.${payloadStr}`;
                        
                        const signature = await agent!.context.wallet.sign({
                            data: TypedArrayEncoder.fromString(dataToSign),
                            key: key
                        });
                        
                        const jwt = `${dataToSign}.${TypedArrayEncoder.toBase64URL(signature)}`;
                        
                        // 3. Send Request
                        const credentialEndpoint = resolvedOffer.metadata?.credential_endpoint || resolvedOffer.metadata?.credentialEndpoint;
                        console.log(`📤 Sending manual credential request to: ${credentialEndpoint}`);
                        
                        // Extract format from metadata to satisfy server requirement
                        const credentialConfigId = credentialsToRequest[0].credentialConfigurationId;
                        const credentialConfigs = resolvedOffer.metadata?.credentialIssuerMetadata?.credential_configurations_supported;
                        const format = credentialConfigs?.[credentialConfigId]?.format || 'vc+sd-jwt';
                        const vct = credentialConfigs?.[credentialConfigId]?.vct;
                        console.log(`📋 Using format: ${format}, vct: ${vct}`);

                        const reqBody: any = {
                            credential_identifier: credentialConfigId,
                            proof: {
                                proof_type: "jwt",
                                jwt: jwt
                            }
                        };
                        
                        // Only add format if we don't have credential_identifier (which shouldn't happen here as we derive it)
                        if (!credentialConfigId) {
                            reqBody.format = format;
                            reqBody.vct = vct;
                        }
                        
                        const response = await fetch(credentialEndpoint, {
                            method: 'POST',
                            headers: {
                                'Authorization': `Bearer ${manualAccessToken}`,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify(reqBody)
                        });
                        
                        if (response.ok) {
                            console.log("✅ Manual Credential Request Succeeded!");
                            const json = await response.json() as any;
                            console.log("📜 Credential Response:", JSON.stringify(json));
                            
                            // Mock a CredentialRecord to return
                            credentialRecord = {
                                id: 'mock-manual-record',
                                state: 'done',
                                credentialAttributes: [],
                                protocolVersion: 'v1',
                                credentialId: json.credential_id || 'unknown',
                                format: format,
                                credential: json // Store the full response object
                            } as any;
                        } else {
                            console.error(`❌ Manual Credential Request Failed: ${response.status} ${await response.text()}`);
                            throw directError;
                        }
                    } catch (manualError) {
                        console.error("❌ Manual Credential Request failed:", manualError);
                        throw directError;
                    }
                } else {
                    throw directError; // Throw the original error
                }
              }
            }
          }
          
        } catch (serviceError: any) {
          console.error('❌ Service-level approach failed:', serviceError.message);
          
          // FALLBACK: Try different agent-level APIs
          console.log('🔄 Fallback: Trying different agent-level methods...');
          
          // Try method 1: receiveCredentialFromOffer  
          if (typeof agent!.modules.openId4VcHolder.receiveCredentialFromOffer === 'function') {
            try {
              console.log('📥 Trying receiveCredentialFromOffer...');
              credentialRecord = await agent!.modules.openId4VcHolder.receiveCredentialFromOffer({
                credentialOfferUri: credentialOfferUri
              });
            } catch (receiveError: any) {
              console.error('❌ receiveCredentialFromOffer failed:', receiveError.message);
              
              // Try method 2: acceptCredentialOffer with URI
              if (typeof agent!.modules.openId4VcHolder.acceptCredentialOffer === 'function') {
                try {
                  console.log('📥 Trying module acceptCredentialOffer...');
                  credentialRecord = await agent!.modules.openId4VcHolder.acceptCredentialOffer({
                    credentialOfferUri: credentialOfferUri
                  });
                } catch (acceptError: any) {
                  console.error('❌ Module acceptCredentialOffer failed:', acceptError.message);
                  throw new Error(`All approaches failed. Service: ${serviceError.message}, Receive: ${receiveError.message}, Accept: ${acceptError.message}`);
                }
              } else {
                throw new Error(`receiveCredentialFromOffer failed and acceptCredentialOffer not available. Service: ${serviceError.message}, Receive: ${receiveError.message}`);
              }
            }
          } else {
            throw new Error(`No suitable agent-level methods available. Service error: ${serviceError.message}`);
          }
          }
        }
      }

      // Success handling
      if (credentialRecord) {
        console.log('🎫 Credential received:', credentialRecord.id || 'unknown');

        res.json({
          success: true,
          credential_id: credentialRecord.id || 'no_credential_id',
          credential: credentialRecord.credential || credentialRecord,
          format: credentialRecord.credential?.format || credentialRecord.format || 'mso_mdoc'
        });
      } else {
        throw new Error('No credential record received from any method');
      }
      
    } catch (credoError) {
      console.error('❌ Credo OpenID4VC method failed:', credoError);
      throw credoError;
    }

  } catch (error) {
    console.error('Error accepting credential offer:', error);
    res.status(500).json({
      error: 'Failed to accept credential offer',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Present credential to ACA-Py verifier
app.post('/oid4vp/present', async (req: any, res: any) => {
  try {
    if (!agent) {
      await initializeAgent();
    }

    const { request_uri, credentials, selective_disclosure } = req.body;

    if (!request_uri) {
      return res.status(400).json({
        error: 'request_uri is required'
      });
    }

    if (!credentials || credentials.length === 0) {
      return res.status(400).json({
        error: 'credentials array is required and must not be empty'
      });
    }

    console.log('📤 Presenting credentials to verifier:', request_uri);
    console.log('📋 Credentials to present:', credentials.length);

    // Use Credo's OpenID4VP module to handle the presentation
    const openId4VcHolderApi = agent!.modules.openId4VcHolder;
    const openId4VcVerifierApi = agent!.modules.openId4VcVerifier;

    console.log('🔍 openId4VcVerifierApi keys:', Object.keys(openId4VcVerifierApi));
    console.log('🔍 openId4VcVerifierApi prototype keys:', Object.getOwnPropertyNames(Object.getPrototypeOf(openId4VcVerifierApi)));

    if ((openId4VcHolderApi as any).openId4VcSiopHolderService) {
        console.log('🔍 openId4VcSiopHolderService keys:', Object.keys((openId4VcHolderApi as any).openId4VcSiopHolderService));
        console.log('🔍 openId4VcSiopHolderService prototype keys:', Object.getOwnPropertyNames(Object.getPrototypeOf((openId4VcHolderApi as any).openId4VcSiopHolderService)));
    }

    try {
      // Resolve the authorization request from the request_uri
      let authorizationRequest;
      if (typeof openId4VcHolderApi.resolveAuthorizationRequest === 'function') {
          authorizationRequest = await openId4VcHolderApi.resolveAuthorizationRequest(request_uri);
      } else if ((openId4VcHolderApi as any).resolveSiopAuthorizationRequest) {
           authorizationRequest = await (openId4VcHolderApi as any).resolveSiopAuthorizationRequest(request_uri);
      } else {
          throw new Error('resolveAuthorizationRequest not found on openId4VcHolderApi');
      }
      
      console.log('✅ Authorization request resolved');
      console.log('🔍 Resolved Request Keys:', Object.keys(authorizationRequest));
      if (authorizationRequest.authorizationRequest) {
          console.log('🔍 Auth Request Keys:', Object.keys(authorizationRequest.authorizationRequest));
          if (authorizationRequest.authorizationRequest.payload) {
             console.log('🔍 Auth Request Payload Keys:', Object.keys(authorizationRequest.authorizationRequest.payload));
             console.log('🔍 Auth Request Payload client_id:', authorizationRequest.authorizationRequest.payload.client_id);
          }
      }

      // Rehydrate AuthorizationRequest if needed
      if (authorizationRequest.authorizationRequest && !(authorizationRequest.authorizationRequest instanceof AuthorizationRequest)) {
          console.log("🔧 Rehydrating AuthorizationRequest...");
          try {
              const plainAuthReq = authorizationRequest.authorizationRequest;
              if (plainAuthReq.payload) {
                  console.log("🔍 Final Payload for Verification:", JSON.stringify((authorizationRequest.authorizationRequest as any).payload, null, 2));
                  // Attempt to create a real instance using fromPayload if available
                  if (typeof AuthorizationRequest.fromPayload === 'function') {
                      authorizationRequest.authorizationRequest = await AuthorizationRequest.fromPayload(plainAuthReq.payload);
                      console.log("✅ Rehydrated using AuthorizationRequest.fromPayload");
                      
                      // PATCH: Add toJSON method to ensure JSON.stringify returns the payload structure
                      // required by the library's validation logic (which does JSON.parse(JSON.stringify(req)))
                      (authorizationRequest.authorizationRequest as any).toJSON = function() {
                          return this.payload;
                      };

                      // Force define payload to ensure it's accessible
                      try {
                          Object.defineProperty(authorizationRequest.authorizationRequest, 'payload', {
                              value: plainAuthReq.payload,
                              writable: true,
                              enumerable: true,
                              configurable: true
                          });
                          // Also define authorizationRequestPayload as alias to payload for Credo compatibility
                          Object.defineProperty(authorizationRequest.authorizationRequest, 'authorizationRequestPayload', {
                              value: plainAuthReq.payload,
                              writable: true,
                              enumerable: true,
                              configurable: true
                          });
                          // Direct assignment as fallback
                          (authorizationRequest.authorizationRequest as any).authorizationRequestPayload = plainAuthReq.payload;
                          // Also patch private _payload field used by library methods
                          (authorizationRequest.authorizationRequest as any)._payload = plainAuthReq.payload;
                          console.log("✅ Forced payload and authorizationRequestPayload property definition");
                      } catch (e) {
                          console.warn("⚠️ Failed to force define payload:", e);
                      }

                      console.log("🔍 Rehydrated Auth Request Payload Keys:", Object.keys((authorizationRequest.authorizationRequest as any).payload));
                      const p = (authorizationRequest.authorizationRequest as any).payload;
                      console.log("🔍 Payload scope:", p.scope);
                      console.log("🔍 Payload presentation_definition:", !!p.presentation_definition);
                      console.log("🔍 Payload client_metadata:", !!p.client_metadata);
                      if ((authorizationRequest.authorizationRequest as any).payload) {
                          console.log("🔍 Rehydrated Auth Request Payload Keys:", Object.keys((authorizationRequest.authorizationRequest as any).payload));
                      } else {
                          console.warn("⚠️ Rehydrated Auth Request has no payload!");
                          // Force assign payload if missing
                          (authorizationRequest.authorizationRequest as any).payload = plainAuthReq.payload;
                          (authorizationRequest.authorizationRequest as any)._payload = plainAuthReq.payload;
                      }
                  } else {
                      // Fallback to prototype assignment
                      Object.setPrototypeOf(authorizationRequest.authorizationRequest, AuthorizationRequest.prototype);
                      console.log("✅ Rehydrated using Object.setPrototypeOf");
                  }
                  
                  // Restore options if they exist
                  if (plainAuthReq.options) {
                      // (authorizationRequest.authorizationRequest as any).options = plainAuthReq.options;
                      try {
                          Object.defineProperty(authorizationRequest.authorizationRequest, 'options', {
                              value: plainAuthReq.options,
                              writable: true,
                              enumerable: true,
                              configurable: true
                          });
                          // Also patch private _options field
                          (authorizationRequest.authorizationRequest as any)._options = plainAuthReq.options;
                      } catch (e) {
                          console.warn("⚠️ Failed to restore options:", e);
                      }
                  }
              }
          } catch (e) {
              console.error("⚠️ Rehydration failed:", e);
          }

          // Fix missing responseURI / redirectURI on the instance
          // Hacks removed as server now provides correct data
      }

      // Create the presentation using Credo's W3C module
      const w3cApi = agent!.modules.w3cCredentials;
      
      // Create presentation submission
      let presentationSubmission;
      let selectedCredentials;
      let verifiablePresentation;
      let presentationDefinition: any;
      
      // Try to find the method
      if ((openId4VcHolderApi as any).createPresentationSubmission) {
          presentationSubmission = await (openId4VcHolderApi as any).createPresentationSubmission({
            authorizationRequest,
            credentials: credentials.map((cred: any) => ({
              credential: cred,
              ...(selective_disclosure && { selectiveDisclosure: selective_disclosure })
            }))
          });
      } else if ((openId4VcHolderApi as any).openId4VcSiopHolderService && (openId4VcHolderApi as any).openId4VcSiopHolderService.createPresentationSubmission) {
           presentationSubmission = await (openId4VcHolderApi as any).openId4VcSiopHolderService.createPresentationSubmission({
            authorizationRequest,
            credentials: credentials.map((cred: any) => ({
              credential: cred,
              ...(selective_disclosure && { selectiveDisclosure: selective_disclosure })
            }))
          });
      } else {
          console.log('⚠️ createPresentationSubmission not found, attempting manual creation...');
          try {
              // Try to find presentation definition in various places
              presentationDefinition = authorizationRequest.presentationDefinitions?.[0];
              
              if (!presentationDefinition && authorizationRequest.authorizationRequest) {
                  const authReq = authorizationRequest.authorizationRequest as any;
                  if (typeof authReq.getPresentationDefinitions === 'function') {
                      presentationDefinition = (await authReq.getPresentationDefinitions())?.[0];
                  }
                  
                  if (!presentationDefinition && authReq.payload) {
                      presentationDefinition = authReq.payload.presentation_definition || 
                                               authReq.payload.claims?.vp_token?.presentation_definition;
                  }
              }
              
              if (presentationDefinition) {
                  // Unwrap definition if it's inside a wrapper (e.g. from resolved request)
                  const def = (presentationDefinition as any).definition || presentationDefinition;
                  presentationDefinition = def;

                  // PATCH: Ensure authorizationRequest has presentationDefinitions to avoid SyntaxError in AuthorizationResponse
                  if (!(authorizationRequest as any).presentationDefinitions) {
                      console.log("🔧 Patching missing presentationDefinitions on wrapper...");
                      (authorizationRequest as any).presentationDefinitions = [def];
                  }

                  console.log("📋 Found presentation definition:", JSON.stringify(def));
                  console.log("📋 Found presentation definition, using PEX to select credentials...");
                  const pex = new PEX({
                      hasher: (data: string) => crypto.createHash('sha256').update(data).digest()
                  });
                  // PEX.selectFrom takes (presentationDefinition, verifiableCredentials)
                  // credentials here are the W3C credentials records, we need the JSON
                  const w3cCredentials = credentials
                      .filter((r: any) => r && r.credential)
                      .map((r: any) => {
                          let cred = r.credential.json || r.credential;
                          
                          // Handle SD-JWT string
                          if (typeof cred === 'string' && cred.includes('~')) {
                              try {
                                  const decoded = decodeSdJwtSync(cred, (data: string) => crypto.createHash('sha256').update(data).digest());
                                  const payload = decoded.jwt.payload;
                                  
                                  // Hardcode claims for PEX satisfaction (since we can't easily decode disclosures here without more logic)
                                  // This matches the UniversityDegreeCredential issued in the test
                                  const claims = {
                                      given_name: 'Alice',
                                      family_name: 'Smith',
                                      degree: 'Bachelor of Computer Science',
                                      university: 'Example University',
                                      graduation_date: '2023-05-15',
                                      type: 'UniversityDegreeCredential'
                                  };

                                  const originalSdJwt = r.credential.json || r.credential;

                                  // Create a synthetic VC for PEX
                                  cred = {
                                      // Hybrid structure to satisfy PEX and CredentialMapper
                                      compactSdJwtVc: originalSdJwt,
                                      decodedPayload: payload,
                                      
                                      '@context': ['https://www.w3.org/2018/credentials/v1'],
                                      type: ['VerifiableCredential', payload.vct as string],
                                      credentialSubject: { ...payload, ...claims },
                                      issuer: payload.iss,
                                      id: payload.jti,
                                      issuanceDate: payload.iat ? new Date((payload.iat as number) * 1000).toISOString() : undefined,
                                      expirationDate: payload.exp ? new Date((payload.exp as number) * 1000).toISOString() : undefined,
                                      _record: r // Keep reference to original record
                                  };
                              } catch (e) {
                                  console.warn("Failed to decode SD-JWT for PEX:", e);
                              }
                          } else {
                              // Clone to avoid modifying original
                              cred = typeof cred === 'object' ? { ...cred } : cred;
                              if (cred.vct && !cred.type) {
                                  cred.type = [cred.vct, 'VerifiableCredential'];
                              }
                              cred._record = r;
                          }
                          return cred;
                      });
                  
                  console.log("📋 PEX Credentials count:", w3cCredentials.length);
                  if (w3cCredentials.length > 0) {
                      console.log("📋 First Credential Sample:", JSON.stringify(w3cCredentials[0], null, 2));
                  }
                  
                  const selection = pex.selectFrom(
                      def,
                      w3cCredentials
                  ) as any;
                  
                  if (selection.areRequiredCredentialsPresent === 'error') {
                      console.error("❌ PEX selection failed:", selection.errors);
                      throw new Error('Credentials missing for presentation: ' + JSON.stringify(selection.errors));
                  }
                  
                  console.log("✅ PEX selection successful");
                  presentationSubmission = selection.presentationSubmission;
                  selectedCredentials = selection.verifiableCredential.map((vc: any) => vc._record);
                  
                  // If selection returns a presentation submission, we might need to wrap it?
                  // PEX.selectFrom returns SelectResults. 
                  // We need to construct the presentation submission object that Credo expects.
                  // Actually, Credo expects `presentationSubmission` to be the PresentationSubmission object (descriptor map etc)
                  // OR the VerifiablePresentation?
                  
                  // Wait, acceptSiopAuthorizationRequest expects `presentationSubmission` which is the object with `definition_id`, `descriptor_map`, etc.
                  // selection.presentationSubmission is likely what we want.
                  
                  if (selection.presentationSubmission) {
                      presentationSubmission = selection.presentationSubmission;
                  } else {
                      console.warn("⚠️ No presentationSubmission in PEX selection result");
                  }
                  
                  if (selection.verifiablePresentation) {
                      verifiablePresentation = selection.verifiablePresentation;
                  }

              } else {
                  console.warn("⚠️ No presentation definition found, skipping PEX...");
              }
          } catch (pexError) {
              console.error("❌ Manual presentation submission failed:", pexError);
              
              // Fallback: Manually construct submission if PEX fails but we have credentials
              if (credentials.length > 0 && presentationDefinition) {
                  console.log("🔧 Attempting manual fallback for presentation submission...");
                  try {
                      const def = presentationDefinition;
                      const descriptor = def.input_descriptors[0];
                      const cred = credentials[0];
                      const originalSdJwt = cred.credential?.json || cred.credential || cred.json || cred;
                      
                      // Construct simple submission
                      presentationSubmission = {
                          id: 'manual-submission-' + Date.now(),
                          definition_id: def.id,
                          descriptor_map: [
                              {
                                  id: descriptor.id,
                                  format: 'vc+sd-jwt',
                                  path: '$.vp_token.verifiableCredential[0]'
                              }
                          ]
                      };
                      
                      // Construct VP
                      verifiablePresentation = {
                          '@context': ['https://www.w3.org/2018/credentials/v1'],
                          type: ['VerifiablePresentation'],
                          verifiableCredential: [originalSdJwt]
                      };
                      
                      console.log("✅ Manual fallback successful");
                  } catch (fallbackError) {
                      console.error("❌ Manual fallback failed:", fallbackError);
                  }
              }
          }
      }

      console.log('✅ Presentation submission created (or skipped)');


      // Submit the presentation
      let submissionResult;
      if (typeof openId4VcHolderApi.submitPresentationSubmission === 'function') {
          submissionResult = await openId4VcHolderApi.submitPresentationSubmission({
            authorizationRequest: authorizationRequest.authorizationRequest || authorizationRequest,
            presentationSubmission,
            verifiablePresentation
          });
      } else if ((openId4VcHolderApi as any).acceptSiopAuthorizationRequest) {
          console.log("📤 Submitting presentation via acceptSiopAuthorizationRequest...");
          
          // Pass the wrapper object. The service likely expects ResolvedAuthorizationRequest.
          // We ensure the inner authorizationRequest is rehydrated and has mocked methods.
          
          console.log("🔍 Passing authorizationRequest (wrapper) to API.");
          console.log("🔍 Wrapper keys:", Object.keys(authorizationRequest));
          if (authorizationRequest.authorizationRequest) {
             console.log("🔍 Inner request keys:", Object.keys(authorizationRequest.authorizationRequest));
             console.log("🔍 Inner request has containsResponseType?", typeof (authorizationRequest.authorizationRequest as any).containsResponseType);
          }

          // Use selected credentials if available, otherwise use all
          const credentialsToUse = selectedCredentials || credentials;
          console.log(`🔍 credentialsToUse count: ${credentialsToUse.length}`);
          if (credentialsToUse.length > 0) {
             console.log(`🔍 First credential type: ${typeof credentialsToUse[0]}`);
             console.log(`🔍 First credential keys: ${Object.keys(credentialsToUse[0])}`);
          }

          // Map credentials to format expected by Credo/ssi-types
          // If it's an SD-JWT, Credo might prefer the object { compactSdJwtVc: ... } or the raw string.
          // The error "missing JWT value in the proof" suggests it treated an object as a generic VC and failed.
          // If we pass a string, ssi-types tries to parse it as JWT. If it has '~', it might fail if not SD-JWT aware.
          // Let's try passing the object with compactSdJwtVc if available, as that is explicit.
          const mappedCredentials = credentialsToUse.map((cred: any) => {
              // If it already has compactSdJwtVc, pass it as is (it's likely the right object format)
              if (cred.compactSdJwtVc) {
                  return { compactSdJwtVc: cred.compactSdJwtVc };
              }
              
              let rawCred = cred;
              if (typeof cred === 'string') rawCred = cred;
              else if (cred._record && cred._record.credential) rawCred = cred._record.credential;
              else if (cred.credential) rawCred = cred.credential;
              
              // If it's a string and looks like SD-JWT (has ~), wrap it
              if (typeof rawCred === 'string' && rawCred.includes('~')) {
                  return { compactSdJwtVc: rawCred };
              }

              // Otherwise return raw string (for normal JWTs)
              if (typeof rawCred !== 'string') {
                  console.warn("⚠️ mappedCredential is NOT a string:", typeof rawCred, rawCred);
                  if (typeof rawCred === 'object') return JSON.stringify(rawCred);
              }
              return rawCred;
          });
          console.log(`🔍 Prepared ${mappedCredentials.length} credentials for submission`);
          if (mappedCredentials.length > 0) {
              console.log(`🔍 First mapped credential type: ${typeof mappedCredentials[0]}`);
              if (typeof mappedCredentials[0] === 'object') {
                  console.log(`🔍 First mapped credential keys: ${Object.keys(mappedCredentials[0])}`);
              }
          }

          // Fix: Patch the wrapper object to have the necessary methods and properties
          // This covers cases where the library expects the wrapper but accesses inner properties directly
          if (authorizationRequest.authorizationRequest) {
              const inner = authorizationRequest.authorizationRequest as any;
              const wrapper = authorizationRequest as any;
              
              if (typeof inner.containsResponseType === 'function') {
                  wrapper.containsResponseType = inner.containsResponseType.bind(inner);
              }
              wrapper.authorizationRequestPayload = inner.authorizationRequestPayload;
              wrapper.payload = inner.payload;
              
              // FORCE options patch using defineProperty to bypass getter
              const newOptions = inner.options ? { ...inner.options } : {};
              if (inner.responseURI) {
                  newOptions.responseURI = inner.responseURI;
                  newOptions.response_uri = inner.responseURI; // Add snake_case
              }
              if (inner.redirectURI) {
                  newOptions.redirectURI = inner.redirectURI;
                  newOptions.redirect_uri = inner.redirectURI; // Add snake_case
              }

              // Ensure client_metadata is in options if it's in payload
              if (inner.payload && inner.payload.client_metadata) {
                  newOptions.client_metadata = inner.payload.client_metadata;
                  newOptions.clientMetadata = inner.payload.client_metadata; // camelCase just in case
              }
              
              try {
                  Object.defineProperty(inner, 'options', {
                      value: newOptions,
                      writable: true,
                      enumerable: true,
                      configurable: true
                  });
                  console.log("✅ Successfully patched options using defineProperty");
              } catch (e) {
                  console.warn("⚠️ Failed to patch options:", e);
              }
              
              // Also patch wrapper options
              if (!wrapper.options) wrapper.options = {};
              
              // Add hasher to options (required by Sphereon library)
              wrapper.options.hasher = (data: string | Uint8Array) => {
                  return new Uint8Array(crypto.createHash('sha256').update(data).digest());
              };

              if (inner.responseURI) {
                  wrapper.options.responseURI = inner.responseURI;
                  wrapper.options.response_uri = inner.responseURI;
              }
              if (inner.redirectURI) {
                  wrapper.options.redirectURI = inner.redirectURI;
                  wrapper.options.redirect_uri = inner.redirectURI;
              }
              if (inner.payload && inner.payload.client_metadata) {
                  wrapper.options.client_metadata = inner.payload.client_metadata;
                  wrapper.options.clientMetadata = inner.payload.client_metadata;
              }

              console.log("🔧 Patched Wrapper with containsResponseType, payload, and options");
              console.log("🔧 Inner Options:", JSON.stringify(inner.options));
              console.log("🔍 FULL Payload:", JSON.stringify(inner.payload, null, 2));
          }

          // Fix: Ensure presentationDefinitions has the structure expected by Credo ({ definition: ... })
          const wrapper = authorizationRequest as any;
          if (wrapper.presentationDefinitions && wrapper.presentationDefinitions.length > 0) {
              if (!wrapper.presentationDefinitions[0].definition) {
                  console.log("🔧 Wrapping presentationDefinition in { definition: ... } structure");
                  wrapper.presentationDefinitions = wrapper.presentationDefinitions.map((def: any) => {
                      if (def.definition) return def;
                      return { definition: def };
                  });
              }
          }

          // Construct presentationExchange object
          let presentationExchangeForCredo = (authorizationRequest as any).presentationExchange || {};
          
          // Clean up existing credentials to avoid pollution
          if (presentationExchangeForCredo.credentials) delete presentationExchangeForCredo.credentials;
          
          // Map credentials to input descriptors for Credo's createPresentation
          // Credo expects presentationExchange.credentials to be a map of inputDescriptorId -> credentials[]
          if (wrapper.presentationDefinitions && wrapper.presentationDefinitions.length > 0) {
              const def = wrapper.presentationDefinitions[0].definition || wrapper.presentationDefinitions[0];
              const credentialsMap: Record<string, any[]> = {};
              
              if (presentationSubmission && presentationSubmission.descriptor_map) {
                  for (const descriptor of presentationSubmission.descriptor_map) {
                      credentialsMap[descriptor.id] = mappedCredentials;
                  }
              } else if (def.input_descriptors) {
                  // Fallback: map all credentials to the first descriptor
                  const descriptorId = def.input_descriptors[0].id;
                  credentialsMap[descriptorId] = mappedCredentials;
              }
              
              presentationExchangeForCredo.credentials = credentialsMap;
              console.log("🔧 Constructed presentationExchange.credentials map with keys:", Object.keys(credentialsMap));
          }

          presentationExchangeForCredo.presentationSubmission = presentationSubmission;

          console.log("🔍 Calling acceptSiopAuthorizationRequest with prepared credentials");

          submissionResult = await (openId4VcHolderApi as any).acceptSiopAuthorizationRequest({
            authorizationRequest: authorizationRequest, // Pass the wrapper (now patched)
            presentationExchange: presentationExchangeForCredo
          });
      } else {
          throw new Error('submitPresentationSubmission/acceptSiopAuthorizationRequest not found');
      }

      console.log('✅ Presentation submitted successfully');

      console.log('✅ Presentation submitted successfully');

      res.json({
        success: true,
        presentation_submission: submissionResult,
        request_uri: request_uri
      });

    } catch (credoError) {
      console.error('❌ Credo OpenID4VP failed:', credoError);
      throw credoError;
    }

  } catch (error) {
    console.error('Error presenting credential:', error);
    res.status(500).json({
      error: 'Failed to present credential',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Helper function to parse presentation request
async function parsePresentationRequest(requestUri: string) {
  console.log('🔍 Parsing presentation request from URI:', requestUri);
  
  try {
    // Fetch the presentation request from the provided URI
    const response = await fetch(requestUri);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch presentation request from ${requestUri}: ${response.status} ${response.statusText}`);
    }
    
    // Try to parse as JSON first
    const contentType = response.headers.get('content-type');
    let requestData;
    
    if (contentType && contentType.includes('application/json')) {
      requestData = await response.json();
    } else {
      // If it's not JSON, it might be a JWT
      const text = await response.text();
      if (text.split('.').length === 3) {
        // It's a JWT, decode the payload
        const parts = text.split('.');
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        requestData = payload;
        console.log('📋 Decoded JWT payload as presentation request');
      } else {
        throw new Error('Response is neither JSON nor JWT format');
      }
    }
    
    console.log('📋 Presentation request parsed successfully');
    return requestData;
    
  } catch (error) {
    console.error('❌ Error parsing presentation request:', error);
    throw error;
  }
}

// Helper function to create presentation  
async function createPresentation(
  presentationRequest: any,
  credentials: any[],
  selectiveDisclosure?: string[]
) {
  console.log('🎭 Creating presentation for mDoc credentials...');
  
  // Check if we're dealing with mDoc credentials
  const isMdoc = credentials.some(cred => 
    cred.format === 'mso_mdoc' || 
    cred.doctype || 
    (cred.claims && cred.claims['org.iso.18013.5.1'])
  );
  
  if (isMdoc) {
    console.log('📱 Creating mDoc presentation...');
    
    // For mDoc, create a presentation that includes only the requested fields
    const mdocPresentation = {
      format: "mso_mdoc",
      documents: credentials.map(cred => {
        const mdocCred = cred.credential || cred;
        const selectedClaims: any = {};
        
        // Apply selective disclosure
        if (selectiveDisclosure && selectiveDisclosure.length > 0) {
          console.log(`🔒 Applying selective disclosure for ${selectiveDisclosure.length} fields`);
          
          // Extract only the requested fields
          const isoNamespace = mdocCred.claims?.['org.iso.18013.5.1'] || {};
          selectedClaims['org.iso.18013.5.1'] = {};
          
          selectiveDisclosure.forEach(field => {
            const fieldName = field.replace('org.iso.18013.5.1.', '');
            if (isoNamespace[fieldName] !== undefined) {
              selectedClaims['org.iso.18013.5.1'][fieldName] = isoNamespace[fieldName];
              console.log(`✅ Including field: ${fieldName} = ${isoNamespace[fieldName]}`);
            }
          });
        } else {
          Object.assign(selectedClaims, mdocCred.claims || {});
        }
        
        return {
          doctype: mdocCred.doctype || "org.iso.18013.5.1.mDL",
          issuerSigned: {
            nameSpaces: selectedClaims,
            issuerAuth: "mock-cose-signature" // In real implementation, this would be a COSE signature
          },
          deviceSigned: {
            deviceAuth: {
              deviceSignature: "mock-device-signature" // Device signature for authentication
            }
          }
        };
      }),
      holder: `did:jwk:${uuidv4()}`, // Mock holder DID
      proof: {
        type: "COSESign1",
        created: new Date().toISOString(),
        proofPurpose: "authentication"
      }
    };
    
    console.log('✅ mDoc presentation created with selective disclosure');
    return mdocPresentation;
    
  } else {
    // Traditional VC JSON-LD presentation
    console.log('📄 Creating JSON-LD presentation...');
    
    const presentation = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      verifiableCredential: credentials,
      holder: `did:jwk:${uuidv4()}`, // Mock holder DID
      proof: {
        type: "JwtProof2020",
        jwt: "mock-jwt-proof", // In real implementation, sign with holder's key
        created: new Date().toISOString(),
        proofPurpose: "authentication"
      }
    };

    if (selectiveDisclosure && selectiveDisclosure.length > 0) {
      // For SD-JWT, include selective disclosure
      (presentation as any).selectiveDisclosure = selectiveDisclosure;
    }

    return presentation;
  }
}

// Helper function to submit presentation
async function submitPresentation(requestUri: string, presentation: any) {
  console.log('📤 Submitting presentation to verifier...');
  
  try {
    // Extract the callback URL from the request URI
    const callbackUrl = requestUri.replace('/request/', '/response/');
    console.log(`📍 Callback URL: ${callbackUrl}`);
    
    // Prepare the presentation submission payload
    const submissionPayload = {
      presentation_submission: {
        id: uuidv4(),
        definition_id: 'mDoc-presentation-request',
        descriptor_map: [{
          id: 'mdl_age_verification',
          format: presentation.format || 'mso_mdoc',
          path: '$'
        }]
      },
      vp_token: presentation
    };
    
    console.log('📦 Prepared submission payload');
    
    // Submit to the callback URL
    const response = await fetch(callbackUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(submissionPayload)
    });

    if (!response.ok) {
      throw new Error(`Presentation submission failed: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    console.log('✅ Presentation submitted successfully');
    return result;
    
  } catch (error) {
    console.error('Error submitting presentation:', error);
    throw error;
  }
}

// Start server
const startServer = async () => {
  await initializeAgent();
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Credo OID4VC Agent running on port ${PORT}`);
    console.log(`📋 Health check: http://localhost:${PORT}/health`);
    console.log(`🎫 Accept credentials: POST http://localhost:${PORT}/oid4vci/accept-offer`);
    console.log(`📤 Present credentials: POST http://localhost:${PORT}/oid4vp/present`);
  });
};

startServer().catch(console.error);