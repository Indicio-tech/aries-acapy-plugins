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
} from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { OpenId4VcHolderModule, OpenId4VcVerifierModule } from '@credo-ts/openid4vc';
import { v4 as uuidv4 } from 'uuid';
import express from 'express';

const app = express();
const PORT = parseInt(process.env.PORT || '3020', 10);

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
      id: 'credo-test-wallet',
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
          const credentialsToRequest = resolvedOffer.credentialOffer?.credential_configuration_ids?.map((id: string) => ({
            credentialConfigurationId: id
          })) || [{ credentialConfigurationId: 'mDL_mdoc' }];
          
          console.log('📋 Credentials to request:', credentialsToRequest);
          
          // BREAKTHROUGH: Try different method signatures based on Credo v0.5.17 analysis
          
          // NEXT FIX: Try different method signatures to avoid metadata destructuring
          
          // SIGNATURE FIX: Based on errors, method expects direct parameters, not nested objects
          
          // FIX: Based on the log, Credo service expects parameters as: (context, resolvedCredentialOffer, credentialsToRequest)
          // The service is destructuring the second parameter expecting {metadata}, but we're passing an object with resolvedCredentialOffer property
          try {
            console.log('🔄 Attempt 1: Using correct service-level parameter order...');
            credentialRecord = await openId4VcHolderApi.openId4VciHolderService.acceptCredentialOffer(
              agent!.context,
              resolvedOffer, // Pass the resolved offer directly as second parameter
              credentialsToRequest // Pass credentials to request as third parameter
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
                throw directError; // Throw the original error
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
    const openId4VcVerifierApi = agent!.modules.openId4VcVerifier;
    
    try {
      // Resolve the authorization request from the request_uri
      const authorizationRequest = await openId4VcVerifierApi.resolveAuthorizationRequest(request_uri);
      console.log('✅ Authorization request resolved');

      // Create the presentation using Credo's W3C module
      const w3cApi = agent!.modules.w3cCredentials;
      
      // Create presentation submission
      const presentationSubmission = await openId4VcVerifierApi.createPresentationSubmission({
        authorizationRequest,
        credentials: credentials.map((cred: any) => ({
          credential: cred,
          // Add selective disclosure info if provided
          ...(selective_disclosure && { selectiveDisclosure: selective_disclosure })
        }))
      });

      console.log('✅ Presentation submission created');

      // Submit the presentation
      const submissionResult = await openId4VcVerifierApi.submitPresentationSubmission({
        authorizationRequest,
        presentationSubmission
      });

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