import express from 'express';
import * as util from 'util';
import { getAgent, initializeAgent } from './agent.js';
import { AuthorizationRequest } from '@sphereon/did-auth-siop';
import { W3cJwtVerifiableCredential, Mdoc, MdocRecord } from '@credo-ts/core';
import { CredentialMapper } from '@sphereon/ssi-types';

// Monkey patch CredentialMapper to handle Mdoc
// Removed as part of refactoring to use native Credo support
/*
try {
    const originalToWrapped = CredentialMapper.toWrappedVerifiableCredential;
    // @ts-ignore
    CredentialMapper.toWrappedVerifiableCredential = (credential: any) => {
        if (credential instanceof Mdoc || (credential.constructor && credential.constructor.name === 'Mdoc')) {
            console.log('⚠️ Monkey-patched CredentialMapper handling Mdoc');
            return {
                credential: credential,
                original: credential,
                decoded: credential, // PEX might look at decoded
                format: 'mso_mdoc' // Hint for PEX?
            };
        }
        return originalToWrapped(credential);
    };
    console.log('✅ Successfully patched CredentialMapper');
} catch (e) {
    console.error('❌ Failed to patch CredentialMapper:', e);
}
*/

const router: express.Router = express.Router();

// Present credential to ACA-Py verifier
router.post('/present', async (req: any, res: any) => {
  let agent = getAgent();
  try {
    if (!agent) {
      agent = await initializeAgent(3020);
    }

    const { request_uri } = req.body;

    if (!request_uri) {
      return res.status(400).json({
        error: 'request_uri is required'
      });
    }

    console.log('Resolving authorization request:', request_uri);

    const resolvedRequest = await agent!.modules.openId4VcHolder.resolveSiopAuthorizationRequest(request_uri);
    
    // Fix for plain object issue
    if (resolvedRequest.authorizationRequest && resolvedRequest.authorizationRequest.constructor.name === 'Object') {
        console.log('Re-hydrating AuthorizationRequest via setPrototypeOf...');
        Object.setPrototypeOf(resolvedRequest.authorizationRequest, AuthorizationRequest.prototype);
    }

    // Patches for @animo-id/mdoc compatibility removed as we are using native Credo support

    let credentials: any = {};
    
    if (resolvedRequest.presentationExchange) {
        const { credentialsForRequest } = resolvedRequest.presentationExchange;
        
        console.log('📋 Presentation Exchange Details:');
        console.log('  - Requirements satisfied:', credentialsForRequest.areRequirementsSatisfied);
        console.log('  - Requirements:', JSON.stringify(credentialsForRequest.requirements, null, 2));
        
        // WORKAROUND: Manually fetch W3C credentials if PEX failed to find them
        if (!credentialsForRequest.areRequirementsSatisfied) {
             console.log('⚠️ Requirements not satisfied automatically. Attempting manual W3C credential lookup...');
             
             // Fetch all W3C credentials
             // @ts-ignore
             const w3cRecords = await agent!.w3cCredentials.getAllCredentialRecords();
             
             // Fetch all mdoc records with defensive check
             let mdocRecords: any[] = [];
             if (agent?.modules?.mdoc) {
                 // @ts-ignore
                 mdocRecords = await agent!.modules.mdoc.getAll();
             } else {
                 console.error('❌ MdocModule not available. Agent modules:', Object.keys(agent?.modules || {}));
             }

             console.log(`Found ${w3cRecords.length} W3C credentials in storage`);
             console.log(`Found ${mdocRecords.length} mdoc credentials in storage`);
             
             if (w3cRecords.length > 0 || mdocRecords.length > 0) {
                 if (w3cRecords.length > 0) {
                    console.log('🔍 First W3C Record:', JSON.stringify(w3cRecords[0], null, 2));
                 }
                 
                 try {
                     console.log('W3cJwtVerifiableCredential defined:', !!W3cJwtVerifiableCredential);
                 } catch (e) {
                     console.error('Error checking W3cJwtVerifiableCredential:', e);
                 }

                 // Hydrate credentials if they are strings (JWTs)
                 for (const record of w3cRecords) {
                     let jwtString: string | undefined;

                     if (typeof record.credential === 'string') {
                         jwtString = record.credential;
                     } else if (typeof record.credential === 'object') {
                         // Check if it is a String wrapper
                         if (record.credential instanceof String) {
                             jwtString = record.credential.toString();
                         } 
                         // Check if it is already hydrated
                         else if (record.credential instanceof W3cJwtVerifiableCredential) {
                             try {
                                 // HACK: Flatten credentialSubject if it has nested claims
                                 // @ts-ignore
                                 if (record.credential.credentialSubject && record.credential.credentialSubject.claims) {
                                     // @ts-ignore
                                     const claims = record.credential.credentialSubject.claims;
                                     // @ts-ignore
                                     const id = record.credential.credentialSubject.id;
                                     
                                     const newSubject = { id, ...claims };
                                     
                                     Object.defineProperty(record.credential, 'credentialSubject', {
                                         value: newSubject,
                                         writable: true,
                                         enumerable: true,
                                         configurable: true
                                     });
                                 }
                             } catch (e) {
                                 // Ignore error
                             }
                         }
                         else {
                             const str = String(record.credential);
                             if (str.startsWith('eyJ')) {
                                 jwtString = str;
                             }
                         }
                     }

                     if (jwtString) {
                         try {
                             // @ts-ignore
                             record.credential = W3cJwtVerifiableCredential.fromSerializedJwt(jwtString);
                         } catch (e) {
                             // Ignore error
                         }
                     }
                 }

                 // Naive strategy: Assign all W3C credentials to all unsatisfied requirements
                 for (const requirement of credentialsForRequest.requirements) {
                     if (!requirement.isRequirementSatisfied) {
                         for (const submission of requirement.submissionEntry) {
                             if (!credentials[submission.inputDescriptorId]) {
                                 credentials[submission.inputDescriptorId] = [];
                             }
                             // Add all W3C records
                             credentials[submission.inputDescriptorId].push(...w3cRecords);
                             // Add all mdoc records
                             if (mdocRecords.length > 0) {
                                 console.log(`Adding ${mdocRecords.length} mdoc credentials to submission for ${submission.inputDescriptorId}`);
                                 credentials[submission.inputDescriptorId].push(...mdocRecords);
                             }
                         }
                     }
                 }
             }
        }

        // Select credentials from PEX result (for SD-JWTs and others that work)
        for (const requirement of credentialsForRequest.requirements) {
            if (requirement.isRequirementSatisfied) {
                for (const submission of requirement.submissionEntry) {
                    if (!credentials[submission.inputDescriptorId]) {
                        credentials[submission.inputDescriptorId] = [];
                    }
                    // We pick the first matching VC
                    if (submission.verifiableCredentials.length > 0) {
                        credentials[submission.inputDescriptorId].push(submission.verifiableCredentials[0].credentialRecord);
                    }
                }
            }
        }
        
        if (Object.keys(credentials).length === 0) {
             return res.status(400).json({ error: 'Could not find the required credentials for the presentation submission' });
        }
    }

    // Use Credo's OpenID4VC module to handle the presentation
    console.log('OpenId4VcHolder methods:', Object.getOwnPropertyNames(Object.getPrototypeOf(agent!.modules.openId4VcHolder)));

    console.log('DEBUG: Credentials map keys:', Object.keys(credentials));
    for (const key in credentials) {
        console.log(`DEBUG: Credentials for ${key}:`, credentials[key].length);
        credentials[key].forEach((c: any, i: number) => {
             console.log(`DEBUG: Credential ${i} type:`, typeof c);
             console.log(`DEBUG: Credential ${i} constructor:`, c ? c.constructor.name : 'null');
             if (c === undefined) console.log('DEBUG: Credential is UNDEFINED!');
        });
    }

    const submissionResult = await agent!.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedRequest.authorizationRequest,
        presentationExchange: {
            credentials
        }
    });

    console.log('✅ Presentation submitted successfully');
    
    // Inspect the result to avoid serialization errors
    const safeResult: any = {};
    
    if (submissionResult.submittedResponse) {
        console.log('Submitted response keys:', Object.keys(submissionResult.submittedResponse));
        safeResult.submittedResponse = submissionResult.submittedResponse;
    }
    
    if (submissionResult.serverResponse) {
        const sRes = submissionResult.serverResponse;
        console.log('Server response constructor:', sRes.constructor ? sRes.constructor.name : typeof sRes);
        
        // If it looks like a Response object (node-fetch/undici), extract useful info
        if (sRes.status !== undefined) {
             safeResult.serverResponse = {
                 status: sRes.status,
                 statusText: sRes.statusText,
                 // body might be a stream or already consumed, so be careful
             };
             
             // Try to get JSON if possible and not consumed
             try {
                 if (typeof sRes.clone === 'function') {
                     const clone = sRes.clone();
                     if (typeof clone.json === 'function') {
                         safeResult.serverResponse.body = await clone.json();
                     }
                 } else if (sRes.bodyUsed === false && typeof sRes.json === 'function') {
                      safeResult.serverResponse.body = await sRes.json();
                 } else if (typeof sRes.data === 'object') {
                      // Axios style?
                      safeResult.serverResponse.body = sRes.data;
                 }
             } catch (e) {
                 console.log('Could not read server response body:', e);
             }
        } else {
            // Assume it's a plain object or something safe
            try {
                JSON.stringify(sRes);
                safeResult.serverResponse = sRes;
            } catch (e) {
                console.log('⚠️ serverResponse is not JSON serializable:', e);
                safeResult.serverResponse = {
                    error: 'Response not serializable',
                    preview: util.inspect(sRes, { depth: 2 })
                };
            }
        }
    }

    try {
        res.json({
            success: true,
            presentation_submission: safeResult.submittedResponse, // Ensure this is at top level for test check
            result: safeResult,
            request_uri: request_uri
        });
    } catch (jsonError) {
        console.error('Error sending JSON response:', jsonError);
        res.status(500).json({
            error: 'Failed to serialize response',
            details: String(jsonError)
        });
    }

  } catch (error) {
    console.error('Error presenting credentials:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;

    res.status(500).json({
      error: 'Failed to present credentials',
      details: errorMessage,
      stack: errorStack
    });
  }
});

export default router;
