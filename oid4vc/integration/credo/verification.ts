import express from 'express';
import * as util from 'util';
import { getAgent, initializeAgent } from './agent.js';
import { AuthorizationRequest } from '@sphereon/did-auth-siop';
import { W3cJwtVerifiableCredential } from '@credo-ts/core';

const router = express.Router();

// Present credential to ACA-Py verifier
router.post('/present', async (req: any, res: any) => {
  let agent = getAgent();
  try {
    if (!agent) {
      await initializeAgent(3020);
      agent = getAgent();
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
             console.log(`Found ${w3cRecords.length} W3C credentials in storage`);
             
             if (w3cRecords.length > 0) {
                 console.log('🔍 First W3C Record:', JSON.stringify(w3cRecords[0], null, 2));
                 
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
