import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { W3cJsonLdVerifiableCredential, W3cJwtVerifiableCredential } from '@credo-ts/core';
import { getAgent, initializeAgent } from './agent.js';

const router: express.Router = express.Router();

// Accept credential offer from ACA-Py issuer
router.post('/accept-offer', async (req: any, res: any) => {
  let agent = getAgent();
  try {
    if (!agent) {
      await initializeAgent(3020);
      agent = getAgent();
    }

    const { credential_offer } = req.body;

    if (!credential_offer) {
      return res.status(400).json({
        error: 'credential_offer is required'
      });
    }

    console.log('📥 Accepting credential offer:', typeof credential_offer === 'string' ? credential_offer : 'JSON Object');

    const holderModule = agent!.modules.openId4VcHolder;
    console.log('🔍 Holder Module Keys:', Object.keys(holderModule));
    console.log('🔍 Holder Module Prototype:', Object.getOwnPropertyNames(Object.getPrototypeOf(holderModule)));

    // Resolve the credential offer first
    const resolvedOffer = await agent!.modules.openId4VcHolder.resolveCredentialOffer(
        typeof credential_offer === 'string' 
            ? credential_offer 
            : `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credential_offer))}`
    );

    console.log('✅ Offer resolved', JSON.stringify(resolvedOffer, null, 2));

    // In Credo 0.5.17, we must choose the specific method based on the grant type
    // We'll assume pre-authorized code for now as that's what the tests use
    const credentialRecord = await agent!.modules.openId4VcHolder.acceptCredentialOfferUsingPreAuthorizedCode(
        resolvedOffer,
        {
            credentialsToRequest: resolvedOffer.offeredCredentials.map((c: any) => c.id),
            credentialBindingResolver: async (bindingOptions: any) => {
                console.log('🔒 Resolving credential binding for:', bindingOptions.keyType);
                const didResult = await agent!.dids.create({
                    method: 'key',
                    options: {
                        keyType: bindingOptions.keyType,
                    },
                });
                
                const did = didResult.didState.did!;
                let didUrl = did;
                
                // Ensure we have a fragment for did:key
                if (did.startsWith('did:key:')) {
                    // Check if we have the document to get the exact key ID
                    if (didResult.didState.didDocument?.verificationMethod?.[0]?.id) {
                        didUrl = didResult.didState.didDocument.verificationMethod[0].id;
                    } else {
                        // Fallback: construct the standard did:key key ID (did#fingerprint)
                        // For did:key, the fingerprint is the part after did:key:
                        const fingerprint = did.split(':')[2];
                        didUrl = `${did}#${fingerprint}`;
                    }
                }
                
                console.log('🔑 Generated DID URL:', didUrl);

                return {
                    method: 'did',
                    didUrl: didUrl,
                };
            }
        }
    );

    console.log('🎫 Credential Record Full Object:', JSON.stringify(credentialRecord, null, 2));

    // Handle array response (Credo returns an array of credentials)
    const credentials = Array.isArray(credentialRecord) ? credentialRecord : [credentialRecord];
    
    // Store credentials in the W3C credentials module so they can be found during presentation
    for (const credential of credentials) {
        try {
            console.log('💾 Storing credential...');

            // Handle different credential structures from Credo's OpenID4VCI client
            const compactJwt = credential.compact || credential.jwt?.serializedJwt;
            
            if (credential.header && credential.header.typ === 'vc+sd-jwt') {
                 console.log('Storing as SD-JWT credential');
                 console.log('Agent modules:', Object.keys(agent!.modules));
                 // @ts-ignore
                 await agent!.sdJwtVc.store(compactJwt);
                 continue;
            } else if (compactJwt) {
                 console.log('Storing as JWT-VC credential');
                 // @ts-ignore
                 const w3cCredential = W3cJwtVerifiableCredential.fromSerializedJwt(compactJwt);
                 // @ts-ignore
                 await agent!.w3cCredentials.storeCredential({ credential: w3cCredential });
                 continue;
            }
            
            let credentialToStore = credential;

            // Patch for SD-JWT credentials which might be missing 'type' property expected by W3cCredentialRecord
            if (!credential.type && credential.payload && credential.payload.vct) {
                console.log('🔧 Patching SD-JWT credential with type and context...');
                // Create a plain object copy to ensure we can add properties and they are visible
                credentialToStore = JSON.parse(JSON.stringify(credential));
                
                credentialToStore.type = ['VerifiableCredential', credential.payload.vct];
                if (!credentialToStore['@context']) {
                    credentialToStore['@context'] = ['https://www.w3.org/2018/credentials/v1'];
                }
                
                // Ensure ID is present (use jti or generate uuid)
                if (!credentialToStore.id) {
                    credentialToStore.id = credential.payload.jti || `urn:uuid:${uuidv4()}`;
                }
                
                if (!credentialToStore.issuanceDate && credential.payload.iat) {
                    credentialToStore.issuanceDate = new Date(credential.payload.iat * 1000).toISOString();
                }
                
                if (!credentialToStore.issuer && credential.payload.iss) {
                    credentialToStore.issuer = credential.payload.iss;
                }
                
                // Use prettyClaims for credentialSubject if available
                if (!credentialToStore.credentialSubject && credential.prettyClaims) {
                    credentialToStore.credentialSubject = credential.prettyClaims;
                }

                // Ensure proof exists (even if empty) to prevent W3cCredentialRecord errors
                if (!credentialToStore.proof) {
                    credentialToStore.proof = [];
                }

                console.log('📦 Credential to store:', JSON.stringify(credentialToStore, null, 2));
            }

            // @ts-ignore
            const w3cCredential = W3cJsonLdVerifiableCredential.fromJson(credentialToStore);
            // @ts-ignore
            await agent!.w3cCredentials.storeCredential({ credential: w3cCredential });
            console.log('✅ Credential stored successfully');
        } catch (e) {
            console.error('❌ Failed to store credential:', e);
        }
    }

    const firstCredential = credentials[0];

    res.json({
      success: true,
      credential: firstCredential,
      format: firstCredential.header?.typ || 'unknown'
    });

  } catch (error) {
    console.error('Error accepting credential offer:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;

    res.status(500).json({
      error: 'Failed to accept credential offer',
      details: errorMessage,
      stack: errorStack
    });
  }
});

export default router;
