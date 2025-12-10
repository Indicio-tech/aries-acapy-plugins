import express from 'express';
import { getAgent, initializeAgent } from './agent.js';

const router: express.Router = express.Router();

// Accept credential offer from ACA-Py issuer
router.post('/accept-offer', async (req: any, res: any) => {
  let agent = getAgent();
  try {
    if (!agent) {
      agent = await initializeAgent(3020);
    }

    const { credential_offer } = req.body;

    if (!credential_offer) {
      return res.status(400).json({
        error: 'credential_offer is required'
      });
    }

    console.log('📥 Accepting credential offer:', typeof credential_offer === 'string' ? credential_offer : 'JSON Object');

    // Resolve the credential offer first
    const resolvedOffer = await agent!.openid4vc.holder.resolveCredentialOffer(
        typeof credential_offer === 'string' 
            ? credential_offer 
            : `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credential_offer))}`
    );

    console.log('✅ Offer resolved', JSON.stringify(resolvedOffer, null, 2));

    let generatedDidUrl: string | undefined;

    // Credential binding resolver for 0.6.0 API
    const credentialBindingResolver = async (bindingOptions: any) => {
        console.log('🔒 Binding options received:', JSON.stringify(bindingOptions, null, 2));
        
        const { supportedDidMethods, supportsAllDidMethods, supportsJwk, proofTypes, credentialFormat } = bindingOptions;
        
        // Check if this is mso_mdoc format - DIDs are not supported for mdoc
        const isMdoc = credentialFormat === 'mso_mdoc';
        
        // Determine signature algorithm - prefer ES256 for mdoc, otherwise use first supported
        let algorithm: 'EdDSA' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256K' = 'EdDSA';
        if (proofTypes?.jwt?.supportedSignatureAlgorithms) {
            algorithm = proofTypes.jwt.supportedSignatureAlgorithms[0] as typeof algorithm;
        }
        
        // Force ES256 for mdoc
        if (isMdoc) {
            console.log('⚠️ Forcing ES256 algorithm for mso_mdoc credential');
            algorithm = 'ES256';
        }

        console.log('🔒 Creating key for algorithm:', algorithm);
        
        try {
            // Create key using the lower-level createKey API with explicit key type
            const algStr = algorithm as string;
            const keyType = algStr === 'ES256' ? { kty: 'EC' as const, crv: 'P-256' as const } 
                          : algStr === 'ES384' ? { kty: 'EC' as const, crv: 'P-384' as const }
                          : algStr === 'ES256K' ? { kty: 'EC' as const, crv: 'secp256k1' as const }
                          : { kty: 'OKP' as const, crv: 'Ed25519' as const }; // EdDSA default
            
            console.log('🔒 Creating key with type:', JSON.stringify(keyType));
            
            const key = await agent!.kms.createKey({
                type: keyType,
            });
            
            console.log('🔑 Created key with ID:', key.keyId);

            // For mso_mdoc, we MUST use jwk binding (DIDs are not supported)
            if (isMdoc) {
                console.log('📋 Using JWK binding for mso_mdoc credential');
                // Import PublicJwk from core to create the proper JWK object
                const { Kms } = await import('@credo-ts/core');
                const publicJwk = Kms.PublicJwk.fromPublicJwk(key.publicJwk);
                return {
                    method: 'jwk',
                    keys: [publicJwk],
                };
            }
        
            // For non-mdoc, create a DID for the key
            const didResult = await agent!.dids.create({
                method: 'key',
                options: {
                    keyId: key.keyId,
                },
            });
            
            const did = didResult.didState.did;
            if (!did) {
                throw new Error('Failed to create DID - didState.did is undefined');
            }
            
            let didUrl = did;
            
            // Ensure we have a fragment for did:key
            if (did.startsWith('did:key:')) {
                // Check if we have the document to get the exact key ID
                if (didResult.didState.didDocument?.verificationMethod?.[0]?.id) {
                    didUrl = didResult.didState.didDocument.verificationMethod[0].id;
                } else {
                    // Fallback: construct the standard did:key key ID (did#fingerprint)
                    const fingerprint = did.split(':')[2];
                    didUrl = `${did}#${fingerprint}`;
                }
            }
            
            console.log('🔑 Generated DID URL:', didUrl);
            generatedDidUrl = didUrl;

            // Return in 0.6.0 format - array of didUrls
            return {
                method: 'did',
                didUrls: [didUrl],
            };
        } catch (keyError) {
            console.error('❌ Error creating key:', keyError);
            throw keyError;
        }
    };

    // In Credo 0.6.0, use requestToken + requestCredentials
    const tokenResponse = await agent!.openid4vc.holder.requestToken({
        resolvedCredentialOffer: resolvedOffer,
    });

    console.log('✅ Token received');

    const credentialResponse = await agent!.openid4vc.holder.requestCredentials({
        resolvedCredentialOffer: resolvedOffer,
        ...tokenResponse,
        credentialBindingResolver,
    });

    console.log('🎫 Credential Response:', JSON.stringify(credentialResponse, null, 2));

    // Handle credentials from the response - in 0.6.0 each credential has a 'record' property
    const credentials = credentialResponse.credentials || [];
    
    // Store credentials using the pre-hydrated records from Credo 0.6.0
    for (const credentialItem of credentials) {
        try {
            // In Credo 0.6.0, each credential item has a 'record' that is already the appropriate record type
            const record = credentialItem.record;
            
            if (!record) {
                console.log('⚠️ No record found in credential item, skipping storage');
                continue;
            }

            const recordType = record.constructor?.name || 'unknown';
            console.log(`📝 Storing credential record of type: ${recordType}`);

            // Store based on record type
            if (recordType === 'MdocRecord' || record.type === 'MdocRecord') {
                // @ts-ignore
                await agent!.mdoc.store({ record });
                console.log('✅ Stored MdocRecord');
            } else if (recordType === 'SdJwtVcRecord' || record.type === 'SdJwtVcRecord') {
                // @ts-ignore
                await agent!.sdJwtVc.store({ record });
                console.log('✅ Stored SdJwtVcRecord');
            } else if (recordType === 'W3cCredentialRecord' || recordType === 'W3cV2CredentialRecord') {
                // @ts-ignore
                await agent!.w3cCredentials.store({ record });
                console.log('✅ Stored W3cCredentialRecord');
            } else {
                console.log(`⚠️ Unknown record type: ${recordType}, attempting generic storage`);
                // Fallback for unknown types - try w3c storage
                try {
                    // @ts-ignore
                    await agent!.w3cCredentials.store({ record });
                } catch (e) {
                    console.error('Failed to store with w3cCredentials, trying sdJwtVc:', e);
                    // @ts-ignore
                    await agent!.sdJwtVc.store({ record });
                }
            }
        } catch (e) {
            console.error('Failed to store credential:', e);
        }
    }

    const firstCredential = credentials[0];

    let format = 'unknown';
    if (firstCredential?.record) {
        const recordType = firstCredential.record.constructor?.name || '';
        if (recordType.includes('Mdoc')) format = 'mso_mdoc';
        else if (recordType.includes('SdJwt')) format = 'vc+sd-jwt';
        else if (recordType.includes('W3c')) format = 'jwt_vc_json';
    }

    res.json({
      success: true,
      credential: firstCredential,
      format: format
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
