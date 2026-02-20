import express from 'express';
import { getAgent } from './agent.js';
import { logger } from './logger.js';

const router: express.Router = express.Router();

// Accept credential offer from ACA-Py issuer
router.post('/accept-offer', async (req: any, res: any) => {
  const agent = getAgent();
  try {

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

    // Credential binding resolver for 0.6.0 API
    // We always use JWK binding for all credential formats.
    // Using did:key would require ACA-Py to resolve the DID document and handle
    // the 'Multikey' verification method type, which it currently doesn't support.
    // JWK binding sends the holder's public key directly in the proof JWT 'jwk' header,
    // which ACA-Py verifies via Key.from_jwk() without any DID resolution.
    //
    // We capture each created key ID so we can set kmsKeyId on SdJwtVcRecord instances
    // after issuance. Credo 0.6.x only maps kmsKeyId for dc+sd-jwt or when the issuer
    // metadata includes vct at the top level; for vc+sd-jwt without vct it is skipped.
    // Setting it manually ensures key binding JWT signing works during presentations.
    const createdKeyIds: string[] = [];
    const credentialBindingResolver = async (bindingOptions: any) => {
        console.log('🔒 Binding options received:', JSON.stringify(bindingOptions, null, 2));
        
        const { proofTypes, credentialFormat } = bindingOptions;
        
        // Determine signature algorithm
        // - mso_mdoc requires ES256 (P-256)
        // - Otherwise use the first algorithm advertised by the issuer, defaulting to EdDSA
        let algorithm: 'EdDSA' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256K' = 'EdDSA';
        if (credentialFormat === 'mso_mdoc') {
            algorithm = 'ES256';
        } else if (proofTypes?.jwt?.supportedSignatureAlgorithms) {
            algorithm = proofTypes.jwt.supportedSignatureAlgorithms[0] as typeof algorithm;
        }

        console.log('🔒 Creating key for algorithm:', algorithm);
        
        try {
            const algStr = algorithm as string;
            const keyType = algStr === 'ES256' ? { kty: 'EC' as const, crv: 'P-256' as const } 
                          : algStr === 'ES384' ? { kty: 'EC' as const, crv: 'P-384' as const }
                          : algStr === 'ES256K' ? { kty: 'EC' as const, crv: 'secp256k1' as const }
                          : { kty: 'OKP' as const, crv: 'Ed25519' as const };
            
            const key = await agent!.kms.createKey({ type: keyType });
            console.log('🔑 Created key with ID:', key.keyId);
            createdKeyIds.push(key.keyId);

            // Always use JWK binding - the proof JWT will carry the holder's public key
            // in the 'jwk' header, which ACA-Py resolves directly without DID lookup.
            const { Kms } = await import('@credo-ts/core');
            const publicJwk = Kms.PublicJwk.fromPublicJwk(key.publicJwk);
            return {
                method: 'jwk',
                keys: [publicJwk],
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
    for (const [credentialIndex, credentialItem] of credentials.entries()) {
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
                // @ts-ignore - Credo 0.6.x mdoc module API has incomplete type definitions
                await agent!.mdoc.store({ record });
                console.log('✅ Stored MdocRecord');
            } else if (recordType === 'SdJwtVcRecord' || record.type === 'SdJwtVcRecord') {
                // Credo 0.6.x only maps kmsKeyId onto SdJwtVcRecord instances when the
                // credential format is dc+sd-jwt OR when the issuer metadata has a top-level
                // `vct` field (FIXME in OpenId4VciHolderService.ts:1230).  For vc+sd-jwt
                // credentials where the issuer uses a credential_definition instead, the
                // mapping is skipped and kmsKeyId stays undefined, causing presentation to
                // fall back to legacyKeyId (= JWK thumbprint) which is NOT the key id
                // stored in askar.  We fix this by applying the captured key id here.
                const keyId = createdKeyIds[credentialIndex];
                if (keyId) {
                    const instances: any[] = (record as any).credentialInstances ?? [];
                    for (const instance of instances) {
                        if (!instance.kmsKeyId) {
                            instance.kmsKeyId = keyId;
                            console.log(`🔑 Set kmsKeyId=${keyId} on SdJwtVcRecord instance`);
                        }
                    }
                }
                // @ts-ignore - Credo 0.6.x sdJwtVc module API has incomplete type definitions
                await agent!.sdJwtVc.store({ record });
                console.log('✅ Stored SdJwtVcRecord');
            } else if (recordType === 'W3cCredentialRecord' || recordType === 'W3cV2CredentialRecord') {
                // @ts-ignore - Credo 0.6.x w3cCredentials module API has incomplete type definitions
                await agent!.w3cCredentials.store({ record });
                console.log('✅ Stored W3cCredentialRecord');
            } else {
                console.log(`⚠️ Unknown record type: ${recordType}, attempting generic storage`);
                // Fallback for unknown types - try w3c storage
                try {
                    // @ts-ignore - Credo 0.6.x w3cCredentials module API has incomplete type definitions
                    await agent!.w3cCredentials.store({ record });
                } catch (e) {
                    console.error('Failed to store with w3cCredentials, trying sdJwtVc:', e);
                    // @ts-ignore - Credo 0.6.x sdJwtVc module API has incomplete type definitions
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
        // Use both constructor.name and record.type to handle minified/compiled code
        const recordType = (firstCredential.record.constructor?.name || '') +
                           ((firstCredential.record as any).type || '');
        if (recordType.includes('Mdoc')) format = 'mso_mdoc';
        else if (recordType.includes('SdJwt')) format = 'vc+sd-jwt';
        else if (recordType.includes('W3c')) format = 'jwt_vc_json';
    }

    // Extract the actual credential string/value from the stored record.
    // Each Credo record type uses a different property for the compact/encoded form.
    let credentialValue: string | undefined;
    if (firstCredential?.record) {
        const record = firstCredential.record as any;

        if (format === 'mso_mdoc') {
            // MdocRecord: credentialInstances[0].issuerSignedBase64Url
            const instances = record.credentialInstances;
            if (instances && instances.length > 0 && instances[0].issuerSignedBase64Url) {
                credentialValue = instances[0].issuerSignedBase64Url;
            }
        } else if (format === 'vc+sd-jwt' || format === 'dc+sd-jwt') {
            // SdJwtVcRecord: credentialInstances[0].compactSdJwtVc
            const instances = record.credentialInstances;
            if (instances && instances.length > 0 && instances[0].compactSdJwtVc) {
                credentialValue = instances[0].compactSdJwtVc;
            }
        } else {
            // W3cCredentialRecord (jwt_vc_json): try multiple property paths because
            // the Credo property name changed across versions:
            //   Credo 0.6.x: W3cJwtVerifiableCredential.serializedJwt
            //   Older Credo: W3cJwtVerifiableCredential.serializedJwtVc
            const cred = record.credential;
            if (cred) {
                if (typeof cred.serializedJwt === 'string') {
                    // Credo 0.6.x property name
                    credentialValue = cred.serializedJwt;
                } else if (typeof cred.serializedJwtVc === 'string') {
                    // Legacy property name (older Credo versions)
                    credentialValue = cred.serializedJwtVc;
                } else if (typeof cred === 'string') {
                    credentialValue = cred;
                } else {
                    // JSON-LD or unknown: serialize the credential object
                    credentialValue = JSON.stringify(cred);
                }
            }
            // Fallback: try credentialInstances (same pattern as mso_mdoc and vc+sd-jwt)
            if (!credentialValue && record.credentialInstances) {
                const instances = record.credentialInstances as any[];
                if (instances.length > 0) {
                    const inst = instances[0];
                    credentialValue = inst.serializedJwt || inst.compactJwtVc || inst.credential;
                }
            }
        }

        if (!credentialValue) {
            console.warn('⚠️ Could not extract credential string for format:', format, 'record type:', record.constructor?.name, record.type);
        }
    }

    res.json({
      success: true,
      // Use null (not undefined) to prevent JSON.stringify from omitting the key.
      // Tests check for credential_data["credential"] and would get KeyError if omitted.
      credential: credentialValue !== undefined ? credentialValue : null,
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
