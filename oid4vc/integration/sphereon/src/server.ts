import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import { OpenID4VCIClientV1_0_13 } from "@sphereon/oid4vci-client";
import { Jwt, ProofOfPossessionCallbacks, Alg } from '@sphereon/oid4vci-common';
import * as jose from 'jose';
import { DIDDocument } from 'did-resolver';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const port = process.env.PORT || 3010;

app.use(bodyParser.json());

app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'ok' });
});

app.post('/oid4vci/accept-offer', async (req: Request, res: Response) => {
  try {
    const { offer, format, invalid_proof } = req.body;
    if (!offer) {
      return res.status(400).json({ error: 'Missing offer in request body' });
    }

    console.log('Accepting offer:', offer);

    let offerToUse = offer;

    // Handle pass-by-reference offers manually if needed
    if (offer.startsWith('openid-credential-offer://')) {
        try {
            const parts = offer.split('?');
            if (parts.length > 1) {
                const urlParams = new URLSearchParams(parts[1]);
                if (urlParams.has('credential_offer')) {
                    const offerVal = urlParams.get('credential_offer');
                    if (offerVal && offerVal.startsWith('http')) {
                        console.log('Detected credential_offer by reference. Fetching from:', offerVal);
                        // @ts-ignore
                        const response = await fetch(offerVal);
                        if (!response.ok) {
                            throw new Error(`Failed to fetch credential offer: ${response.statusText}`);
                        }
                        const offerJson = await response.json();
                        // Check if the response is wrapped in an "offer" property (ACA-Py behavior)
                        let actualOffer = offerJson;
                        // @ts-ignore
                        if (offerJson.offer) {
                            // @ts-ignore
                            actualOffer = offerJson.offer;
                        }

                        // Reconstruct offer with value
                        const encodedJson = encodeURIComponent(JSON.stringify(actualOffer));
                        offerToUse = `openid-credential-offer://?credential_offer=${encodedJson}`;
                    }
                }
            }
        } catch (e) {
            console.error('Failed to resolve credential offer reference:', e);
        }
    }

    const client = await OpenID4VCIClientV1_0_13.fromURI({
      uri: offerToUse,
      clientId: 'test-clientId',
      retrieveServerMetadata: true,
    });

    // Acquire access token and capture the response (includes c_nonce for proof)
    let tokenBody: any = null;
    try {
        const tokenResult = await client.acquireAccessToken();
        tokenBody = (tokenResult as any)?.successBody ?? tokenResult;
        console.log('Access token acquired');
    } catch (e) {
        console.log('Note: Failed to acquire access token (might not be needed for this flow):', e);
    }

    // Generate a key pair for the holder binding
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256');
    const publicJwk = await jose.exportJWK(publicKey);
    
    // Create a did:jwk
    const didJwk = `did:jwk:${Buffer.from(JSON.stringify(publicJwk)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}`;
    const kid = `${didJwk}#0`;

    async function signCallback(args: Jwt, kid?: string): Promise<string> {
      const jwt = await new jose.SignJWT(args.payload as any)
        .setProtectedHeader(args.header)
        .setIssuedAt()
        .setIssuer(didJwk)
        .setAudience(args.payload.aud as string | string[])
        .setExpirationTime('5m')
        .sign(privateKey);

      if (invalid_proof) {
          console.log('Tampering with proof signature');
          return jwt.substring(0, jwt.length - 10) + 'XXXXXXXXXX';
      }
      return jwt;
    }

    const callbacks: ProofOfPossessionCallbacks<DIDDocument> = {
      signCallback,
    };

    // We extract the credential configuration IDs from the offer
    // @ts-ignore
    const credentialOffer = client.credentialOffer;
    if (!credentialOffer || !credentialOffer.credential_offer) {
         throw new Error('No credential offer found in client');
    }
    const payload = credentialOffer.credential_offer as any;
    const credentialConfigurationIds = payload.credential_configuration_ids;

    if (!credentialConfigurationIds || credentialConfigurationIds.length === 0) {
        throw new Error('No credential configuration IDs found in offer');
    }

    // We use the first configuration ID found
    const credentialIdentifier = credentialConfigurationIds[0];

    // -----------------------------------------------------------------------
    // Custom mso_mdoc path: the Sphereon OID4VCI library (v0.13) does not
    // support parsing CBOR-encoded mso_mdoc credential responses.  We bypass
    // it and send the credential request manually using raw fetch so we can
    // return the base64url-encoded IssuerSigned bytes as-is.
    // -----------------------------------------------------------------------
    if (format === 'mso_mdoc') {
        // Extract endpoint metadata from the initialised client.
        // Different versions of the Sphereon library surface these under
        // different property paths, so we try all common locations.
        const endpointMeta: any = (client as any).endpointMetadata ?? {};
        const openIdMeta: any =
            endpointMeta.openIDResponse ??
            endpointMeta.credential_issuer_metadata ??
            {};
        const credentialEndpoint: string =
            // Direct property (some v0.13 builds expose it here)
            endpointMeta.credential_endpoint ??
            openIdMeta.credential_endpoint ??
            `${endpointMeta.issuer ?? openIdMeta.credential_issuer ?? ''}/credential`;
        const issuerValue: string | undefined =
            openIdMeta.credential_issuer ?? openIdMeta.issuer ?? endpointMeta.issuer;

        const accessTokenValue: string | undefined =
            tokenBody?.access_token ??
            (client as any)?.accessToken?.access_token;
        if (!accessTokenValue) {
            throw new Error('No access token available for mso_mdoc credential request');
        }
        if (!credentialEndpoint) {
            throw new Error('No credential_endpoint found in server metadata for mso_mdoc');
        }

        // Build OID4VCI proof JWT — include c_nonce when provided by the token endpoint
        const cNonce: string | undefined = tokenBody?.c_nonce ?? tokenBody?.c_nonce_value;
        const proofClaims: any = { iat: Math.floor(Date.now() / 1000) };
        if (issuerValue) proofClaims.aud = issuerValue;
        if (cNonce) proofClaims.nonce = cNonce;

        const proofJwt = await new jose.SignJWT(proofClaims)
            .setProtectedHeader({
                alg: 'ES256',
                typ: 'openid4vci-proof+jwt',
                jwk: publicJwk,
            })
            .setIssuedAt()
            .sign(privateKey);

        // POST credential request directly to the issuer endpoint
        const mdocCredReqBody = {
            credential_identifier: credentialIdentifier,
            proof: { proof_type: 'jwt', jwt: proofJwt },
        };

        // @ts-ignore – fetch is available in Node 18+
        const mdocFetchResponse = await fetch(credentialEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${accessTokenValue}`,
            },
            body: JSON.stringify(mdocCredReqBody),
        });

        if (!mdocFetchResponse.ok) {
            const errText = await mdocFetchResponse.text();
            throw new Error(
                `mso_mdoc credential request failed: ${mdocFetchResponse.status} ${errText}`,
            );
        }

        const mdocCredJson = await mdocFetchResponse.json();
        const mdocCredential =
            (mdocCredJson as any).credential ??
            ((mdocCredJson as any).credentials as any[])?.[0]?.credential;

        console.log('mso_mdoc credential acquired via direct fetch');
        return res.json({ credential: mdocCredential });
    }
    // -----------------------------------------------------------------------
    // Default path: use the Sphereon library for JWT / SD-JWT formats
    // -----------------------------------------------------------------------

    const credentialResponse = await client.acquireCredentials({
      credentialIdentifier: credentialIdentifier,
      proofCallbacks: callbacks,
      // Pass format as an internal hint so the library can determine the signing
      // algorithm. The Sphereon library does NOT include 'format' in the HTTP
      // request body when credentialIdentifier is set (OID4VCI 1.0 §7.2 is satisfied).
      format: (format || 'jwt_vc_json') as any,
      alg: Alg.ES256,
      kid: kid,
    });

    console.log('Credential acquired successfully');
    console.log('Credential response keys:', Object.keys(credentialResponse));

    // Handle both OID4VCI 1.0 (credentials array) and legacy draft (credential field).
    // OID4VCI 1.0 final spec returns: {"credentials": [{"credential": "eyJ..."}]}
    // Older draft spec returned: {"credential": "eyJ...", "format": "..."}
    const responseAny = credentialResponse as any;
    const credential =
      responseAny.credential ??
      (responseAny.credentials as any[])?.[0]?.credential;

    res.json({ credential });

  } catch (error: any) {
    console.error('Error accepting offer:', error);
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

app.post('/oid4vp/present-credential', async (req: Request, res: Response) => {
  try {
    const { authorization_request_uri, verifiable_credentials } = req.body;
    if (!authorization_request_uri) {
      return res.status(400).json({ error: 'Missing authorization_request_uri' });
    }
    if (!verifiable_credentials || verifiable_credentials.length === 0) {
        return res.status(400).json({ error: 'Missing verifiable_credentials' });
    }

    console.log('Presenting credential to:', authorization_request_uri);

    // 1. Resolve the Authorization Request
    let requestJwt = authorization_request_uri;
    if (authorization_request_uri.startsWith('openid-vc://') || authorization_request_uri.startsWith('openid4vp://') || authorization_request_uri.startsWith('openid://')) {
        let urlString = authorization_request_uri.replace(/^(openid-vc|openid4vp|openid):/, 'http:');
        if (urlString.startsWith('http://?')) {
            urlString = urlString.replace('http://?', 'http://localhost/?');
        }
        const url = new URL(urlString);
        const requestUri = url.searchParams.get('request_uri');
        if (requestUri) {
             // @ts-ignore
             const response = await fetch(requestUri);
             requestJwt = await response.text();
        } else {
            requestJwt = url.searchParams.get('request');
        }
    }
    
    if (!requestJwt) {
         throw new Error('Could not extract request JWT from URI');
    }
    
    // Decode Request JWT
    const requestPayload = jose.decodeJwt(requestJwt);
    console.log('Request Payload:', requestPayload);
    
    const { nonce, response_uri, client_id, state } = requestPayload;
    
    if (!response_uri) {
        throw new Error('No response_uri in authorization request');
    }

    // Create VP
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256');
    const publicJwk = await jose.exportJWK(publicKey);
    const didJwk = `did:jwk:${Buffer.from(JSON.stringify(publicJwk)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}`;
    const kid = `${didJwk}#0`;
    
    const vpPayload = {
        iss: didJwk,
        sub: didJwk,
        vp: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiablePresentation'],
            verifiableCredential: verifiable_credentials
        },
        nonce: nonce,
        aud: client_id
    };
    
    const vpToken = await new jose.SignJWT(vpPayload as any)
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: kid })
        .setIssuedAt()
        .setIssuer(didJwk)
        .setAudience(client_id as string)
        .sign(privateKey);
        
    // Create Presentation Submission
    const presentationDefinition = (requestPayload as any).presentation_definition;
    let submission = null;
    
    if (presentationDefinition) {
        const descriptorId = presentationDefinition.input_descriptors[0].id;
        submission = {
            id: uuidv4(),
            definition_id: presentationDefinition.id,
            descriptor_map: [
                {
                    id: descriptorId,
                    format: 'jwt_vp',
                    path: '$',
                    path_nested: {
                        id: descriptorId,
                        format: 'jwt_vc',
                        path: '$.vp.verifiableCredential[0]'
                    }
                }
            ]
        };
    }
    
    // Send Response
    const formData = new URLSearchParams();
    formData.append('vp_token', vpToken);
    if (submission) {
        formData.append('presentation_submission', JSON.stringify(submission));
    }
    if (state) {
        formData.append('state', state as string);
    }
    
    // @ts-ignore
    const postResponse = await fetch(response_uri as string, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formData
    });
    
    if (!postResponse.ok) {
        const text = await postResponse.text();
        throw new Error(`VP submission failed: ${postResponse.status} ${text}`);
    }

    // ACA-Py returns 200 with an empty body from its post_response handler.
    // Safely attempt JSON parse; treat empty/non-JSON body as a success response.
    let jsonResponse: any = { success: true };
    try {
        const responseText = await postResponse.text();
        if (responseText.trim()) {
            jsonResponse = JSON.parse(responseText);
        }
    } catch (_e) {
        // Non-JSON body is acceptable; ACA-Py uses empty 200 responses
    }
    res.json(jsonResponse);

  } catch (error: any) {
    console.error('Error presenting credential:', error);
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

app.listen(port, () => {
  console.log(`Sphereon wrapper listening on port ${port}`);
});
