import { v4 as uuidv4 } from 'uuid';

// Helper function to parse presentation request
export async function parsePresentationRequest(requestUri: string) {
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
export async function createPresentation(
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
export async function submitPresentation(requestUri: string, presentation: any) {
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
