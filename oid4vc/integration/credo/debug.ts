/**
 * Debug routes for isolating integration test failures.
 *
 * These endpoints expose internal Credo record structures that are not
 * visible from the standard /oid4vci/accept-offer response, giving us
 * exact knowledge of what Credo returns from requestCredentials() for
 * each credential format.
 *
 * Intended for use by targeted integration tests only — not production use.
 */

import express from 'express';
import { getAgent } from './agent.js';

const router: express.Router = express.Router();

// ---------------------------------------------------------------------------
// Helper: deep-inspect a single credential record returned by Credo
// ---------------------------------------------------------------------------

function inspectRecord(record: any): Record<string, unknown> {
  const info: Record<string, unknown> = {
    constructor_name: record?.constructor?.name ?? null,
    record_type: record?.type ?? null,
    own_keys: record ? Object.keys(record) : [],
    prototype_keys: record
      ? Object.getOwnPropertyNames(Object.getPrototypeOf(record))
      : [],
  };

  // credentialInstances (W3cCredentialRecord, SdJwtVcRecord, MdocRecord)
  const instances: any[] = record?.credentialInstances ?? [];
  info.credential_instances_count = instances.length;
  info.credential_instances = instances.map((inst: any) => {
    const entry: Record<string, unknown> = { own_keys: Object.keys(inst) };
    for (const [k, v] of Object.entries(inst)) {
      if (typeof v === 'string') {
        entry[k] = (v as string).length > 100
          ? (v as string).substring(0, 100) + '…'
          : v;
      } else if (v === null || v === undefined) {
        entry[k] = v;
      } else if (typeof v === 'object') {
        entry[k] = { type: (v as any)?.constructor?.name, keys: Object.keys(v as any) };
      } else {
        entry[k] = typeof v;
      }
    }
    return entry;
  });

  // Test well-known getters / properties
  const getterMap: Record<string, unknown> = {};
  for (const key of [
    'encoded', 'firstCredential', 'credential', 'type',
    'claimFormat', 'jwt', 'serializedJwt', 'compact', 'base64Url',
  ]) {
    try {
      const val = (record as any)[key];
      if (val === undefined) {
        getterMap[key] = '__undefined__';
      } else if (typeof val === 'string') {
        getterMap[key] = val.length > 100 ? val.substring(0, 100) + '…' : val;
      } else if (val === null) {
        getterMap[key] = null;
      } else if (typeof val === 'object') {
        getterMap[key] = {
          type: (val as any)?.constructor?.name,
          keys: Object.keys(val as any).slice(0, 20),
        };
      } else {
        getterMap[key] = `${typeof val}: ${val}`;
      }
    } catch (e: any) {
      getterMap[key] = `ERROR: ${e?.message}`;
    }
  }
  info.getters = getterMap;

  // What does JSON.stringify see?
  try {
    const plain = JSON.parse(JSON.stringify(record));
    info.serialized_keys = Object.keys(plain);
    const plainInstances: any[] = plain?.credentialInstances ?? [];
    info.serialized_instances = plainInstances.map((inst: any) => ({
      keys: Object.keys(inst),
      credential_preview: typeof inst.credential === 'string'
        ? inst.credential.substring(0, 100)
        : JSON.stringify(inst.credential)?.substring(0, 80),
    }));
  } catch (e: any) {
    info.serialize_error = e?.message;
  }

  return info;
}

// ---------------------------------------------------------------------------
// POST /debug/resolve-offer
//
// Resolve a credential offer and return the offer metadata, so we can see
// exactly what formats and binding methods the issuer advertises.
// ---------------------------------------------------------------------------

router.post('/resolve-offer', async (req: any, res: any) => {
  const agent = getAgent();
  try {
    const { credential_offer } = req.body;
    if (!credential_offer) {
      return res.status(400).json({ error: 'credential_offer is required' });
    }

    const resolved = await agent!.openid4vc.holder.resolveCredentialOffer(
      typeof credential_offer === 'string'
        ? credential_offer
        : `openid-credential-offer://?credential_offer=${encodeURIComponent(
            JSON.stringify(credential_offer)
          )}`
    );

    const configs: Record<string, unknown> = {};
    for (const [id, config] of Object.entries(
      resolved.offeredCredentialConfigurations
    )) {
      const c = config as any;
      configs[id] = {
        format: c.format,
        cryptographic_binding_methods_supported:
          c.cryptographic_binding_methods_supported,
        proof_types_supported: c.proof_types_supported,
        scope: c.scope,
      };
    }

    res.json({
      credential_issuer:
        resolved.metadata?.credentialIssuer?.credential_issuer,
      draft_version: (resolved.metadata as any)?.originalDraftVersion,
      offered_configurations: configs,
    });
  } catch (error: any) {
    res.status(500).json({
      error: 'Resolve failed',
      details: error?.message || String(error),
    });
  }
});

// ---------------------------------------------------------------------------
// POST /debug/accept-offer-inspect
//
// Run the full requestCredentials() flow for a credential offer and return
// a deep inspection of every returned record — without trying to extract a
// "nice" credential value.  The response shows exactly what keys/values each
// record exposes so we can write correct extraction code (or a targeted fix).
//
// Also captures the binding resolver input so we can see the credentialFormat
// and proofTypes that Credo passes us.
// ---------------------------------------------------------------------------

router.post('/accept-offer-inspect', async (req: any, res: any) => {
  const agent = getAgent();
  try {
    const { credential_offer } = req.body;
    if (!credential_offer) {
      return res.status(400).json({ error: 'credential_offer is required' });
    }

    const resolvedOffer = await agent!.openid4vc.holder.resolveCredentialOffer(
      typeof credential_offer === 'string'
        ? credential_offer
        : `openid-credential-offer://?credential_offer=${encodeURIComponent(
            JSON.stringify(credential_offer)
          )}`
    );

    // Capture what the binding resolver is called with
    const bindingResolverCalls: any[] = [];

    const credentialBindingResolver = async (opts: any) => {
      const { proofTypes, credentialFormat, supportsJwk, supportsAllDidMethods,
              supportedDidMethods } = opts;
      const call: any = {
        credentialFormat,
        supportsJwk,
        supportsAllDidMethods,
        supportedDidMethods,
        proof_type_algs: proofTypes?.jwt?.supportedSignatureAlgorithms,
      };

      let algorithm: string = 'EdDSA';
      if (credentialFormat === 'mso_mdoc') {
        algorithm = 'ES256';
      } else if (proofTypes?.jwt?.supportedSignatureAlgorithms?.[0]) {
        algorithm = proofTypes.jwt.supportedSignatureAlgorithms[0];
      }

      // Credo 0.6.x throws for JWK binding on W3C credential formats (jwt_vc_json,
      // jwt_vc_json-ld, ldp_vc). Use did:key binding for those; JWK for others.
      // ACA-Py's key_material_for_kid() now handles the Multikey VM type that
      // Credo 0.6.x did:key documents use.
      const W3C_FORMATS = ['jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc'];
      if (W3C_FORMATS.includes(credentialFormat)) {
        const algStr2 = algorithm as string;
        const kmsKeyType2 = algStr2 === 'ES256'
          ? { kty: 'EC' as const, crv: 'P-256' as const }
          : { kty: 'OKP' as const, crv: 'Ed25519' as const };
        try {
          const w3cKey = await agent!.kms.createKey({ type: kmsKeyType2 });
          const didResult = await agent!.dids.create({ method: 'key', options: { keyId: w3cKey.keyId } });
          const didState = (didResult.didState as any);
          if (didState.state !== 'finished') {
            throw new Error(`did:key creation failed: ${JSON.stringify(didState)}`);
          }
          const verificationMethodId =
            didState.didDocument?.verificationMethod?.[0]?.id ?? didState.did;
          call.resolved_method = 'did';
          call.resolved_algorithm = algorithm;
          bindingResolverCalls.push(call);
          return { method: 'did', didUrls: [verificationMethodId] };
        } catch (e) {
          call.resolved_method = 'did:key_error';
          call.resolved_algorithm = algorithm;
          bindingResolverCalls.push(call);
          throw e;
        }
      }

      const algStr = algorithm;
      const keyType =
        algStr === 'ES256' ? { kty: 'EC' as const, crv: 'P-256' as const }
        : algStr === 'ES384' ? { kty: 'EC' as const, crv: 'P-384' as const }
        : algStr === 'ES256K' ? { kty: 'EC' as const, crv: 'secp256k1' as const }
        : { kty: 'OKP' as const, crv: 'Ed25519' as const };

      const key = await agent!.kms.createKey({ type: keyType });
      const { Kms } = await import('@credo-ts/core');
      const publicJwk = Kms.PublicJwk.fromPublicJwk(key.publicJwk);

      call.resolved_method = 'jwk';
      call.resolved_algorithm = algorithm;
      bindingResolverCalls.push(call);

      return { method: 'jwk', keys: [publicJwk] };
    };

    const tokenResponse = await agent!.openid4vc.holder.requestToken({
      resolvedCredentialOffer: resolvedOffer,
    });

    let credentialResponse: any = null;
    let requestError: string | null = null;
    let requestErrorStack: string | null = null;
    try {
      credentialResponse = await agent!.openid4vc.holder.requestCredentials({
        resolvedCredentialOffer: resolvedOffer,
        ...tokenResponse,
        credentialBindingResolver,
      });
    } catch (e: any) {
      requestError = e?.message || String(e);
      requestErrorStack = e?.stack ?? null;
    }

    const result: Record<string, unknown> = {
      binding_resolver_calls: bindingResolverCalls,
      request_error: requestError,
      request_error_stack: requestErrorStack,
      credentials_count: credentialResponse?.credentials?.length ?? 0,
      deferred_count: credentialResponse?.deferredCredentials?.length ?? 0,
      credentials: (credentialResponse?.credentials ?? []).map(
        (item: any) => inspectRecord(item.record)
      ),
    };

    res.json(result);
  } catch (error: any) {
    res.status(500).json({
      error: 'Inspection failed',
      details: error?.message || String(error),
      stack: error?.stack,
    });
  }
});

export default router;
