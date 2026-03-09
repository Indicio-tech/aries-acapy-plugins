import unittest

from mso_mdoc.cred_processor import MsoMdocCredProcessor


class TestMsoMdocCredProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = MsoMdocCredProcessor()

    def test_transform_issuer_metadata_preserves_namespace_claims_dict(self):
        """mso_mdoc claims namespace dict is preserved as-is (not converted to array).

        Per OID4VCI 1.0 Appendix B.2, mso_mdoc uses a namespace-keyed dict for
        claims, unlike sd_jwt_vc which uses a flat path-array.
        """
        original_claims = {
            "org.iso.18013.5.1": {
                "given_name": {
                    "mandatory": True,
                    "display": [{"name": "Given Name", "locale": "en"}],
                },
                "family_name": {"mandatory": True},
            }
        }
        metadata = {"claims": original_claims}
        self.processor.transform_issuer_metadata(metadata)
        self.assertIsInstance(metadata["claims"], dict)
        self.assertEqual(metadata["claims"], original_claims)

    def test_transform_issuer_metadata_converts_cose_alg(self):
        """Algorithm strings are converted to COSE integer identifiers."""
        metadata = {"credential_signing_alg_values_supported": ["ES256", "ES384"]}
        self.processor.transform_issuer_metadata(metadata)
        self.assertEqual(
            metadata["credential_signing_alg_values_supported"], [-7, -35]
        )

    def test_transform_issuer_metadata_noop_when_claims_already_dict(self):
        """Already dict claims stay unchanged (idempotent transform)."""
        original = {"org.iso.18013.5.1": {"given_name": {"mandatory": True}}}
        metadata = {"claims": original}
        self.processor.transform_issuer_metadata(metadata)
        self.assertEqual(metadata["claims"], original)

    def test_prepare_payload_flattens_doctype(self):
        """Test that _prepare_payload flattens the dictionary if doctype is present as a key."""
        doctype = "org.iso.18013.5.1.mDL"
        payload = {
            doctype: {"given_name": "John", "family_name": "Doe"},
            "other_field": "value",
        }

        prepared = self.processor._prepare_payload(payload, doctype)

        self.assertIn("given_name", prepared)
        self.assertEqual(prepared["given_name"], "John")
        self.assertIn("family_name", prepared)
        self.assertEqual(prepared["family_name"], "Doe")
        self.assertNotIn(doctype, prepared)
        self.assertEqual(prepared["other_field"], "value")

    def test_prepare_payload_no_flattening_needed(self):
        """Test that _prepare_payload leaves flat dictionaries alone."""
        doctype = "org.iso.18013.5.1.mDL"
        payload = {"given_name": "John", "family_name": "Doe"}

        prepared = self.processor._prepare_payload(payload, doctype)

        self.assertEqual(prepared["given_name"], "John")
        self.assertEqual(prepared["family_name"], "Doe")

    def test_prepare_payload_encodes_portrait(self):
        """Test that _prepare_payload encodes binary portrait data."""
        payload = {"portrait": b"binary_data"}

        prepared = self.processor._prepare_payload(payload)

        self.assertIsInstance(prepared["portrait"], str)
        # "binary_data" in base64 is "YmluYXJ5X2RhdGE="
        self.assertEqual(prepared["portrait"], "YmluYXJ5X2RhdGE=")

    def test_prepare_payload_encodes_portrait_list(self):
        """Test that _prepare_payload encodes list of bytes portrait data."""
        # [97, 98, 99] is b"abc"
        payload = {"portrait": [97, 98, 99]}

        prepared = self.processor._prepare_payload(payload)

        self.assertIsInstance(prepared["portrait"], str)
        # "abc" in base64 is "YWJj"
        self.assertEqual(prepared["portrait"], "YWJj")
