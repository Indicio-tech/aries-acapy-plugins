"""Test presentation of an SD-JWT VC."""

from uuid import uuid4

from acapy_agent.core.profile import Profile

from oid4vc.pex import PresentationExchangeEvaluator


NESTED_ATRIB_VC = "eyJraWQiOiAiZGlkOmp3azpleUpqY25ZaU9pQWlVQzB5TlRZaUxDQWlhM1I1SWpvZ0lrVkRJaXdnSW5naU9pQWlYMTgyU3pKZlFtVTFPRkp4TkhKTFdUaHFTRkJ2TlVSME0wOUVibXhQWDFaU1VXcHdaM1Z5TFZCVmF5SXNJQ0o1SWpvZ0lraHhhRFl5TjJsVmNsZzJWVlpSYm1KWVJVbzBWMlZSYlZWWE5pMDJORTFQVVd0UmNFWnNTa1pGTm5NaUxDQWlkWE5sSWpvZ0luTnBaeUo5IzAiLCAidHlwIjogInZjK3NkLWp3dCIsICJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIklrT1puVUh2b25tS0lvOVg3d2pyS2kxNHhDYUsxQnp5cHRvT3NfU3lTLXciLCAiX3VZZWlrSWJnNzVwVUVBR3hDSnNOWk1oSmNTMFc1NFM3VWZveUpmUnl6OCJdLCAic29tZXRoaW5nX25lc3RlZCI6IHsiX3NkIjogWyI3Ylh0V1NabFl5bmxSbVBPY29vRy1QZDhKcGxPUFJ4QTdYS3JkR2I4ck1vIl0sICJrZXkyIjogeyJfc2QiOiBbInZqNGRfa0R3ZWFNNVJxNC1NNXhxX3ZlR3ZtdF9CNWZBWGk4UjJzVkg3eWsiXX19LCAic291cmNlX2RvY3VtZW50X3R5cGUiOiAiaWRfY2FyZCIsICJhZ2VfZXF1YWxfb3Jfb3ZlciI6IHsiX3NkIjogWyJHckJCcDh4T0JMV19PdEZfU0hYc0ZISm1adjZWeGtEV29Kc2NFZTlSZWpNIiwgIktFbTJZVGE0ZWJlRU52d1Y1WXM4aWt1a0UxYTZCUlQyMUtlWWtuV3NUek0iLCAiWTRkLVJ2NUwtSFFsTXdTcllvX2hkZlA0TW1Ba2k4VmpRSE9wVFNhSVJNdyIsICJibUVRUy1qU1ZaU2x6eGl1Q0hRbklZdkxSUkw3Y2xaSDVYTzJJS2JCZTJVIiwgImpLdEVKQTBIN01nSVcyNlJabHdBYzFOSjB5OFZEdnlNNm5MS0N5Z0NzUDgiLCAidVpKdnJkaExfSGxrZDItdTFLUjE2S1RIbEZQRVpKYVdtRXhOT25hQS01ayJdfSwgImNuZiI6IHsia2lkIjogImRpZDpqd2s6ZXlKcmRIa2lPaUFpVDB0UUlpd2dJbU55ZGlJNklDSkZaREkxTlRFNUlpd2dJbmdpT2lBaVRrOXBOMTlSY21KVldrZHROVEJNVGswNWVHa3dUR0phY205V1RFbGpXVE5GT0ZSTE1UVlVUVzFJV1NJc0lDSjFjMlVpT2lBaWMybG5JbjAjMCIsICJqd2siOiB7Imt0eSI6ICJPS1AiLCAiY3J2IjogIkVkMjU1MTkiLCAieCI6ICJOT2k3X1FyYlVaR201MExOTTl4aTBMYlpyb1ZMSWNZM0U4VEsxNVRNbUhZIiwgInVzZSI6ICJzaWcifX0sICJ2Y3QiOiAiRXhhbXBsZUlEQ2FyZCIsICJpc3MiOiAiZGlkOmp3azpleUpqY25ZaU9pQWlVQzB5TlRZaUxDQWlhM1I1SWpvZ0lrVkRJaXdnSW5naU9pQWlYMTgyU3pKZlFtVTFPRkp4TkhKTFdUaHFTRkJ2TlVSME0wOUVibXhQWDFaU1VXcHdaM1Z5TFZCVmF5SXNJQ0o1SWpvZ0lraHhhRFl5TjJsVmNsZzJWVlpSYm1KWVJVbzBWMlZSYlZWWE5pMDJORTFQVVd0UmNFWnNTa1pGTm5NaUxDQWlkWE5sSWpvZ0luTnBaeUo5IiwgImlhdCI6IDE3MzA4MzA3MzYsICJfc2RfYWxnIjogInNoYS0yNTYifQ.04hhAViHYBOWd-aqWseRgZC2I6S2EPumqmUvJqNOUpxKcPfACpbzWyEmoYkHgomTaxpW4xtRe7lxcCeZIFR7Eg~WyJ4ejQtVXA2NnNGV3BsWlprUzFVUkR3IiwgIm5lc3RlZF9hZ2FpbiIsICJ2YWwyIl0~WyI2MWtERGcwelVzR0Q5d3Zzcy1oRjRRIiwgImtleTEiLCAidmFsMSJd~WyJhTko5M1RqX3QtN25naHVpdV91S3dBIiwgIjEyIiwgdHJ1ZV0~WyJXVGFKM3VxcDBUM3k4OVQxdFliQ2FnIiwgIjE0IiwgdHJ1ZV0~WyJ1UjA0akUwWVpROHNlejdUcU9YQm1nIiwgIjE2IiwgdHJ1ZV0~WyJUMmdKWnJUS3dtUEJtUkMyUTJVZ2pnIiwgIjE4IiwgdHJ1ZV0~WyJfdFpIc2tzNUxpWUpxd1BuR3lySmNnIiwgIjIxIiwgdHJ1ZV0~WyJZY1k5N0dWUFYzN2g5WnBaU2oxdTNBIiwgIjY1IiwgZmFsc2Vd~WyJjSktsa3IzUzU5Rm8wMTBOS3BBdGxBIiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ~WyJJOUNVbWpkeFVVQ3E5a1NpejhuQWVnIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlcm1hbm4iXQ~"


NESTED_ATTRIB_PRES_DEF = {
    "id": "001d7604-85f2-4b89-b77b-366e9a68cc93",
    "purpose": "Present basic profile info",
    "format": {"vc+sd-jwt": {}},
    "input_descriptors": [
        {
            "id": "ID Card",
            "name": "Profile",
            "purpose": "Present basic profile info",
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {
                        "path": ["$.vct"],
                        "filter": {"type": "string"},
                    },
                    {
                        "path": ["$.family_name"],
                    },
                    {
                        "path": ["$.given_name"],
                    },
                    {
                        "path": ["$.something_nested.key1"],
                        "filter": {"type": "string"},
                    },
                    {
                        "path": ["$.something_nested.key2.nested_again"],
                        # "filter": {"type": "string"},
                    },
                ],
            },
        }
    ],
}

NESTED_ATTRIB_SUB = {
    "id": "vcGKEqRFXnT7_x8nDZ07B",
    "definition_id": "001d7604-85f2-4b89-b77b-366e9a68cc93",
    "descriptor_map": [{"id": "ID Card", "format": "vc+sd-jwt", "path": "$"}],
}


async def test_nested_attribute(profile: Profile):
    evaluator = PresentationExchangeEvaluator.compile(NESTED_ATTRIB_PRES_DEF)
    result = await evaluator.verify(profile, NESTED_ATTRIB_SUB, NESTED_ATRIB_VC)
    assert result.verified is True
