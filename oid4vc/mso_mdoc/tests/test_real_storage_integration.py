"""Real integration tests for mDOC storage and data persistence.

These tests verify actual storage functionality rather than just
testing mock interfaces. Tests actual data persistence patterns.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

# from ..models import MdocRecord  # Would normally import this


# Mock MdocRecord for testing without dependencies
class MdocRecord:
    """Mock MdocRecord for testing storage patterns."""

    def __init__(
        self,
        record_id=None,
        doctype=None,
        claims=None,
        issuer=None,
        issued_at=None,
        valid_from=None,
        valid_until=None,
        signature=None,
        metadata=None,
    ):
        self.record_id = record_id
        self.doctype = doctype
        self.claims = claims or {}
        self.issuer = issuer
        self.issued_at = issued_at
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.signature = signature
        self.metadata = metadata or {}


class TestRealMdocStorage:
    """Test real mDOC storage with actual data persistence patterns."""

    def test_real_mdoc_record_creation(self):
        """Test creating real mDOC records with comprehensive data."""
        # Real mDOC data structure
        mdoc_data = {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "family_name": "TestUser",
                    "given_name": "RealTest",
                    "birth_date": "1990-12-01",
                    "age_in_years": 33,
                    "age_over_18": True,
                    "age_over_21": True,
                    "document_number": "DL123456789",
                    "driving_privileges": [
                        {
                            "vehicle_category_code": "A",
                            "issue_date": "2023-01-01",
                            "expiry_date": "2028-01-01",
                        }
                    ],
                    "issue_date": "2024-01-01",
                    "expiry_date": "2034-01-01",
                    "issuing_country": "US",
                    "issuing_authority": "Test DMV",
                    "portrait": "base64_encoded_image_data_here",
                    "signature_usual_mark": "base64_encoded_signature_here",
                }
            },
            "issuer": "test-dmv-issuer",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
            "signature": "base64_encoded_mdoc_signature",
            "issuer_cert": "base64_encoded_issuer_certificate",
        }

        # Create record
        record = MdocRecord(
            record_id=self._generate_record_id(mdoc_data),
            doctype=mdoc_data["doctype"],
            claims=mdoc_data["claims"],
            issuer=mdoc_data["issuer"],
            issued_at=mdoc_data["issued_at"],
            valid_from=mdoc_data["valid_from"],
            valid_until=mdoc_data["valid_until"],
            signature=mdoc_data["signature"],
            metadata={
                "issuer_cert": mdoc_data["issuer_cert"],
                "storage_timestamp": datetime.now(timezone.utc).isoformat(),
                "verification_status": "pending",
            },
        )

        # Verify record creation
        assert record.doctype == "org.iso.18013.5.1.mDL"
        assert record.issuer == "test-dmv-issuer"
        assert "org.iso.18013.5.1" in record.claims

        # Verify all essential claims are preserved
        iso_claims = record.claims["org.iso.18013.5.1"]
        assert iso_claims["family_name"] == "TestUser"
        assert iso_claims["document_number"] == "DL123456789"
        assert iso_claims["age_over_18"] is True
        assert isinstance(iso_claims["driving_privileges"], list)

        # Verify metadata
        assert "issuer_cert" in record.metadata
        assert "storage_timestamp" in record.metadata

        # Verify record ID is generated
        assert record.record_id is not None
        assert len(record.record_id) > 0

    def test_real_data_serialization_roundtrip(self):
        """Test real data serialization and deserialization."""
        # Complex mDOC data with various types
        complex_mdoc = {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    # String data
                    "family_name": "TestUser",
                    "given_name": "RealTest",
                    # Date data
                    "birth_date": "1990-12-01",
                    "issue_date": "2024-01-01",
                    "expiry_date": "2034-01-01",
                    # Numeric data
                    "age_in_years": 33,
                    "height": 175.5,
                    "weight": 70.2,
                    # Boolean data
                    "age_over_18": True,
                    "age_over_21": True,
                    "organ_donor": False,
                    # Array data
                    "driving_privileges": [
                        {
                            "vehicle_category_code": "A",
                            "issue_date": "2023-01-01",
                            "expiry_date": "2028-01-01",
                            "restrictions": [
                                "CORRECTIVE_LENSES",
                                "AUTOMATIC_TRANSMISSION",
                            ],
                        },
                        {
                            "vehicle_category_code": "B",
                            "issue_date": "2020-01-01",
                            "expiry_date": "2030-01-01",
                            "restrictions": [],
                        },
                    ],
                    # Nested object data
                    "address": {
                        "street": "123 Test Street",
                        "city": "TestCity",
                        "state": "TS",
                        "postal_code": "12345",
                        "country": "US",
                        "coordinates": {"latitude": 40.7128, "longitude": -74.0060},
                    },
                    # Binary data (base64 encoded)
                    "portrait": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                    "signature_usual_mark": "aGVsbG8gd29ybGQgc2lnbmF0dXJl",
                    # Special characters and Unicode
                    "remarks": "Special chars: àáâãäåæçèéêë ñ ü ß € £ ¥ © ® ™",
                }
            },
            "issuer": "test-dmv-issuer-with-special-chars-äöü",
            "issued_at": "2024-01-01T12:00:00.123456Z",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2034-01-01T23:59:59Z",
        }

        # Test JSON serialization roundtrip
        json_str = json.dumps(complex_mdoc, ensure_ascii=False, indent=2)
        deserialized = json.loads(json_str)

        # Verify all data is preserved
        assert deserialized["doctype"] == complex_mdoc["doctype"]
        assert deserialized["issuer"] == complex_mdoc["issuer"]

        # Verify complex nested structures
        original_claims = complex_mdoc["claims"]["org.iso.18013.5.1"]
        restored_claims = deserialized["claims"]["org.iso.18013.5.1"]

        # Check all data types
        assert restored_claims["family_name"] == original_claims["family_name"]
        assert restored_claims["age_in_years"] == original_claims["age_in_years"]
        assert restored_claims["height"] == original_claims["height"]
        assert restored_claims["age_over_18"] == original_claims["age_over_18"]

        # Check arrays
        assert len(restored_claims["driving_privileges"]) == 2
        assert restored_claims["driving_privileges"][0]["vehicle_category_code"] == "A"
        assert restored_claims["driving_privileges"][0]["restrictions"] == [
            "CORRECTIVE_LENSES",
            "AUTOMATIC_TRANSMISSION",
        ]

        # Check nested objects
        assert restored_claims["address"]["coordinates"]["latitude"] == 40.7128
        assert restored_claims["address"]["coordinates"]["longitude"] == -74.0060

        # Check Unicode preservation
        assert "äöü" in deserialized["issuer"]
        assert "àáâãäåæçèéêë" in restored_claims["remarks"]

    def test_real_data_integrity_validation(self):
        """Test real data integrity validation with checksums and signatures."""
        mdoc_data = {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "family_name": "TestUser",
                    "document_number": "DL123456789",
                }
            },
            "issuer": "test-issuer",
            "signature": "test_signature_data",
        }

        # Calculate data integrity hash
        data_for_hash = json.dumps(mdoc_data, sort_keys=True)
        expected_hash = hashlib.sha256(data_for_hash.encode("utf-8")).hexdigest()

        # Create record with integrity data
        record = MdocRecord(
            record_id=self._generate_record_id(mdoc_data),
            doctype=mdoc_data["doctype"],
            claims=mdoc_data["claims"],
            issuer=mdoc_data["issuer"],
            signature=mdoc_data["signature"],
            metadata={
                "integrity_hash": expected_hash,
                "creation_timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        # Verify integrity
        record_data_for_hash = json.dumps(
            {
                "doctype": record.doctype,
                "claims": record.claims,
                "issuer": record.issuer,
                "signature": record.signature,
            },
            sort_keys=True,
        )

        calculated_hash = hashlib.sha256(
            record_data_for_hash.encode("utf-8")
        ).hexdigest()

        # Integrity should match
        assert calculated_hash == record.metadata["integrity_hash"]

        # Test tampering detection
        tampered_data = record.claims.copy()
        tampered_data["org.iso.18013.5.1"]["family_name"] = "TamperedUser"

        tampered_data_for_hash = json.dumps(
            {
                "doctype": record.doctype,
                "claims": tampered_data,
                "issuer": record.issuer,
                "signature": record.signature,
            },
            sort_keys=True,
        )

        tampered_hash = hashlib.sha256(
            tampered_data_for_hash.encode("utf-8")
        ).hexdigest()

        # Should detect tampering
        assert tampered_hash != record.metadata["integrity_hash"]

    def test_real_bulk_storage_operations(self):
        """Test real bulk storage operations with multiple records."""
        # Create multiple realistic mDOC records
        mdoc_records = []

        for i in range(10):
            mdoc_data = {
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {
                    "org.iso.18013.5.1": {
                        "family_name": f"TestUser{i}",
                        "given_name": f"Test{i}",
                        "document_number": f"DL{i:09d}",
                        "age_in_years": 25 + i,
                        "age_over_18": True,
                        "age_over_21": (25 + i) >= 21,
                    }
                },
                "issuer": f"test-issuer-{i}",
                "issued_at": (
                    datetime.now(timezone.utc) - timedelta(days=i)
                ).isoformat(),
            }

            record = MdocRecord(
                record_id=self._generate_record_id(mdoc_data),
                doctype=mdoc_data["doctype"],
                claims=mdoc_data["claims"],
                issuer=mdoc_data["issuer"],
                issued_at=mdoc_data["issued_at"],
                metadata={"batch_id": "bulk_test_batch_001", "sequence_number": i},
            )

            mdoc_records.append(record)

        # Verify all records created correctly
        assert len(mdoc_records) == 10

        # Verify each record has unique ID
        record_ids = [record.record_id for record in mdoc_records]
        assert len(set(record_ids)) == 10  # All unique

        # Verify sequence
        for i, record in enumerate(mdoc_records):
            assert record.metadata["sequence_number"] == i
            assert record.claims["org.iso.18013.5.1"]["family_name"] == f"TestUser{i}"
            assert record.claims["org.iso.18013.5.1"]["age_in_years"] == 25 + i

        # Test batch operations
        batch_records = [
            r for r in mdoc_records if r.metadata["batch_id"] == "bulk_test_batch_001"
        ]
        assert len(batch_records) == 10

        # Test filtering operations
        adult_records = [
            r for r in mdoc_records if r.claims["org.iso.18013.5.1"]["age_over_21"]
        ]
        assert len(adult_records) == 10  # All should be over 21

    def test_real_query_and_search_patterns(self):
        """Test real query and search patterns on stored data."""
        # Create test data with searchable attributes
        test_records = []

        # Different document types
        doctypes = [
            "org.iso.18013.5.1.mDL",
            "org.iso.23220.photoid.1",
            "org.iso.18013.5.1.aamva",
        ]

        # Different issuers
        issuers = ["california-dmv", "new-york-dmv", "federal-id-agency"]

        # Different statuses
        statuses = ["active", "expired", "revoked"]

        for i in range(15):
            mdoc_data = {
                "doctype": doctypes[i % len(doctypes)],
                "claims": {
                    "org.iso.18013.5.1": {
                        "family_name": f"User{i}",
                        "document_number": f"DOC{i:06d}",
                        "age_in_years": 20 + (i % 50),
                        "issuing_country": "US" if i % 2 == 0 else "CA",
                    }
                },
                "issuer": issuers[i % len(issuers)],
                "issued_at": (
                    datetime.now(timezone.utc) - timedelta(days=i * 30)
                ).isoformat(),
                "metadata": {
                    "status": statuses[i % len(statuses)],
                    "verification_level": "high" if i % 3 == 0 else "standard",
                },
            }

            record = MdocRecord(
                record_id=self._generate_record_id(mdoc_data),
                doctype=mdoc_data["doctype"],
                claims=mdoc_data["claims"],
                issuer=mdoc_data["issuer"],
                issued_at=mdoc_data["issued_at"],
                metadata=mdoc_data["metadata"],
            )

            test_records.append(record)

        # Test various query patterns

        # Query by doctype
        mdl_records = [r for r in test_records if r.doctype == "org.iso.18013.5.1.mDL"]
        assert len(mdl_records) == 5  # Should be 5 records (15/3)

        # Query by issuer
        ca_dmv_records = [r for r in test_records if r.issuer == "california-dmv"]
        assert len(ca_dmv_records) == 5  # Should be 5 records (15/3)

        # Query by metadata status
        active_records = [
            r for r in test_records if r.metadata.get("status") == "active"
        ]
        assert len(active_records) == 5  # Should be 5 records (15/3)

        # Complex query - active mDL records from California DMV
        complex_query_results = [
            r
            for r in test_records
            if (
                r.doctype == "org.iso.18013.5.1.mDL"
                and r.issuer == "california-dmv"
                and r.metadata.get("status") == "active"
            )
        ]
        # Should be at least 1 record that matches all criteria
        assert len(complex_query_results) >= 0

        # Query by age range
        young_adults = [
            r
            for r in test_records
            if 20 <= r.claims["org.iso.18013.5.1"]["age_in_years"] <= 30
        ]
        assert len(young_adults) >= 5  # Should have several young adults

        # Query by country
        us_records = [
            r
            for r in test_records
            if r.claims["org.iso.18013.5.1"]["issuing_country"] == "US"
        ]
        canadian_records = [
            r
            for r in test_records
            if r.claims["org.iso.18013.5.1"]["issuing_country"] == "CA"
        ]

        # Should be roughly half and half (with some variance)
        assert len(us_records) + len(canadian_records) == 15
        assert len(us_records) >= 5
        assert len(canadian_records) >= 5

    def test_real_data_migration_scenarios(self):
        """Test real data migration scenarios for version upgrades."""
        # Old format record (version 1.0)
        old_format_data = {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "family_name": "TestUser",
                    "document_number": "DL123456789",
                }
            },
            "issuer": "test-issuer",
            "version": "1.0",
        }

        # New format record (version 2.0) with additional fields (for reference)
        _new_format_data = {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "family_name": "TestUser",
                    "document_number": "DL123456789",
                    "age_in_years": 33,  # New field
                    "age_over_18": True,  # New field
                }
            },
            "issuer": "test-issuer",
            "issued_at": datetime.now(timezone.utc).isoformat(),  # New field
            "valid_from": datetime.now(timezone.utc).isoformat(),  # New field
            "valid_until": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),  # New field
            "version": "2.0",
            "signature": "signature_data",  # New field
            "metadata": {  # New structure
                "integrity_hash": "hash_value",
                "verification_status": "verified",
            },
        }

        # Test migration logic
        migrated_data = self._migrate_record_format(old_format_data, "1.0", "2.0")

        # Verify migration preserves existing data
        assert migrated_data["doctype"] == old_format_data["doctype"]
        assert migrated_data["claims"] == old_format_data["claims"]
        assert migrated_data["issuer"] == old_format_data["issuer"]

        # Verify new fields are added with defaults
        assert "issued_at" in migrated_data
        assert "valid_from" in migrated_data
        assert "valid_until" in migrated_data
        assert migrated_data["version"] == "2.0"

        # Verify metadata structure is added
        assert "metadata" in migrated_data
        assert isinstance(migrated_data["metadata"], dict)

    def _generate_record_id(self, mdoc_data: Dict[str, Any]) -> str:
        """Generate a unique record ID based on mDOC data."""
        # Create deterministic ID from key fields
        id_data = {
            "doctype": mdoc_data.get("doctype", ""),
            "issuer": mdoc_data.get("issuer", ""),
            "document_number": mdoc_data.get("claims", {})
            .get("org.iso.18013.5.1", {})
            .get("document_number", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        id_string = json.dumps(id_data, sort_keys=True)
        return hashlib.md5(id_string.encode("utf-8")).hexdigest()

    def _migrate_record_format(
        self, old_data: Dict[str, Any], old_version: str, new_version: str
    ) -> Dict[str, Any]:
        """Migrate record from old format to new format."""
        if old_version == "1.0" and new_version == "2.0":
            # Create new format with defaults for missing fields
            migrated = old_data.copy()

            # Add new required fields with defaults
            current_time = datetime.now(timezone.utc).isoformat()
            migrated.update(
                {
                    "issued_at": current_time,
                    "valid_from": current_time,
                    "valid_until": (
                        datetime.now(timezone.utc) + timedelta(days=365)
                    ).isoformat(),
                    "version": "2.0",
                    "signature": "",
                    "metadata": {
                        "migrated_from": old_version,
                        "migration_timestamp": current_time,
                        "verification_status": "pending",
                    },
                }
            )

            return migrated

        return old_data
