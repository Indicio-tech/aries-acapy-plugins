import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from bitarray import bitarray
import zlib
import base64

from .. import status_handler
from ..models import StatusListDef, StatusListShard
from acapy_agent.config.settings import Settings

@pytest.mark.asyncio
async def test_get_status_list_ietf_endianness():
    # Setup
    context = MagicMock()
    context.profile.settings = Settings({
        "plugin_config": {
            "status_list": {
                "public_uri": "http://localhost:8000",
                "list_size": 1000,
                "shard_size": 100,
                "file_path": "./status_list_files"
            }
        }
    })
    context.profile.session.return_value.__aenter__.return_value = MagicMock()
    context.metadata = {"wallet_id": "test-wallet"}
    
    definition = MagicMock(spec=StatusListDef)
    definition.id = "def-id"
    definition.list_type = "ietf"
    definition.shard_size = 8
    definition.issuer_did = "did:example:123"
    definition.status_size = 1
    
    # Create a shard with a known bit pattern
    # 00000001 (index 7 is set)
    shard_bits = bitarray('00000001')
    shard = MagicMock(spec=StatusListShard)
    shard.shard_number = "0"
    shard.status_bits = shard_bits
    
    # Mock StatusListShard.query
    # Note: We patch where it is used, or the class itself if it's a class method
    with patch("status_list.v1_0.status_handler.StatusListShard.query", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = [shard]
        
        # Call get_status_list
        result = await status_handler.get_status_list(context, definition, "1")
        
        # Result should be a dict with "status_list" -> "lst" (encoded)
        assert "status_list" in result
        assert "lst" in result["status_list"]
        
        encoded_list = result["status_list"]["lst"]
        
        # Decode and verify
        # Add padding if needed
        missing_padding = len(encoded_list) % 4
        if missing_padding:
            encoded_list += '=' * (4 - missing_padding)
            
        compressed_bytes = base64.urlsafe_b64decode(encoded_list)
        bit_bytes = zlib.decompress(compressed_bytes)
        
        ba = bitarray()
        ba.frombytes(bit_bytes)
        
        # Verify the bit at index 7 is 1
        assert ba[7] == 1
        # Verify the bit at index 0 is 0
        assert ba[0] == 0
