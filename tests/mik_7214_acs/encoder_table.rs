// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7915 (HEADER.4a): the encoder produces the specification table byte for
//! byte. The decoder row checks the other direction; a round-trip alone would
//! pass an encoder that wrapped values the specification leaves plain.

use super::SPEC_ENCODING_TABLE;
use mcp_gateway::protocol::headers::encode_header_value;

#[test]
fn ac_header_4a_the_encoder_produces_the_specifications_table() {
    for (original, header_value) in SPEC_ENCODING_TABLE {
        assert_eq!(
            encode_header_value(original),
            *header_value,
            "encoding {original:?} must give the specification's value"
        );
    }
}
