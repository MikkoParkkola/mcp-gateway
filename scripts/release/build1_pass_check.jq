# BUILD.1 PASS check: the client's stream-json output shows a successful gateway_list_servers call.
# Run: jq -s -e -f scripts/release/build1_pass_check.jq client.jsonl
# Event shape follows the Claude Code stream-json docs; confirmed by MIK-8602.VERIFY.7.
try (
  . as $events
  # R1: tool_use ids for gateway_list_servers on assistant events (need at least one).
  | ([ $events[]?
       | select((.type? // null) == "assistant")
       | (.message?.content? // empty) | .[]?
       | select((.type? // null) == "tool_use")
       | select((.name? // null) == "mcp__gw4__gateway_list_servers")
       | select((((.id? // null) | type)) == "string")
       | .id
     ]) as $ids
  # R2: tool_result blocks on user events answering one of those ids (need at least one).
  | ([ $events[]?
       | select((.type? // null) == "user")
       | (.message?.content? // empty) | .[]?
       | select((.type? // null) == "tool_result")
       | select((.tool_use_id? // null) as $t | ($ids | index($t) != null))
     ]) as $matched
  | ((($ids | length) >= 1)
     and (($matched | length) >= 1)
     # R3: every matched result has is_error absent or false.
     and (([$matched[] | select((.is_error // false) == false)] | length) == ($matched | length))
     # R4: every matched result carries non-empty text.
     and (([$matched[]
             | select((.content? // null) as $c
                      | if ($c | type) == "string" then ($c | length) > 0
                        elif ($c | type) == "array" then (([$c[]?
                                                           | select((.type? // null) == "text")
                                                           | select((((.text? // null) | type)) == "string")
                                                           | select((.text | length) > 0)
                                                          ] | length) >= 1)
                        else false end)]
            | length) == ($matched | length))
     # R5: the last event is a result with is_error strictly false.
     and ((($events | length) >= 1)
          and (($events[-1] | (.type? // null)) == "result")
          and (($events[-1] | [.is_error?] | .[0]) == false)))
) catch false
