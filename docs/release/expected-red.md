# Expected-red register

Targets deliberately red under §P2 (test written before implementation).
R14's trigger reads this file: strict CI is "green enough" when every red
here is listed, and MRTR.7a/7b are MET. Every entry owes a green; the register
must be empty at RC.

| target | criterion | kind | introduced | owner |
| --- | --- | --- | --- | --- |
| `mik_7215_control4_reap_count_acs` | CONTROL.4 T3 | compile-red | `09735d32` | control4-lifecycle |
