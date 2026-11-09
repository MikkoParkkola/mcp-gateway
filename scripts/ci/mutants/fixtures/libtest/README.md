# libtest output fixtures

Shared by every parser of libtest's `test NAME ... RESULT` records: the
mutant runner's self-test (`run_mutants.py --self-test`) and the spark-cargo
replay harness. A line written straight to stderr while a test runs (a
warning, a forwarded measurement) can land between `test NAME ... ` and its
result in a merged stream; each parser must still read one record per test.

| file | source | the record it must yield |
|---|---|---|
| midline-stderr.txt | real: mutants run 42515472734, baseline-13.log (header line dropped) | the h12 health-start row, ok |
| alloc-meter-one-thread.txt | libtest's one-thread format with forwarded measurement lines | the INTAKE.2(a) row, ok |
| failed-after-noise.txt | libtest's format, a stderr line glued after the prefix | m::row_that_fails, FAILED, panicked at src/x.rs:9 |
| panic-in-passing-test.txt | libtest's --nocapture format, a caught panic | m::passes_after_a_caught_panic, ok |
| zero-match.txt | libtest's format, a filter that matched nothing | no record |
| stray-ok-before-failed.txt | libtest's format, a stderr line that is `ok` alone before the real FAILED | must not read as a pass |
| stray-failed-before-ok.txt | libtest's format, a stderr `FAILED` line and a caught panic at the spec line before the real ok | must not read as a kill |
