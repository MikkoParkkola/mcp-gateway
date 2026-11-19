The three `.txt` files are copied byte for byte from the supplied fixture-data
directory. `running-line.txt` retains its provenance header: probe run
44240619213, coverage-linux/report-lcov.log, cargo-llvm-cov 0.9.1.

`F-p1.txt` and `F-p4.txt` are the supplied extracts of that run's part 1 and
part 4 lcov exports for src/events/backend_source.rs, upstream_starts and its
closure, lines 317–323. The supplied extracts have no comment headers; their
original SF, FN, FNDA and DA records are preserved here without alteration.

The test relocates those records to src/gateway/server/backend_source.rs so
startup grading measures the lost counts. Structural hashes and object paths
are synthetic: only part 4's hash has a profile record. All other path prefixes
receive fully covered synthetic files. No Rust compilation or LLVM is needed.
