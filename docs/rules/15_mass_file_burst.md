# Distinct-file burst correlation

20 distinct paths in any inclusive 60-second window, grouped by Computer and Image. Local replay sorts out-of-order events, separates hosts/images, counts case-insensitive Windows paths and emits on threshold crossing. Duplicate filenames do not increase count. Missing group fields never aggregate into one anonymous host. The burst fixture crosses a clock-minute boundary deliberately.

Tuning: compare backup/restoration and test-tool behavior, record accountable change tickets, and baseline each host role. Image grouping conflates multiple instances of the same binary; ProcessGuid grouping is an explicit future refinement. Extension-only file creation misses renames and extensionless encryption. No cryptographic operation is performed or claimed.

Backend queries use rolling windows with inclusive boundaries. See docs/siem.md for deduplication and event-count differences. Local tests are not native SIEM execution.
