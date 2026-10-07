- **A bridged prompt's relay receipt commits when the prompt is written, not queued.** A prompt
  queued on a session stream could still be withheld by the stream's audit gate or dropped by a
  lagging subscriber, yet its receipt was already recorded, exempting that caller for text it never
  received. The receipt now commits once, when a stream writes the prompt. (MIK-7939)
