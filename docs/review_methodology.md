# Review methodology

## Chapter deep-dive policy

The tool uses a bounded, evidence-preserving review flow:

1. The first review pass produces the document summary, chapter overviews, and
   the main issue list.
2. A chapter deep dive is treated as a recorded inspection pass, not as an
   unbounded retry button.
3. The first deep-dive pass evaluates the selected chapter against the
   applicable checklist and records concrete issues.
4. A second pass is allowed only to search for residual issues that were not
   already found. Existing issues are passed back into the prompt so the model
   is instructed not to repeat them.
5. After two passes, the UI stops further LLM calls and recommends acting on
   the recorded findings. This avoids nondeterministic repeated reviews and
   keeps token cost bounded.

This policy follows three principles from established review practice:

- Systematic reviews should have a defined procedure and documented results.
- Inspection findings should be tracked as anomaly/action-item records rather
  than rediscovered repeatedly.
- Different review passes should add coverage by changing perspective or
  objective, not by asking the same question again.

