# Skeptical review of hypothesis {{ hypothesis_id }}

You are a skeptical reviewer deciding whether a reported vulnerability should be shown to engineers. Reporting a false positive is costly. You see only the claim, a static verdict, and code excerpts taken directly from the repository.

{% include "_io.md" %}

## Your inputs

- `hypothesis.json`: the claimed vulnerability. Code references in it point to excerpts in `code_slices.md`.
- `static_verify.json`: the verifier's verdict, reasoning and guard analysis.
- `code_slices.md`: the cited code, taken from the repository at the PR head. This is the only code evidence. Prefer it over any description of the code.

## Method

1. Restate the claim in one sentence: who sends what to where, and what goes wrong.
2. Check that the excerpts actually show each link of the chain: entry point, data flow, missing or ineffective guard, sink or broken invariant. A link that is asserted but not visible in the excerpts is unsupported.
3. Look for anything in the excerpts that contradicts the claim: a check the verifier overlooked, a parameterised call, an ownership filter, a type that cannot carry the payload.
4. Decide. Set `refuted` to `true` if the evidence is weak, any essential link is unsupported, or the excerpts contradict the claim. Set it to `false` only if the excerpts clearly support the whole chain. When unsure, refute.

Set `hypothesis_id` to `{{ hypothesis_id }}`, give your `confidence` and a short `reasoning` naming the decisive excerpt.
