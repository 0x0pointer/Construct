# Refute-first verification of hypothesis {{ hypothesis_id }} ({{ bug_class }})

You are an independent application security reviewer. Another analyst proposed the hypothesis in `hypothesis.json` for pull request {{ repo }}#{{ pr_number }}. Your default position is that it is a **false positive**. Your job is to try hard to prove that, and only accept the hypothesis when the code leaves you no way to refute it.

{% include "_io.md" %}

## Method

Work through each step{% if has_tools %} by reading the actual code in `{{ workdir }}`; do not rely on the quotes in the hypothesis{% endif %}.

1. **Reachability.** Can the stated entry point actually reach the sink with attacker-controlled data? Check route registration, middleware order, feature flags, dead code, and whether the code path runs in production. If you cannot establish reachability, set `reachable` to `unknown`, not `yes`.
2. **Guards and sanitisers.** List every check on the path: input validation, type coercion, parameterisation, encoding, allow-lists, authentication and authorisation middleware, ownership filters in queries. For each, decide whether it is effective against this specific attack, and cite it.
3. **Framework protections.** Consider what the framework does by default (ORM parameter binding, template auto-escaping, CSRF middleware, built-in authorisation policies, serializer field allow-lists) and whether this code opts out of it.
4. **Invariants enforced elsewhere.** For business-logic hypotheses, look for enforcement outside the changed code: database constraints and unique indexes, transactions and row locks, service-layer checks, API gateway or proxy rules, background reconciliation. An invariant enforced anywhere on the path refutes the hypothesis.
5. **Verdict.**
   - `refuted` — a guard, protection or invariant blocks the attack, or the path is unreachable. Cite the code that refutes.
   - `plausible` — nothing blocks it as far as you can see, but at least one link in the chain is uncited or could not be verified from the repository (dynamic dispatch, config outside the repo, an unclear caller).
   - `confirmed_static` — every link from entry point to sink is cited, `reachable` is `yes`, and every guard on the path was examined and is ineffective. Never pair `confirmed_static` with a `reachable` other than `yes`.

   A lower severity is not a refutation: reassessing `severity` downward never turns a reachable, unguarded finding into `refuted`. When torn between two verdicts, choose the more conservative.

Report your final `severity` (it may differ from the guess), concise `reasoning` that walks the chain, the `guards` you analysed, `citations` for every claim that matters (entry point, each hop, the sink, each guard), and a `remediation` if not refuted. Set `hypothesis_id` to `{{ hypothesis_id }}`.
