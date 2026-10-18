# Why JSON Schema validates empty agent output

An agent is asked to find five vulnerabilities in a contract. It returns five
findings. The JSON is valid: five objects, every required field present,
severities drawn from the allowed enum, no extra keys. `jsonschema.validate`
returns None — no exception, no error path. The pipeline marks the step green.

Read the five findings. They are identical.

The agent did no work and reported success in a perfectly valid format. This is
not an exotic failure mode. It is the most common one, because it is the only
failure mode that leaves no trace in the *shape* of the data.

## Form is not content

Schema validation answers exactly one question: is this shaped the way we
agreed? Types, required fields, enums, formats, nesting. Every one of those
checks is about the envelope. None of them is about the letter inside.

This is not a flaw in JSON Schema. The schema was never asked "does this mean
anything". We validated the artifact for what it *is* — a data structure — and
then quietly treated "valid" as "good". Those are different claims, and the gap
between them is where agents live.

## What empty actually looks like

Absent output is easy: there is nothing to validate, the response fails, the
error is loud. The interesting cases are all *presence without information* —
the artifact is fully formed and says nothing:

- five list items that are identical — "five findings" that are one finding
  copied five times;
- `"message": "TODO"` — the field exists because the schema said so, not
  because anyone filled it;
- `"recommendations": []` — a schema that allows an empty array reports
  success on an empty array;
- a required field carefully left at the exact default value from the schema;
- a summary that ends mid-sentence because the model hit the token cap and
  never mentioned it;
- a paragraph of 40 words where 9 are unique.

Every single one of these passes validation. Most of them pass review too, if
the reviewer is another LLM skimming for "does it look right".

## Seven measurable signals

The key move is to refuse unfalsifiable checks. "This response feels
meaningless" is not a test — there is no way to show it to someone else and
argue with the result. But "this required field consists entirely of the word
`example`" is a fact about the bytes.

So we measure emptiness where it is measurable — seven signals, each one
inspectable and disputable:

1. **Identical list items (`uniform_list`).** If more than half of a list is
   identical (≥90% is treated as severe), the list is a placeholder for a list.
   A single duplicate can be honest; a majority of duplicates is absence of
   work.
2. **Placeholder values (`stub_value`).** `TODO`, `TBD`, `placeholder`,
   `example`, `test`, `lorem ipsum`, `n/a` — including CJK equivalents. High
   severity when the whole field is a stub, low when a stub word appears inside
   real text.
3. **Blank and empty containers (`blank_string`, `empty_list`,
   `empty_object`).** Whitespace-only strings and `[]`/`{}` satisfy a schema.
   They satisfy nothing else.
4. **Truncation markers (`truncation`).** Output ending in `...`, `[truncated]`,
   `continued` — the model was cut off and does not say so.
5. **Low-variety repetition (`repetitive_text`).** For texts of 12+ words: if
   fewer than ~a third of the words are unique, it is filler.
6. **Schema defaults left in place (`schema_default`).** A *required* field
   holding exactly the schema's own `default` means nobody filled it.
7. **Enum fields stuck on the first value (`enum_first_value`).** A categorical
   field that is always the first enum option is a guess dressed as a decision.

None of these check meaning. They check the mechanical fingerprints of
absence — and because each fingerprint is a measurement, each one can be shown
to a reviewer: here is the field, here is the value, here is why it fired.

## Verdicts, not vibes

The signals roll up into three verdicts:

- **`CONTENT_PRESENT`** — nothing above fired.
- **`THIN_CONTENT`** — some medium signals; worth a look.
- **`VALID_BUT_EMPTY`** — the form is fine, the content is suspect.

The third name is deliberate. It means "the form is fine, the content is
suspect" — **not** "the content is absent". Suspicion requires a person; a
verdict requires proof. The tool shows both and pretends neither.

And one honest limit, stated in the README because it matters: absence of
signals does **not** prove meaningfulness. It only means the coarse checks did
not fire. A response can be vague, circular and useless in seven ways we did
not think to measure. Passing is a statement about the checks, not a
certificate about the content.

## Where this belongs in a pipeline

The place for this check is the boundary where an agent's output stops being
"a reply" and starts being "a result" — before it is paid for, forwarded,
merged, or shown to a customer as work done.

Two properties matter there. First, it must run *before* the consequence —
detecting five identical findings after the refund was processed is an
incident report, not a guard. Second, the verdict must be evidence-shaped: if
you are going to reject an agent's output, you owe it a specific, disputable
reason — `uniform_list: 5 of 5 items are identical` — not a vibe.

You cannot retry what you cannot detect. An empty artifact passing validation
is a false green, and false greens are the one failure mode that survives
every dashboard.

---

If you want to see it run: [attest](https://attest.rta.lat/demo) checks an
artifact in four layers — form and emptiness (this post), prompt-injection
shapes, provenance signatures, and entitlement — before anything downstream
trusts it. Code is open, the demo is a single form, and the emptiness layer is
forty-something tests of exactly the signals above.
