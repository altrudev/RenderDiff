# Model-facing assurance

RenderDiff never assumes that a tokenizer is a model. Exact token IDs, exact model-input payloads, and observed model responses are separate evidence channels. The caller must identify the tokenizer/encoding and model/version. A lexical token count is not a model token count.

Use `compare_model_views` with an installed tokenizer, `openai_compatible_observer` with an explicitly authorized endpoint, and `compare_model_behaviour` for paired source/projection probes. The model probe sends no tools and follows no redirects; it does not discover credentials or automatically send evidence to a provider. A host must additionally restrict egress destinations and enforce consent, retention, and data-classification policy.

A trusted semantic observer receives both representations, not a preselected malicious verdict. It must return bounded evidence spans. Its conclusions remain advisory and may be wrong. A model cannot grant itself authority or certify the absence of prompt injection. Behavioral comparisons should record model version, configuration, prompt template, seed where supported, and repeated-run variability. Exact response equality is not proof of semantic equivalence.
