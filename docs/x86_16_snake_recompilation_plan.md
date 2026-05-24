# x86-16 Snake Recompilation Plan

This plan has been retired.

Snake-specific rescue logic and source-specific cleanup hooks were removed from
the decompiler codebase. Any remaining x86-16 recompilation work should now be
tracked under the generic corpus and COD plans:

- `angr_platforms/docs/dream_decompiler_execution_plan.md`
- `angr_platforms/docs/x86_16_cod_corpus_completion_plan.md`
- `angr_platforms/docs/x86_16_martypc_improvement_plan.md`

Keep snake-specific behavior out of the decompiler pipeline unless a future
regression is proven to be general enough to live in the shared x86-16
architecture.
