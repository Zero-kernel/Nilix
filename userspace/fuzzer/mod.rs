// Phase 4: Coverage-guided fuzzer modules
// Phase 5: Resource-aware fuzzing modules
// Phase 6: Stateful fuzzing modules
// Phase 7: CI integration & continuous fuzzing modules

pub mod corpus;
pub mod mutator;
pub mod executor;
pub mod seeds;
pub mod resources;
pub mod constraints;
pub mod generator;
pub mod resource_mutator;
pub mod leak_detector;
pub mod transactions;
pub mod state_machine;
pub mod stateful_coverage;
pub mod ipc_coordinator;
pub mod minimizer;
pub mod continuous;
pub mod crash_triage;
pub mod corpus_sync;
pub mod dashboard;
