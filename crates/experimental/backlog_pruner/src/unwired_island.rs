//! # Unwired Island Detector
//!
//! Detects pull requests that introduce new functions which are never called
//! by any existing code — dead-on-arrival logic with `in_degree == 0`.
//!
//! ## Algorithm
//! 1. Ingest the master branch call graph as a directed `petgraph::graph::DiGraph`.
//! 2. For each new function name introduced by the PR, compute its `in_degree`
//!    (number of master-branch callers) via `neighbors_directed(Incoming)`.
//! 3. If **every** newly added function has `in_degree == 0` and none of them
//!    override a known lifecycle method, the PR is `UNWIRED_ISLAND`.
//!
//! ## Lifecycle Override Exemption
//! Functions that override lifecycle hooks (e.g., `_ready`, `on_event`,
//! `setUp`, `tearDown`) are exempt from the unwired-island flag even when
//! `in_degree == 0`, because they are invoked by the runtime framework rather
//! than by application code.
//!
//! ## Graph Representation
//! The master call graph is stored as a `petgraph::graph::DiGraph<String, ()>`.
//! `DiGraph` was selected over `petgraph::csr::Csr` because CSR's compressed
//! row format only efficiently models outgoing edges; computing incoming
//! `in_degree` over a large CSR requires an O(E) full-edge scan.  `DiGraph`
//! provides O(in_degree) incoming-neighbour iteration out of the box.

use petgraph::graph::DiGraph;
use petgraph::Direction;
use std::collections::HashMap;

/// Known lifecycle / framework hook names exempt from the unwired-island flag.
///
/// A new function whose simple (unqualified) name matches any entry here will
/// not be flagged as unwired even when no existing code calls it directly.
const LIFECYCLE_EXEMPTIONS: &[&str] = &[
    // Godot / game engine
    "_ready",
    "_process",
    "_physics_process",
    "_input",
    "_notification",
    // Python test frameworks
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
    // Rust / C entry-point
    "main",
    // General init / cleanup
    "init",
    "initialize",
    "setup",
    "cleanup",
    "destroy",
    "dispose",
    // Web / event frameworks
    "on_event",
    "handle",
    "middleware",
    "dispatch",
];

/// Returns `true` if `name` matches a known lifecycle / framework hook.
fn is_lifecycle(name: &str) -> bool {
    LIFECYCLE_EXEMPTIONS.contains(&name)
}

/// A directed call graph built from the master branch's symbol index.
///
/// Edges represent calls: an edge from node A → B means function A calls B.
/// The graph is used to compute `in_degree` — the number of master-branch
/// functions that call a given function name.
pub struct MasterCallGraph {
    graph: DiGraph<String, ()>,
    /// Maps qualified function name → `NodeIndex` for O(1) lookup.
    name_to_node: HashMap<String, petgraph::graph::NodeIndex>,
}

impl MasterCallGraph {
    /// Build a `MasterCallGraph` from an edge list.
    ///
    /// `edges` is a slice of `(caller, callee)` qualified name pairs.
    /// Nodes are created on first reference; duplicate edges are deduplicated.
    pub fn new(edges: &[(String, String)]) -> Self {
        let mut graph: DiGraph<String, ()> = DiGraph::new();
        let mut name_to_node: HashMap<String, petgraph::graph::NodeIndex> = HashMap::new();

        let get_or_insert = |g: &mut DiGraph<String, ()>,
                             map: &mut HashMap<String, petgraph::graph::NodeIndex>,
                             name: &str|
         -> petgraph::graph::NodeIndex {
            if let Some(&idx) = map.get(name) {
                idx
            } else {
                let idx = g.add_node(name.to_owned());
                map.insert(name.to_owned(), idx);
                idx
            }
        };

        for (caller, callee) in edges {
            let a = get_or_insert(&mut graph, &mut name_to_node, caller);
            let b = get_or_insert(&mut graph, &mut name_to_node, callee);
            graph.add_edge(a, b, ());
        }

        Self {
            graph,
            name_to_node,
        }
    }

    /// Returns the `in_degree` of the function named `name`.
    ///
    /// `in_degree` is the number of master-branch functions that call `name`.
    /// Returns `0` if the function does not appear in the call graph.
    pub fn in_degree(&self, name: &str) -> usize {
        match self.name_to_node.get(name) {
            Some(&idx) => self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count(),
            None => 0,
        }
    }
}

/// Returns `true` if the PR introduces only unwired, unreachable functions.
///
/// A PR is `UNWIRED_ISLAND` when every newly added function satisfies both:
/// - `in_degree == 0` in the master call graph (no existing caller), AND
/// - its simple (unqualified) name does not match a known lifecycle hook.
///
/// Returns `false` when `new_functions` is empty (no new functions → no island).
///
/// # Parameters
/// - `new_functions`: Qualified names of functions introduced by the PR.
/// - `master_graph`: The current master-branch call graph.
pub fn is_unwired_island(new_functions: &[String], master_graph: &MasterCallGraph) -> bool {
    if new_functions.is_empty() {
        return false;
    }

    new_functions.iter().all(|name| {
        let deg = master_graph.in_degree(name);
        // Extract the simple name (last `::` segment) for lifecycle matching.
        let simple = name.rsplit("::").next().unwrap_or(name.as_str());
        deg == 0 && !is_lifecycle(simple)
    })
}
