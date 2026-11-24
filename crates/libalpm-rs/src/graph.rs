//! Port of lib/libalpm/graph.c: vertices of the dependency graph used by `_alpm_sortbydeps`.
//! Vertices live in a `Vec` and refer to each other by index (upstream uses pointers).

/// enum _alpm_graph_vertex_state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphState {
    Unprocessed,
    Processing,
    Processed,
}

/// alpm_graph_t
#[derive(Debug)]
pub struct Graph<T> {
    pub data: T,
    /// where did we come from?
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// used for DFS without recursion: position in `children`
    pub iterator: usize,
    pub state: GraphState,
}

impl<T> Graph<T> {
    /// _alpm_graph_new (+ data)
    pub fn new(data: T) -> Graph<T> {
        Graph {
            data,
            parent: None,
            children: Vec::new(),
            iterator: 0,
            state: GraphState::Unprocessed,
        }
    }
}
