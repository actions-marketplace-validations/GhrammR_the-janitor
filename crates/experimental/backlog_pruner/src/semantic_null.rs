//! # Semantic Null Detector
//!
//! Determines whether a pull request changes execution logic or only cosmetic
//! tokens (identifiers, string literals, comments).
//!
//! ## Algorithm
//! 1. Walk the tree-sitter AST for both the base and PR branches.
//! 2. Collect only *structural* node kinds — control flow, expressions,
//!    statements — stripping `identifier`, `string_literal`, `comment`, and
//!    all whitespace nodes.
//! 3. Stream the structural node kind strings into a BLAKE3 hasher.
//!    No intermediate `Vec` allocation — pure streaming cursor.
//! 4. Compare the two resulting 32-byte hashes.
//!    If they are equal the PR changes no execution logic → `SEMANTIC_NULL`.

use blake3::Hasher;
use tree_sitter::Node;

/// Node kinds that carry **no** execution semantics.
///
/// Stripping these leaves only the structural skeleton of the AST.
/// The set covers tree-sitter's language-agnostic cosmetic node kinds.
const COSMETIC_KINDS: &[&str] = &[
    "identifier",
    "type_identifier",
    "field_identifier",
    "string_literal",
    "string",
    "string_content",
    "comment",
    "line_comment",
    "block_comment",
    "doc_comment",
    "integer_literal",
    "float_literal",
    "char_literal",
    "raw_string_literal",
    // Whitespace / punctuation nodes that most grammars expose as named nodes.
    "newline",
    "indent",
    "dedent",
];

/// Returns `true` if the node kind carries execution semantics.
///
/// Cosmetic nodes (identifiers, literals, comments) are excluded so only
/// structural skeleton nodes contribute to the hash.
#[inline]
fn is_structural(kind: &str) -> bool {
    !COSMETIC_KINDS.contains(&kind)
}

/// Stream structural node kinds from `node`'s subtree into `hasher`.
///
/// Uses a manual stack-based traversal to avoid recursion (zero stack growth
/// beyond the bounded `Vec<Node>` which mirrors the tree depth, typically ≤ 50
/// for real-world ASTs).
///
/// Only named nodes with structural kinds contribute bytes.  Leaf nodes are
/// included if structural; internal nodes contribute their kind string before
/// their children are pushed.
fn hash_structural_skeleton(node: Node, hasher: &mut Hasher) {
    let mut stack: Vec<Node> = Vec::with_capacity(64);
    stack.push(node);

    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if n.is_named() && is_structural(kind) {
            hasher.update(kind.as_bytes());
            hasher.update(b"\x00"); // null separator — prevents kind-string concatenation collisions
        }
        // Push children in reverse order so they are processed left-to-right.
        let count = n.child_count();
        for i in (0..count).rev() {
            if let Some(child) = n.child(i as u32) {
                stack.push(child);
            }
        }
    }
}

/// Compute the BLAKE3 hash of the structural skeleton rooted at `node`.
///
/// Streams node kind strings into the hasher — zero heap allocation beyond
/// the traversal stack.
pub fn structural_hash(node: Node) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hash_structural_skeleton(node, &mut hasher);
    *hasher.finalize().as_bytes()
}

/// Returns `true` if the PR introduces no change to execution logic.
///
/// Compares the structural BLAKE3 hashes of `base_root` and `pr_root`.
/// Equal hashes mean only cosmetic tokens differ — the PR is `SEMANTIC_NULL`.
///
/// # Parameters
/// - `base_root`: Root node of the base-branch parse tree.
/// - `pr_root`: Root node of the PR-branch parse tree.
pub fn is_semantic_null(base_root: Node, pr_root: Node) -> bool {
    let base_hash = structural_hash(base_root);
    let pr_hash = structural_hash(pr_root);
    base_hash == pr_hash
}

/// Returns `true` if the full file blobs produce identical structural skeletons.
///
/// Parses both byte slices with `language`, then delegates to [`is_semantic_null`].
/// Returns `false` on any parse failure or if either tree contains error nodes
/// (indicating the grammar could not cleanly parse the file — unsafe to conclude null).
///
/// # Parameters
/// - `old_bytes`: Raw bytes of the file at the base/merge-base commit.
/// - `new_bytes`: Raw bytes of the file at the PR head commit.
/// - `language`: The tree-sitter grammar to use for both parses.
pub fn is_semantic_null_blobs(
    old_bytes: &[u8],
    new_bytes: &[u8],
    language: &tree_sitter::Language,
) -> bool {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(language).is_err() {
        return false;
    }

    let old_tree = match parser.parse(old_bytes, None) {
        Some(t) => t,
        None => return false,
    };
    let new_tree = match parser.parse(new_bytes, None) {
        Some(t) => t,
        None => return false,
    };

    // Reject if either parse produced error nodes — structural comparison is
    // unreliable on incomplete/invalid ASTs.
    if old_tree.root_node().has_error() || new_tree.root_node().has_error() {
        return false;
    }

    is_semantic_null(old_tree.root_node(), new_tree.root_node())
}
