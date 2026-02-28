//! CSV export for bounce log data.
//!
//! Reads `.janitor/bounce_log.ndjson` and streams each entry as a CSV row,
//! suitable for loading into Excel, Google Sheets, or a pandas DataFrame.
//!
//! ## Columns
//!
//! | Column | Source field | Notes |
//! |--------|-------------|-------|
//! | `PR_Number` | `pr_number` | Empty string when absent |
//! | `Author` | `author` | Empty string when absent |
//! | `Score` | `slop_score` | Composite weighted score |
//! | `Dead_Code_Count` | `dead_symbols_added` | Functions re-added from registry |
//! | `Logic_Clones` | `logic_clones_found` | BLAKE3/SimHash clone pairs |
//! | `Zombie_Syms` | `zombie_symbols_added` | Verbatim dead-body reintroductions |
//! | `Zombie_Deps` | `zombie_deps` | Dep names joined with `;` |
//! | `Antipatterns` | `antipatterns` | Violation descriptions joined with `;` |
//! | `Comment_Violations` | `comment_violations` | Phrase + line joined with `;` |
//! | `Timestamp` | `timestamp` | ISO 8601 UTC |

use anyhow::Result;
use std::path::Path;

/// Export the bounce log at `<repo>/.janitor/bounce_log.ndjson` to a CSV file.
///
/// Creates or overwrites `out`.  Returns an error when the bounce log is absent
/// or the output file cannot be written.
pub fn cmd_export(repo: &Path, out: &Path) -> Result<()> {
    let janitor_dir = repo.join(".janitor");
    let entries = crate::report::load_bounce_log(&janitor_dir);

    if entries.is_empty() {
        anyhow::bail!(
            "No bounce log entries found at {}.\n\
             Run `janitor bounce` first to populate the log.",
            janitor_dir.join("bounce_log.ndjson").display()
        );
    }

    let mut wtr = csv::Writer::from_path(out)
        .map_err(|e| anyhow::anyhow!("Cannot create CSV file {}: {}", out.display(), e))?;

    // Header row.
    wtr.write_record([
        "PR_Number",
        "Author",
        "Score",
        "Dead_Code_Count",
        "Logic_Clones",
        "Zombie_Syms",
        "Zombie_Deps",
        "Antipatterns",
        "Comment_Violations",
        "Timestamp",
    ])?;

    for entry in &entries {
        wtr.write_record([
            entry
                .pr_number
                .map(|n| n.to_string())
                .unwrap_or_default()
                .as_str(),
            entry.author.as_deref().unwrap_or(""),
            entry.slop_score.to_string().as_str(),
            entry.dead_symbols_added.to_string().as_str(),
            entry.logic_clones_found.to_string().as_str(),
            entry.zombie_symbols_added.to_string().as_str(),
            entry.zombie_deps.join(";").as_str(),
            entry.antipatterns.join(";").as_str(),
            entry.comment_violations.join(";").as_str(),
            entry.timestamp.as_str(),
        ])?;
    }

    wtr.flush()?;

    println!("Exported {} entries → {}", entries.len(), out.display());
    Ok(())
}
