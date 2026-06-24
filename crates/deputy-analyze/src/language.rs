use serde::Serialize;
use std::fmt;

/// A source language, classified by file extension. Memory-unsafe native languages (C/C++/asm)
/// are tracked distinctly because their presence in a dependency raises its risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Language {
    Rust,
    C,
    Cpp,
    Assembly,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Shell,
    Other,
}

impl Language {
    /// Classify by (case-insensitive) file extension.
    pub fn from_ext(ext: &str) -> Self {
        match ext.to_ascii_lowercase().as_str() {
            "rs" => Language::Rust,
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => Language::Cpp,
            "s" | "asm" => Language::Assembly,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" => Language::TypeScript,
            "py" => Language::Python,
            "go" => Language::Go,
            "sh" | "bash" => Language::Shell,
            _ => Language::Other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::C => "C",
            Language::Cpp => "C++",
            Language::Assembly => "Assembly",
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Python => "Python",
            Language::Go => "Go",
            Language::Shell => "Shell",
            Language::Other => "Other",
        }
    }

    /// Whether this is a memory-unsafe native language (C / C++ / assembly).
    pub fn is_memory_unsafe_native(self) -> bool {
        matches!(self, Language::C | Language::Cpp | Language::Assembly)
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
