//! Terminal-only startup banner inspired by HardVPS.
//! Keep machine-readable output and redirected logs unchanged.

use std::io::{self, IsTerminal, Write};

const LOGO: [&str; 6] = [
    "██████╗ ███████╗ █████╗ ██╗     ██╗████████╗██╗     ",
    "██╔══██╗██╔════╝██╔══██╗██║     ██║╚══██╔══╝██║     ",
    "██████╔╝█████╗  ███████║██║     ██║   ██║   ██║     ",
    "██╔══██╗██╔══╝  ██╔══██║██║     ██║   ██║   ██║     ",
    "██║  ██║███████╗██║  ██║███████╗██║   ██║   ███████╗",
    "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   ╚══════╝",
];

/// Only paint interactive terminals; never pollute stdout for scripts/pipes.
pub fn show() {
    if !io::stdout().is_terminal() {
        return;
    }

    let colored = std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").as_deref() != Ok("dumb");
    let shades = [39, 45, 51, 50, 44, 38];
    let mut out = io::stdout().lock();
    let _ = writeln!(out);
    for (line, shade) in LOGO.iter().zip(shades) {
        if colored {
            let _ = writeln!(out, "   \x1b[1;38;5;{shade}m{line}\x1b[0m");
        } else {
            let _ = writeln!(out, "   {line}");
        }
    }
    if colored {
        let _ = writeln!(out, "   \x1b[1;38;5;220m  SCANNER XXL\x1b[0m");
        let _ = writeln!(out, "   \x1b[1;37m  Discover. Verify. Filter.\x1b[0m");
        let _ = writeln!(out, "   \x1b[38;5;220m  RELEASE {}\x1b[0m\n", env!("CARGO_PKG_VERSION"));
    } else {
        let _ = writeln!(out, "     SCANNER XXL");
        let _ = writeln!(out, "     Discover. Verify. Filter.");
        let _ = writeln!(out, "     RELEASE {}\n", env!("CARGO_PKG_VERSION"));
    }
    let _ = out.flush();
}
