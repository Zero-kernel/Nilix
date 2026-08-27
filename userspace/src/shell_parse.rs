//! Pure command-prefix parsing shared by the user shell and host tests.

/// Return the argument portion of an `ls` command.
///
/// `Some(&[])` denotes bare `ls` (current directory), while a non-empty slice
/// is the requested path.  Argument-taking forms are recognized before the
/// bare command so a separating whitespace byte cannot be mistaken for the
/// end of the command (U56-1).
pub fn ls_args(command: &[u8]) -> Option<&[u8]> {
    if command.len() >= 3
        && command[0] == b'l'
        && command[1] == b's'
        && (command[2] == b' ' || command[2] == b'\t')
    {
        return Some(&command[3..]);
    }
    if command.len() >= 2
        && command[0] == b'l'
        && command[1] == b's'
        && (command.len() == 2 || command[2] == 0 || command[2] == b' ' || command[2] == b'\t')
    {
        return Some(&[]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::ls_args;

    #[test]
    fn separates_bare_and_path_forms_without_reordering_ambiguity() {
        assert_eq!(ls_args(b"ls"), Some(&[][..]));
        assert_eq!(ls_args(b"ls /tmp"), Some(b"/tmp".as_slice()));
        assert_eq!(ls_args(b"ls\t/var"), Some(b"/var".as_slice()));
        assert_eq!(ls_args(b"lsof"), None);
    }
}
