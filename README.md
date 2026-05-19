# hex_viewer_dz
hex viewer hacker style

## Compilation and Usage

```bash
# Install ncurses if not already installed
sudo apt-get install libncurses-dev  # Debian/Ubuntu
# or
sudo yum install ncurses-devel       # RHEL/CentOS

# Compile with Clang
clang -O2 -o hex_viewer hex_viewer.c -lncurses

# Run
./hex_viewer /bin/ls
./hex_viewer program.exe
```

## Features

1. **Multi-tab Interface**:
   - `[Tab]` switches between Hex, ASCII, Structures, and Raw views
   - Keyboard shortcuts: `h`, `a`, `s`, `r` for direct navigation

2. **Hex View**: Classic hex dump with address, hex bytes, and ASCII representation
3. **ASCII View**: Raw printable characters view
4. **Structures View**: Parsed ELF/PE headers and section information
5. **Raw View**: Continuous hex dump without formatting
6. **Navigation**: Arrow keys, Page Up/Down for scrolling

## Key Bindings

- `Arrow Keys` - Navigate through hex view
- `Tab` - Switch between views
- `PgUp/PgDn` - Page scrolling
- `h/a/s/r` - Direct view selection (Hex/ASCII/Structures/Raw)
- `q` - Quit

The viewer automatically detects ELF and PE file formats and displays appropriate structural information when in the Structures tab.
