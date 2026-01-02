# Cut Command Implementation

This directory contains a proper implementation of the `cut` command for Cowrie honeypots.

## Features

- Supports field extraction with `-f` option (e.g., `-f1`, `-f1,3`, `-f1-3`)
- Custom delimiters with `-d` option (e.g., `-d:` for colon-separated fields)
- File input support
- Piped input support
- Basic error handling and help/version output

## Usage Examples

```bash
# Extract first field from /etc/passwd (usernames)
cat /etc/passwd | cut -f1 -d:

# Extract username and shell from /etc/passwd
cut -f1,7 -d: /etc/passwd

# Extract fields 1 through 3
cut -f1-3 -d: /etc/passwd
```

## Implementation Notes

- Based on the Cowrie command framework (similar to awk, dd, curl implementations)
- Supports the most common cut options: `-f`, `-d`, `-s`, `--complement`
- Handles both file input and piped input
- Includes proper error messages and help text

## Installation

1. Place `cut.py` in `cowrie-core/commands/cut.py`
2. The Docker build process will automatically copy it to the correct location in the Cowrie container
3. The command will be automatically registered as both `cut` and `/usr/bin/cut`

## Testing

To test the implementation:

```bash
# In a Cowrie shell
echo "root:x:0:0:root:/root:/bin/bash" | cut -f1 -d:
# Should output: root
```