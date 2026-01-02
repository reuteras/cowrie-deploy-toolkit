# Dynamic filesystem for Cowrie honeypots

This module provides a dynamic filesystem implementation that makes `/proc/uptime` change in real-time based on container runtime, preventing honeypot detection through static uptime values.

## Features

- **Dynamic /proc/uptime**: Changes in real-time based on actual container runtime
- **Realistic behavior**: `cat /proc/uptime && sleep 5 && cat /proc/uptime` shows different values
- **Consistent uptime command**: `uptime` command matches `/proc/uptime` output
- **Backward compatible**: All other files behave exactly like the standard Cowrie filesystem

## Files

- `fs_dynamic.py`: Dynamic filesystem implementation with monkey patching
- `commands/uptime.py`: Uptime command that matches /proc/uptime output
- `commands/cut.py`: Enhanced cut command with field processing

## Usage

1. Include the files in your cowrie-core directory
2. The Docker build process will automatically integrate them
3. `/proc/uptime` and `uptime` command will show real container runtime

## Implementation Details

- **Monkey patching**: `fs_dynamic.py` replaces `HoneyPotFilesystem` with `DynamicHoneyPotFilesystem`
- **Real-time calculation**: Uptime calculated as `time.time() - start_time`
- **Consistent output**: Both `/proc/uptime` and `uptime` command use same calculation

## Testing

```bash
# In a honeypot session:
$ cat /proc/uptime
123.45 118.67

$ sleep 5

$ cat /proc/uptime
128.45 123.67

$ uptime
 10:30:45 up  3:25,  1 user,  load average: 0.00, 0.01, 0.05
```

Both `/proc/uptime` and `uptime` should show consistent, changing values.