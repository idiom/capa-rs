# capa-rs demo — static capability detection for PE/ELF binaries
# Usage: vhs demo.tape

Output demo.gif

Set Shell "powershell"
Set FontSize 15
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set CursorBlink false

Hide
Type "$env:PATH = 'C:\Users\yeti-sec\Desktop\capa-rs-release\capa-rs-release\target\release;' + $env:PATH"
Enter
Type "$env:CAPA_RULES = 'C:\Users\yeti-sec\Desktop\capa-rules'"
Enter
Type "cd C:\Users\yeti-sec\Desktop\test_samples"
Enter
Sleep 1s
Type "cls"
Enter
Sleep 500ms
Show

# -- Title --
Type "# capa-rs -- fast capability detection for PE/ELF binaries"
Enter
Sleep 1s

# -- Show help --
Type "capa-rs --help"
Enter
Sleep 3s

# -- Analyze a binary --
Type "capa-rs golang_vidar"
Enter
Sleep 5s

# -- Verbose output with match locations --
Type "capa-rs -v golang_vidar"
Enter
Sleep 5s

# -- JSON output for automation --
Type "capa-rs -j golang_vidar | Select-Object -First 40"
Enter
Sleep 4s

# -- Namespace filtering --
Type "capa-rs -n anti-analysis golang_vidar"
Enter
Sleep 4s

# -- Done --
Type "# ~10x faster than Python capa"
Enter
Sleep 2s
