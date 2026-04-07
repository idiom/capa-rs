# capa-rs demo — Conti ransomware analysis

Output demos/floss_conti.gif

Set Shell "powershell"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type "$env:PATH = 'C:\Users\yeti-sec\Desktop\ida_claude_rev2\tools;' + $env:PATH"
Enter
Type "$env:CAPA_RULES = 'C:\Users\yeti-sec\Desktop\capa-rules'"
Enter
Type "cd C:\Users\yeti-sec\Desktop\test_samples\floss"
Enter
Sleep 1s
Type "cls"
Enter
Sleep 500ms
Show

Type "# Conti ransomware analysis"
Enter
Sleep 0.5s
Type "capa-rs floss_conti"
Enter
Sleep 8s

Type "# Verbose output"
Enter
Sleep 0.5s
Type "capa-rs -v floss_conti"
Enter
Sleep 8s
