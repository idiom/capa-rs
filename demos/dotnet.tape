# capa-rs demo — .NET assembly analysis

Output demos/dotnet.gif

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
Type "cd C:\Users\yeti-sec\Desktop\test_samples"
Enter
Sleep 1s
Type "cls"
Enter
Sleep 500ms
Show

Type "# .NET assembly analysis — njRAT"
Enter
Sleep 0.5s
Type "capa-rs -f dotnet dotnet_njrat"
Enter
Sleep 8s

Type "# Verbose output"
Enter
Sleep 0.5s
Type "capa-rs -v -f dotnet dotnet_njrat"
Enter
Sleep 8s
