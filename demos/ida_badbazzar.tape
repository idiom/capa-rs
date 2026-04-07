# capa-rs demo — IDA backend analysis: BadBazaar spyware

Output demos/ida_badbazzar.gif

Set Shell "powershell"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type "$env:PATH = 'C:\Users\yeti-sec\Desktop\capa-rs-release\target\release;C:\Program Files\IDA Professional 9.2;' + $env:PATH"
Enter
Type "$env:IDADIR = 'C:\Program Files\IDA Professional 9.2'"
Enter
Type "cd C:\Users\yeti-sec\Desktop\test_samples\floss"
Enter
Sleep 1s
Type "cls"
Enter
Sleep 500ms
Show

Type "# IDA Pro backend — BadBazaar spyware"
Enter
Sleep 0.5s
Type "capa-rs --backend ida floss_badbazzar"
Enter
Sleep 15s

Type "# Verbose output via IDA backend"
Enter
Sleep 0.5s
Type "capa-rs --backend ida -v floss_badbazzar"
Enter
Sleep 15s
