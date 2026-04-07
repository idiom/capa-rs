# capa-rs demo — IDA backend + pure-Rust analysis

Output demos/all_samples.gif

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
Type "cd C:\Users\yeti-sec\Desktop\test_samples"
Enter
Sleep 1s
Type "cls"
Enter
Sleep 500ms
Show

Type "# 1/6  IDA backend — BadBazaar spyware"
Enter
Sleep 0.5s
Type "capa-rs --backend ida floss\floss_badbazzar"
Enter
Sleep 15s

Type "# 2/6  IDA backend — Conti ransomware"
Enter
Sleep 0.5s
Type "capa-rs --backend ida floss\floss_conti"
Enter
Sleep 20s

Type "# 3/6  ELF (Mirai botnet)"
Enter
Sleep 0.5s
Type "capa-rs elf_mirai"
Enter
Sleep 8s

Type "# 4/6  Golang PE (Vidar stealer)"
Enter
Sleep 0.5s
Type "capa-rs golang_vidar"
Enter
Sleep 8s

Type "# 5/6  GraalVM native-image (Cysmos)"
Enter
Sleep 0.5s
Type "capa-rs graalvm_cysmos"
Enter
Sleep 8s

Type "# 6/6  Rust PE (CargoBay)"
Enter
Sleep 0.5s
Type "capa-rs rust_cargobay"
Enter
Sleep 8s

Type "# 6 samples — 2x IDA backend, 4x pure Rust"
Enter
Sleep 2s
