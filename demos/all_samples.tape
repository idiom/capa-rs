# capa-rs demo — all sample types in one recording

Output demos/all_samples.gif

Set Shell "powershell"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

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

Type "# 1/8  .NET assembly (njRAT)"
Enter
Sleep 0.5s
Type "capa-rs -f dotnet dotnet_njrat"
Enter
Sleep 8s

Type "# 2/8  ELF (Mirai)"
Enter
Sleep 0.5s
Type "capa-rs elf_mirai"
Enter
Sleep 8s

Type "# 3/8  Golang PE (Vidar)"
Enter
Sleep 0.5s
Type "capa-rs golang_vidar"
Enter
Sleep 8s

Type "# 4/8  GraalVM native-image (Cysmos)"
Enter
Sleep 0.5s
Type "capa-rs graalvm_cysmos"
Enter
Sleep 8s

Type "# 5/8  Rust PE (CargoBay)"
Enter
Sleep 0.5s
Type "capa-rs rust_cargobay"
Enter
Sleep 8s

Type "# 6/8  FLOSS sample (BadBazaar)"
Enter
Sleep 0.5s
Type "capa-rs floss_badbazzar"
Enter
Sleep 8s

Type "# 7/8  FLOSS sample (Conti)"
Enter
Sleep 0.5s
Type "capa-rs floss_conti"
Enter
Sleep 8s

Type "# 8/8  PE sample"
Enter
Sleep 0.5s
Type "capa-rs b02337d82c44ed46e5b186bd54cde717be39da81a29fb332090d10a5c444ccb6"
Enter
Sleep 8s

Type "# All 8 samples analyzed"
Enter
Sleep 2s
