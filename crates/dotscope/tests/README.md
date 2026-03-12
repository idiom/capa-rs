# Test Fixtures

The Mono test sample DLLs are not included in this distribution to keep the
repository size manageable (~160MB of .NET assemblies).

To run dotscope tests that require these fixtures, download them from the
[Mono project](https://www.mono-project.com/) and place them under
`tests/samples/mono_2.0/`.

The `crafted_2.exe` fixture can be built from the dotscope fuzz/craft targets.
