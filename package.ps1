mkdir tools

$sourceNugetExe = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
$targetNugetExe = ".\tools\nuget.exe"
Invoke-WebRequest $sourceNugetExe -OutFile $targetNugetExe

.\tools\nuget.exe pack .\Syfuhs.Security.Kerberos\Syfuhs.Security.Kerberos.csproj -Prop Configuration=Release
.\tools\nuget.exe pack .\Syfuhs.Security.Kerberos.Aes\Syfuhs.Security.Kerberos.Aes.csproj -Prop Configuration=Release