using System.Reflection;
using System.Resources;
using System.Runtime.InteropServices;

[assembly: AssemblyDescription("Kerberos.NET library")]

#if DEBUG
[assembly: AssemblyConfiguration("DEBUG")]
#else
[assembly: AssemblyConfiguration("RELEASE")]
#endif

[assembly: AssemblyProduct("Kerberos.NET")]
[assembly: AssemblyCopyright("Copyright © Kerberos.NET 2017")]
[assembly: NeutralResourcesLanguage("en", UltimateResourceFallbackLocation.MainAssembly)]

[assembly: ComVisible(false)]

[assembly: AssemblyInformationalVersion("1.2.2.1")]
