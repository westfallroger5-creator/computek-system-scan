using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CompuTek.Scanner.App
{
    internal sealed class EngineLayout
    {
        public string DirectoryPath { get; set; }
        public string RemoteScannerPath { get; set; }
        public string PostScamScannerPath { get; set; }
        public string TechnicianToolboxPath { get; set; }
        public string FinalSystemCheckPath { get; set; }
        public string PreClonePath { get; set; }
        public string CatalogPath { get; set; }
        public CatalogInfo Catalog { get; set; }
    }

    internal static class EmbeddedEngine
    {
        private const string RemoteResource = "CompuTek.Scanner.Engine.RemoteAccessScanAndRemove.ps1";
        private const string PostScamResource = "CompuTek.Scanner.Engine.PostScam_SystemIntegrityScanner.ps1";
        private const string TechnicianToolboxResource = "CompuTek.Scanner.Engine.IT_Technician_Toolbox.ps1";
        private const string FinalSystemCheckResource = "CompuTek.Scanner.Engine.FinalSystemCheck_CompuTek.ps1";
        private const string PreCloneResource = "CompuTek.Scanner.Engine.PreClone.ps1";
        private const string ModuleResource = "CompuTek.Scanner.Engine.CompuTek.Scanner.Common.psm1";
        private const string CatalogResource = "CompuTek.Scanner.Engine.RemoteAccessSignatures.json";

        public static EngineLayout Prepare()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            string version = assembly.GetName().Version.ToString();
            string programDataRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CompuTek",
                "ScannerApp");
            string compuTekRoot = Directory.GetParent(programDataRoot).FullName;
            string engineRoot = Path.Combine(programDataRoot, "Engine");
            string stageDirectory = Path.Combine(engineRoot, version);
            PrepareProtectedDirectory(compuTekRoot);
            PrepareProtectedDirectory(programDataRoot);
            PrepareProtectedDirectory(engineRoot);
            PrepareProtectedDirectory(stageDirectory);

            string remotePath = Path.Combine(stageDirectory, "RemoteAccessScanAndRemove.ps1");
            string postScamPath = Path.Combine(stageDirectory, "PostScam_SystemIntegrityScanner.ps1");
            string technicianToolboxPath = Path.Combine(stageDirectory, "IT_Technician_Toolbox.ps1");
            string finalSystemCheckPath = Path.Combine(stageDirectory, "FinalSystemCheck_CompuTek.ps1");
            string preClonePath = Path.Combine(stageDirectory, "PreClone.ps1");
            string modulePath = Path.Combine(stageDirectory, "CompuTek.Scanner.Common.psm1");
            string catalogPath = Path.Combine(stageDirectory, "RemoteAccessSignatures.json");

            WriteResource(assembly, RemoteResource, remotePath);
            WriteResource(assembly, PostScamResource, postScamPath);
            WriteResource(assembly, TechnicianToolboxResource, technicianToolboxPath);
            WriteResource(assembly, FinalSystemCheckResource, finalSystemCheckPath);
            WriteResource(assembly, PreCloneResource, preClonePath);
            WriteResource(assembly, ModuleResource, modulePath);

            CatalogInfo catalog = LoadCatalog(assembly, programDataRoot);
            WriteAtomic(catalogPath, catalog.Content);

            return new EngineLayout
            {
                DirectoryPath = stageDirectory,
                RemoteScannerPath = remotePath,
                PostScamScannerPath = postScamPath,
                TechnicianToolboxPath = technicianToolboxPath,
                FinalSystemCheckPath = finalSystemCheckPath,
                PreClonePath = preClonePath,
                CatalogPath = catalogPath,
                Catalog = catalog
            };
        }

        public static string GetPowerShellPath()
        {
            string path = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(path))
                throw new FileNotFoundException("Windows PowerShell 5.1 was not found.", path);
            return path;
        }

        private static CatalogInfo LoadCatalog(Assembly assembly, string programDataRoot)
        {
            string managedCatalog = Path.Combine(programDataRoot, "RemoteAccessSignatures.json");
            string portableCatalog = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RemoteAccessSignatures.json");
            if (File.Exists(portableCatalog))
                return CatalogValidator.Validate(File.ReadAllBytes(portableCatalog), "catalog beside the EXE");
            if (File.Exists(managedCatalog))
            {
                RejectReparsePoint(managedCatalog);
                return CatalogValidator.Validate(File.ReadAllBytes(managedCatalog), "managed ProgramData catalog");
            }
            return CatalogValidator.Validate(ReadResource(assembly, CatalogResource), "embedded default catalog");
        }

        private static void WriteResource(Assembly assembly, string resourceName, string destination)
        {
            WriteAtomic(destination, ReadResource(assembly, resourceName));
        }

        private static byte[] ReadResource(Assembly assembly, string resourceName)
        {
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                    throw new InvalidOperationException("Required embedded scanner component is missing: " + resourceName);
                using (MemoryStream memory = new MemoryStream())
                {
                    stream.CopyTo(memory);
                    return memory.ToArray();
                }
            }
        }

        private static void WriteAtomic(string destination, byte[] content)
        {
            RejectReparsePoint(destination);
            string temporary = destination + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllBytes(temporary, content);
            try
            {
                // Delete a pre-existing regular file before the move so an unsafe
                // explicit ACL from an older/user-created file cannot survive the
                // overwrite. The new file inherits the protected directory ACL.
                if (File.Exists(destination)) File.Delete(destination);
                File.Move(temporary, destination);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private static void PrepareProtectedDirectory(string path)
        {
            if (Directory.Exists(path))
                RejectReparsePoint(path);
            else
                Directory.CreateDirectory(path);
            RejectReparsePoint(path);
            ProtectDirectory(path);
        }

        private static void RejectReparsePoint(string path)
        {
            if (!File.Exists(path) && !Directory.Exists(path)) return;
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("A trusted scanner path is a link or reparse point and will not be used: " + path);
        }

        private static void ProtectDirectory(string path)
        {
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
            Directory.SetAccessControl(path, security);
        }
    }
}
