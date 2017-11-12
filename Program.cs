using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading.Tasks;

namespace SharePointFileShareMigrationAnalysis
{
    class Program
    {
        internal static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        internal static int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        internal const int MAX_PATH = 260;

        [StructLayout(LayoutKind.Sequential)]
        internal struct FILETIME
        {
            internal uint dwLowDateTime;
            internal uint dwHighDateTime;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WIN32_FIND_DATA
        {
            internal FileAttributes dwFileAttributes;
            internal FILETIME ftCreationTime;
            internal FILETIME ftLastAccessTime;
            internal FILETIME ftLastWriteTime;
            internal int nFileSizeHigh;
            internal int nFileSizeLow;
            internal int dwReserved0;
            internal int dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string cFileName;
            // not using this
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            internal string cAlternate;
        }

        [Flags]
        internal enum EFileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,
        }

        [Flags]
        internal enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004,
        }

        internal enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5,
        }

        [Flags]
        internal enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr FindFirstFile(string lpFileName, out
                WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern bool FindNextFile(IntPtr hFindFile, out
                WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FindClose(IntPtr hFindFile);

        internal class DirInfo
        {
            public long Size { get; set; }
            public long Files { get; set; }
        }

        internal static long byteToGb = 1024 * 1024 * 1024;
        internal static string[] hiddenDirs = new string[] {
            "_files",
            "_Dateien",
            "_fichiers",
            "_bestanden",
            "_file",
            "_archivos",
            "_tiedostot",
            "_pliki",
            "_soubory",
            "_elemei",
            "_ficheiros",
            "_arquivos",
            "_dosyalar",
            "_datoteke",
            "_fitxers",
            "_failid",
            "_fails",
            "_bylos",
            "_fajlovi",
            "_fitxategiak",
            "_private" };

        public static void Main(string[] args)
        {
            try
            {
                using (StreamWriter ffi = new FileInfo("SPShareAnalysis_Files.csv").CreateText())
                {
                    ffi.AutoFlush = true;
                    lock(ffi){ ffi.WriteLine("{0},{1},{2}", new object[] { "Path", "Size", "MaxPathLength" }); }
                    using (StreamWriter cfi = new FileInfo("SPShareAnalysis_Dirs.csv").CreateText())
                    {
                        cfi.AutoFlush = true;
                        lock(cfi){ cfi.WriteLine("{0},{1},{2},{3},{4},{5},{6}", new object[] { "Path", "#Files", "#Dirs", "SizeOfFiles", "TotalSize", "TotalFiles", "MaxPathLength" }); }
                        using (StreamWriter efi = new FileInfo("SPShareAnalysis_Errors.csv").CreateText())
                        {
                            efi.AutoFlush = true;
                            lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { "Path", "Type", "Error" }); }
                            using (StreamWriter tfi = new FileInfo("SPShareAnalysis_Types.csv").CreateText())
                            {
                                tfi.AutoFlush = true;
                                lock(tfi){ tfi.WriteLine("{0},{1},{2}", new object[] { "Type", "Count", "Size" }); }
                                string[] shares = new string[Properties.Settings.Default.Shares.Count];
                                Properties.Settings.Default.Shares.CopyTo(shares, 0);
                                Dictionary<string, DirInfo> typeInfo = new Dictionary<string, DirInfo>();
                                Parallel.ForEach(shares, new ParallelOptions {
                                    MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1 }, 
                                    (currentShare) =>
                                {
                                    GetInfo(currentShare, currentShare, ffi, cfi, efi, typeInfo);
                                });
                                foreach (KeyValuePair<string, DirInfo> type in typeInfo)
                                    lock(tfi){ tfi.WriteLine("{0},{1},{2}", new object[] { type.Key, type.Value.Files, type.Value.Size }); }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                lock(Console.Error){ Console.Error.WriteLine("An exception happended: " + ex.GetType().ToString()); }
                lock(Console.Error){ Console.Error.WriteLine(ex.Message); }
                lock(Console.Error){ Console.Error.WriteLine(ex.StackTrace); }
            }
        }

        internal static string GetName(string di)
        {
            while (di.EndsWith("\\")) { di.TrimEnd("\\".ToCharArray()); }
            if (di.IndexOf("\\") == -1) return di;
            return di.Substring(di.LastIndexOf("\\") + 1);
        }

        internal static long GetFileSize(string filePath)
        {
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(filePath, out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                return (long)findData.nFileSizeLow + (long)findData.nFileSizeHigh * 4294967296;
            }
            else
            {
                return 0;
            }
        }

        internal static List<string> GetDirectories(string dirName)
        {
            List<string> results = new List<string>();
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(dirName + @"\*", out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                bool found;
                do
                {
                    string currentFileName = findData.cFileName;
                    if (((int)findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                        currentFileName != "." && currentFileName != "..")
                    {
                        results.Add(Path.Combine(dirName, currentFileName));
                    }
                    found = FindNextFile(findHandle, out findData);
                }
                while (found);
            }
            FindClose(findHandle);
            return results;
        }

        internal static List<string> GetFiles(string dirName)
        {
            List<string> results = new List<string>();
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(dirName + @"\*", out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                bool found;
                do
                {
                    string currentFileName = findData.cFileName;
                    if (((int)findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        results.Add(Path.Combine(dirName, currentFileName));
                    }
                    found = FindNextFile(findHandle, out findData);
                }
                while (found);
            }
            FindClose(findHandle);
            return results;
        }

        internal static DirInfo GetInfo(string root, string di, StreamWriter ffi, StreamWriter cfi, StreamWriter efi, Dictionary<string, DirInfo> typeInfo)
        {
            string name = GetName(di);
            if (name.IndexOfAny("\\/:*?\"<>|#%".ToCharArray()) > -1)
                lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "Not allowed character found: \\ / : * ? \" < > | # %" }); }
            if (name.ToCharArray()[0] == '~')
                lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "A name starting with ~ is not allowed" }); }
            if (name.ToCharArray()[0] == '.')
                lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "A name starting with . is not allowed" }); }
            foreach (string ending in hiddenDirs)
            {
                if (name.EndsWith(ending))
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "A name ending in " + ending + " will not be visible" }); }
            }
            if (name == "forms")
                lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "A name forms is not allowed" }); }
            if (name.Contains("_vti_"))
                lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "Folder name should not contain _vti_" }); }
            if (name.Length > 250)
                lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { di, "Dir", "Name too long" }); }
            List<string> files = GetFiles(di);
            List<string> subs = GetDirectories(di);
            long locSize = 0;
            long subSize = 0;
            long subCount = files.Count;
            int maxPathLength = di.Length;
            Parallel.ForEach(files, new ParallelOptions {
                MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1 }, 
                (fi) =>
            {
                locSize += GetFileSize(fi);
                string fname = GetName(fi);
                string fext = "";
                if (fname.IndexOf(".") > -1) fext = fname.Substring(fname.LastIndexOf("."));
                lock (typeInfo)
                {
                    if (!typeInfo.ContainsKey(fext)) typeInfo.Add(fext, new DirInfo());
                    typeInfo[fext].Files += 1;
                    typeInfo[fext].Size += locSize;
                }
                if (fname.IndexOfAny("\\/:*?\"<>|#%".ToCharArray()) > -1)
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "Not allowed character found: \\ / : * ? \" < > | # %" }); }
                if (fname.ToCharArray()[0] == '~')
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "A name starting with ~ is not allowed" }); }
                if (fname.ToCharArray()[0] == '.' && fname.ToCharArray()[1] == '.')
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "A name starting with .. is not allowed" }); }
                if (fext == ".tmp" || fext == ".ds_store")
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "File extensions .tmp and .ds_store are not allowed" }); }
                if (fname == "desktop.ini" || fname == "thumbs.db" || fname == "ehthumbs.db")
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "File names desktop.ini, thumbs.db and ehthumbs.db are not allowed" }); }
                if ((fi.Length / byteToGb) > 2)
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "Too big. only 2GB allowed" }); }
                if (fname.Length > 256)
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "Name too long. Only 256 allowed" }); }
                if ((fi.Length - root.Length) > 250)
                    lock(efi){ efi.WriteLine("{0},{1},{2}", new object[] { fi, "File", "Folder name and file name combinations can have up to 250 characters" }); }
                if (fi.Length > maxPathLength)
                    maxPathLength = fi.Length;
                lock(ffi){ ffi.WriteLine("{0},{1},{2}", new object[] { fi, locSize, fname.Length }); }
            });
            Parallel.ForEach(subs, new ParallelOptions {
                MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1 }, 
                (sdi) =>
            {
                DirInfo subinfo = GetInfo(root, sdi, ffi, cfi, efi, typeInfo);
                subSize += subinfo.Size;
                subCount += subinfo.Files;
            });
            lock(cfi){ cfi.WriteLine("{0},{1},{2},{3},{4},{5},{6}", new object[] { di, files.Count, subs.Count, locSize / byteToGb, (locSize + subSize) / byteToGb, subCount, maxPathLength }); }
            DirInfo info = new DirInfo();
            info.Size = locSize + subSize;
            info.Files = subCount;
            return info;
        }
    }
}
