using System;

namespace SharpEDRChecker
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                bool isAdm = PrivilegeChecker.PrivCheck();
                PrintIntro(isAdm);
                var summary = ProcessChecker.CheckProcesses();
                summary += ProcessChecker.CheckCurrentProcessModules();
                summary += DirectoryChecker.CheckDirectories();
                summary += ServiceChecker.CheckServices();
                summary += DriverChecker.CheckDrivers();
                PrintOutro(summary);
#if DEBUG
                Console.WriteLine("Press Enter to continue...");
                Console.ReadLine();
#endif
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error running SharpEDRChecker: " + e.Message);
                Console.WriteLine(e.StackTrace);
            }
        }

        private static void PrintIntro(bool isAdm)
        {
            if (isAdm)
            {
                Console.WriteLine($"\n##################################################################");
                Console.WriteLine("   [!][!][!] Welcome to SharpEDRChecker by @PwnDexter [!][!][!]");
                Console.WriteLine("[+][+][+] Running as admin, all checks will be performed [+][+][+]");
                Console.WriteLine($"##################################################################\n");
            }
            else
            {
                Console.WriteLine($"\n###################################################################################################");
                Console.WriteLine("                    [!][!][!] Welcome to SharpEDRChecker by @PwnDexter [!][!][!]");
                Console.WriteLine("[-][-][-] Not running as admin, some privileged metadata and processes may not be checked [-][-][-]");
                Console.WriteLine($"###################################################################################################\n");
            }
        }

        private static void PrintOutro(string summary)
        {
            Console.WriteLine($"################################");
            Console.WriteLine($"[!][!][!] TLDR Summary [!][!][!]");
            Console.WriteLine($"################################");
            Console.WriteLine($"{summary}");
            Console.WriteLine($"#######################################");
            Console.WriteLine("[!][!][!] EDR Checks Complete [!][!][!]");
            Console.WriteLine($"#######################################\n");
        }
    }
}
