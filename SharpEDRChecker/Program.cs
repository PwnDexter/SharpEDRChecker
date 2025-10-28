﻿﻿﻿using System;

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
                var summary = new ProcessChecker().Check();
                summary += new ModuleChecker().Check();
                summary += new DirectoryChecker().Check();
                summary += new ServiceChecker().Check();
                summary += new RegistryChecker().Check();
                summary += new AdsChecker().Check();
                summary += new BrowserExtensionChecker().Check();
                summary += new DriverChecker().Check();
                summary += new DnsCacheChecker().Check();
                summary += new EtwProviderChecker().Check();
                summary += new EventLogProviderChecker().Check();
                summary += new ScheduledTaskChecker().Check();
                summary += new WmiConsumerChecker().Check();
                summary += new NetworkChecker().Check();
                summary += new SecurityProductChecker().Check();
                summary += new ForensicToolChecker().Check();
                summary += new RemoteAccessToolChecker().Check();

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
