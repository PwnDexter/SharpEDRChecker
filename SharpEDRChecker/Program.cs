﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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

                var allCheckers = new List<IChecker>
                {
                    new RegistryChecker(),
                    new ProcessChecker(),
                    new ModuleChecker(),
                    new DirectoryChecker(),
                    new AdsChecker(),
                    new ServiceChecker(),
                    new DriverChecker(),
                    new NetworkChecker(),
                    new DnsCacheChecker(),
                    new EventLogProviderChecker(),
                    new WmiConsumerChecker(),
                    new EtwProviderChecker(),
                    new BrowserExtensionChecker(),
                    new ScheduledTaskChecker(),
                    new SecurityProductChecker(),
                    new ForensicToolChecker(),
                    new RemoteAccessToolChecker()
                };

                List<IChecker> checkersToRun;
                if (args.Length > 0)
                {
                    if (args.Length == 1 && args[0].ToLower() == "list")
                    {
                        Console.WriteLine("\n[+] Available checks:");
                        foreach (var checker in allCheckers)
                        {
                            Console.WriteLine($"\t- {checker.Name}");
                        }
                        Console.WriteLine();
                        return;
                    }
                    Console.WriteLine($"[+] Running specified checks: {string.Join(", ", args)}\n");
                    var requestedChecks = new HashSet<string>(args.Select(a => a.ToLower()));
                    checkersToRun = allCheckers.Where(c => requestedChecks.Contains(c.Name.ToLower())).ToList();
                }
                else
                {
                    checkersToRun = allCheckers;
                }

                var summaryBuilder = new StringBuilder();
                var random = new Random();
                foreach (var checker in checkersToRun)
                {
                    // Sleep for a random time between 2 to 7 seconds to break up the activity pattern
                    System.Threading.Thread.Sleep(random.Next(2000, 7000));
                    summaryBuilder.Append(checker.Check());
                }

                PrintOutro(summaryBuilder.ToString());
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
