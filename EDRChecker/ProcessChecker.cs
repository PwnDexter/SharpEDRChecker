using System;
using System.Diagnostics;
using System.Management;

namespace EDRChecker
{
    internal class ProcessChecker
    {
        public static void CheckProcesses()
        {
            
            //Get process listing
            Process[] proclist = Process.GetProcesses();
            Console.WriteLine("Current running processes are:");

            foreach (Process i in proclist)
            {
                Console.WriteLine("Process: {0} ID: {1} ", i.ProcessName, i.Id);
            }
        }

        public static void CheckCurrentProcessModules()
        {
            //Get your current process - GTG
            Process myproc = Process.GetCurrentProcess();
            Console.WriteLine("My procs loaded modules: {0} ID: {1} Name: {2}", myproc.Modules, myproc.Id, myproc.ProcessName);

            // WMI Proc info
            var searcher = new ManagementObjectSearcher("Select * From Win32_Process");
            var processList = searcher.Get();

            foreach (var process in processList)
            {
                var processName = process["Name"];
                var processPath = process["ExecutablePath"];

                if (processPath != null)
                {
                    var fileVersionInfo = FileVersionInfo.GetVersionInfo(processPath.ToString());
                    var processDescription = fileVersionInfo.FileDescription;

                    Console.WriteLine("WMI Proc Stuff");
                    Console.WriteLine("{0} - {1}", processName, processDescription);
                }
            }
        }
    }
}
