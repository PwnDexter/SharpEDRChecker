using System;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class ScheduledTaskChecker : IChecker
    {
        public string Name => "scheduledtasks";

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("############################################");
                Console.WriteLine("[!][!][!] Checking Scheduled Tasks [!][!][!]");
                Console.WriteLine("############################################\n");

                var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\TaskScheduler");
                var query = new ObjectQuery("SELECT * FROM MSFT_ScheduledTask");
                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject task in searcher.Get())
                    {
                        summaryBuilder.Append(CheckTask(task));
                    }
                }

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious scheduled tasks found\n");
                    return "\n[+] No suspicious scheduled tasks found\n";
                }
                return $"\n[!] Scheduled Task Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking scheduled tasks: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking scheduled tasks\n";
            }
        }

        private string CheckTask(ManagementObject task)
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                string taskName = task["TaskName"]?.ToString() ?? "";
                string taskPath = task["TaskPath"]?.ToString() ?? "";
                string allattribs = $"{taskName} - {taskPath}";

                var actions = (ManagementBaseObject[])task["Actions"];
                if (actions != null)
                {
                    foreach (var action in actions)
                    {
                        // We are most interested in command-line actions
                        if (action.ClassPath.ClassName == "MSFT_TaskExecAction")
                        {
                            allattribs += $" - {action["Execute"]} {action["Arguments"]}";
                        }
                    }
                }

                var matches = EDRMatcher.GetMatches(allattribs);
                if (matches.Count > 0)
                {
                    Console.WriteLine($"[-] Suspicious scheduled task found:" +
                                      $"\n\tTask Path: {taskPath}{taskName}" +
                                      $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                    summaryBuilder.Append($"\t[-] {taskPath}{taskName} : {string.Join(", ", matches.ToArray())}\n");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking individual task: {task["TaskName"]}\n{e.Message}");
            }
            return summaryBuilder.ToString();
        }
    }
}
