using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpEDRChecker
{
    internal class BrowserExtensionChecker : IChecker
    {
        public string Name => "browserextensions";

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("################################################");
                Console.WriteLine("[!][!][!] Checking Browser Extensions [!][!][!]");
                Console.WriteLine("################################################\n");

                summaryBuilder.Append(CheckChromiumExtensions("Google Chrome",
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data")));

                summaryBuilder.Append(CheckChromiumExtensions("Microsoft Edge",
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data")));

                summaryBuilder.Append(CheckFirefoxExtensions(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox\Profiles")));


                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious browser extensions found\n");
                    return "\n[+] No suspicious browser extensions found\n";
                }
                return $"\n[!] Browser Extension Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking browser extensions: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking browser extensions\n";
            }
        }

        private string CheckChromiumExtensions(string browserName, string userDataPath)
        {
            var summaryBuilder = new StringBuilder();
            if (!Directory.Exists(userDataPath)) return "";

            try
            {
                var extensionDirs = Directory.GetDirectories(userDataPath, "Extensions", SearchOption.AllDirectories);
                foreach (var extensionDir in extensionDirs)
                {
                    foreach (var extension in Directory.GetDirectories(extensionDir))
                    {
                        var manifestPath = Path.Combine(extension, "manifest.json");
                        if (File.Exists(manifestPath))
                        {
                            string content = File.ReadAllText(manifestPath);
                            // Simple regex to find the "name" field in the manifest
                            var match = Regex.Match(content, "\"name\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"");
                            if (match.Success)
                            {
                                string extensionName = match.Groups[1].Value;
                                var matches = EDRMatcher.GetMatches(extensionName);
                                if (matches.Count > 0)
                                {
                                    Console.WriteLine($"[-] Suspicious {browserName} extension found:" +
                                                      $"\n\tExtension Name: {extensionName}" +
                                                      $"\n\tPath: {extension}" +
                                                      $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                                    summaryBuilder.Append($"\t[-] {browserName} - {extensionName} : {string.Join(", ", matches.ToArray())}\n");
                                }
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { /* Ignore */ }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not check {browserName} extensions at {userDataPath}: {e.Message}");
            }
            return summaryBuilder.ToString();
        }

        private string CheckFirefoxExtensions(string profilesPath)
        {
            var summaryBuilder = new StringBuilder();
            if (!Directory.Exists(profilesPath)) return "";

            try
            {
                var extensionsJsonFiles = Directory.GetFiles(profilesPath, "extensions.json", SearchOption.AllDirectories);
                foreach (var file in extensionsJsonFiles)
                {
                    string content = File.ReadAllText(file);
                    // Simple regex to find "name" fields in the extensions.json
                    var nameMatches = Regex.Matches(content, "\"name\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"");
                    foreach (Match match in nameMatches)
                    {
                        string extensionName = match.Groups[1].Value;
                        var edrMatches = EDRMatcher.GetMatches(extensionName);
                        if (edrMatches.Count > 0)
                        {
                            Console.WriteLine($"[-] Suspicious Firefox extension found:" +
                                              $"\n\tExtension Name: {extensionName}" +
                                              $"\n[!] Matched on: {string.Join(", ", edrMatches.ToArray())}\n");
                            summaryBuilder.Append($"\t[-] Firefox - {extensionName} : {string.Join(", ", edrMatches.ToArray())}\n");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not check Firefox extensions at {profilesPath}: {e.Message}");
            }
            return summaryBuilder.ToString();
        }
    }
}
