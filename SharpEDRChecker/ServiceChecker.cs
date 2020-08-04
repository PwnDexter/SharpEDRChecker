using System;
using System.Collections.Generic;
using System.Management;

namespace SharpEDRChecker
{
    internal class ServiceChecker
    {
        internal static string CheckServices()
        {
            Console.WriteLine("[!] Checking Services...");
            try
            {
                var serviceList = new ManagementObjectSearcher("Select * From Win32_Service").Get();
                string summary = "";
                foreach (var service in serviceList)
                {
                    summary += CheckService(service);
                }
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious services found\n");
                    return "\n[+] No suspicious services found\n";
                }
                return $"\nService Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting services: {e}");
                return "[-] Errored on getting services";
            }
        }

        private static string CheckService(ManagementBaseObject service)
        {
            var serviceName = service["Name"];
            var serviceDisplayName = service["DisplayName"];
            var serviceDescription = service["Description"];
            var serviceCaption = service["Caption"];
            var servicePathName = service["PathName"];
            var serviceState = service["State"];
            var servicePID = service["ProcessId"];
            var metadata = "";

            var allattribs = $"{serviceName} - " +
                $"{serviceDisplayName} - " +
                $"{serviceDescription} - " +
                $"{serviceCaption} - " +
                $"{servicePathName}";

            if (servicePathName != null)
            {
                var indexOfExe = servicePathName.ToString().ToLower().IndexOf(".exe");
                var filePath = servicePathName.ToString().Substring(0, indexOfExe + ".exe".Length).Trim('"');
                metadata = $"{FileChecker.GetFileInfo(filePath)}";
                allattribs = $"{allattribs} - {metadata}";
            }

            var matches = new List<string>();
            foreach (var edrstring in EDRData.edrlist)
            {
                if (allattribs.ToLower().Contains(edrstring.ToLower()))
                {
                    matches.Add(edrstring);
                }
            }
            if (matches.Count > 0)
            {
                Console.WriteLine($"[-] Suspicious service found:" +
                       $"\n\tName: {serviceName}" +
                       $"\n\tDisplayName: {serviceDisplayName}" +
                       $"\n\tDescription: {serviceDescription}" +
                       $"\n\tCaption: {serviceCaption}" +
                       $"\n\tBinary: {servicePathName}" +
                       $"\n\tStatus: {serviceState}" +
                       $"\n\tProcess ID: {servicePID}" +
                       $"\n\tFile Metadata: {metadata}" +
                       $"\n[!] Matched on: {string.Join(", ", matches)}\n");
                return $"\t{serviceName} : {string.Join(", ", matches)}\n";
            }
            return "";
        }
    }
}