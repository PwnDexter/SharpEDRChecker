using System;
using System.Diagnostics;
using System.IO;

namespace SharpEDRChecker
{
    class FileChecker
    {
        internal static string GetFileInfo(string filePath)
        {
            FileVersionInfo fileVersionInfo;
            try
            {
                fileVersionInfo = FileVersionInfo.GetVersionInfo(filePath);
                return $"\n \t\t Product Name: {fileVersionInfo.ProductName}" +
                    $"\n \t\t Filename: {fileVersionInfo.FileName}" +
                    $"\n \t\t Original Filename: {fileVersionInfo.OriginalFilename}" +
                    $"\n \t\t Internal Name: {fileVersionInfo.InternalName}" +
                    $"\n \t\t Company Name: {fileVersionInfo.CompanyName}" +
                    $"\n \t\t File Description: {fileVersionInfo.FileDescription}" +
                    $"\n \t\t Product Version: {fileVersionInfo.ProductVersion}" +
                    $"\n \t\t Comments: {fileVersionInfo.Comments}" +
                    $"\n \t\t Legal Copyright: {fileVersionInfo.LegalCopyright}" +
                    $"\n \t\t Legal Trademarks: {fileVersionInfo.LegalTrademarks}";
            }
            catch (FileNotFoundException)
            {
                if (filePath.ToLower().StartsWith(@"c:\windows\system32\"))
                {
                    filePath = filePath.ToLower().Replace(@"c:\windows\system32\", @"c:\Windows\Sysnative\");
                    return GetFileInfo(filePath);
                }
                else
                {
                    Console.WriteLine($"[!] Could not get file info for: {filePath}\n");
                    return "";
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting file info for: {filePath}\n{e.Message}\n{e.StackTrace}");
                return "";
            }
        }
    }
}