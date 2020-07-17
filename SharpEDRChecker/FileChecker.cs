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
            catch (FileNotFoundException e)
            {
                if (filePath.ToLower().StartsWith(@"c:\windows\system32\"))
                {
                    filePath = filePath.ToLower().Replace(@"c:\windows\system32\", @"C:\Windows\Sysnative\");
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
                    catch (FileNotFoundException ee)
                    {
                        Console.Write($"Cant Find File: {ee}");
                    }
                }
                else
                {
                    return e.Message;
                }
            }
            return null;
        }
    }
}
