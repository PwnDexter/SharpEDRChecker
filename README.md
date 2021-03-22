# SharpEDRChecker

New and improved C# Implementation of [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker). Checks running processes, process metadata, Dlls loaded into your current process and each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools. Catches hidden EDRs as well via its metadata checks, more info can be found in my blog post [here](https://redteaming.co.uk/2021/03/18/sharpedrchecker/).

This binary can be loaded into your C2 server by loading the module then running it. Note: this binary is now included in [PoshC2](https://github.com/nettitude/PoshC2) so no need to manually add it.

I will continue to add and improve the list when time permits. A full roadmap can be found below.

Find me on twitter [@PwnDexter](https://twitter.com/PwnDexter) for any issues or questions!

## Install & Compile

Git clone the repo down and open the solution in Visual Studio then build the project or alternatively download the latest release from [here](https://github.com/PwnDexter/SharpEDRChecker/releases).

```
git clone https://github.com/PwnDexter/SharpEDRChecker.git
```

## Usage

Once the binary has been loaded onto your host or into your C2 of choice, you can use the following commands:

Run the binary against the local host and perform checks based on current user integrity:
```
.\SharpEDRChecker.exe
run-exe SharpEDRChecker.Program SharpEDRChecker
```

For use in PoshC2 ise the following:
```
sharpedrchecker
```

## Roadmap
- [ ] - Add more EDR Products - never ending
- [ ] - Test across more Windows and .NET versions
- [ ] - Add remote host query capability
- [ ] - Port to python for unix/macos support


## Example Output

Initial start down C2:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-start.png)

Processes:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-processes.png)

Modloads in your process:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-modload.png)

Directories:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-directories.png)

Services:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-services.png)

Drivers:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-drivers.png)

TLDR Summary:

![](https://github.com/PwnDexter/SharpEDRChecker/blob/master/Images/sdrc-tldr.png)
