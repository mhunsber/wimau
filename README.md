# Windows Image Automatic Updater

The Windows Image Automatic Updater (wimau) PowerShell Module extends the
DISM and UpdateServices modules to help service offline images.

## Install

wimau is published to PowerShell Gallery: https://www.powershellgallery.com/packages/wimau/

```ps1
Install-Module -Name wimau
```

## Example Uses

### Install updates from WSUS on an offline VHD file

Apply all approved updates from the system-defined WSUS server to a VHD file

```ps1
Sync-WindowsImage -Image '.\myImage.vhdx' -SystemWsusServer
```

![](https://github.com/mhunsber/wimau/blob/main/images/wimau-ex-sync-windowsimage-1.gif)

### Search for and download update files for a specific WSUS product

```ps1
$updates = Find-WsusUpdate -ProductTitle 'WsusProduct' -UpdateServer (Get-WsusServer -Name 'mywsus' -PortNumber 8530)

Get-WsusUpdateSelfContainedFile -WsusUpdate $updates -Path '.\download-path'
```

![](https://github.com/mhunsber/wimau/blob/main/images/wimau-ex-find-wsusupdate-1.gif)

## Using a different version of DISM

If you install DISM separately from the one shipped with Windows by default, you will need to manually import it and
ensure that the install location is in the `PATH` environment variable before running these commands.

```ps1
# EXAMPLE
$custom_dism_path = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM'
Import-Module $custom_dism_path
$env:Path = "$custom_dism_path;$env:PATH"
```

## Keeping Image size small

If you continously add packages to a windows image, the old updates will build up over time and the image size will grow. You'll want to run `Repair-WindowsImage -StartComponentCleanup -ResetBase` to remove these old updates.
The `Sync-WindowsImage` cmdlet automatically does this by calling `-RunUpdateCleanup` on `Update-WindowsImage`.

If your image is a dynamically expanding `.vhdx` file, you'll also want to optimize it.
The following function will reduce the size of the vhdx file. It is not included in the `wimau` module since
it requires the Hyper-V role.

```ps1
function Optimize-VirtualDrive ($Path) {
    $currentVHDSize = Get-Item -Path $Path | Select-Object -ExpandProperty Length
    Mount-VHD -Path $Path -NoDriveLetter
    $partitions = Get-VHD -Path $Path | Get-Disk | Get-Partition | Where-Object Type -EQ 'Basic'
    foreach($partition in $partitions) {
        $partition | Add-PartitionAccessPath -AssignDriveLetter
        $driveLetter = Get-Partition `
            -DiskNumber $partition.DiskNumber `
            -PartitionNumber $partition.PartitionNumber `
                | Select-Object -ExpandProperty DriveLetter

        # https://community.spiceworks.com/t/i-cannot-compact-vhdx-to-reclaim-space/766282/4
        Defrag.exe "${driveLetter}:" /X
        Defrag.exe "${driveLetter}:" /K /L
        Defrag.exe "${driveLetter}:" /X
        Defrag.exe "${driveLetter}:" /K
        $partition | Remove-PartitionAccessPath -AccessPath "${driveLetter}:"
    }
    Dismount-VHD -Path $Path
    Optimize-VHD -Path $Path -Mode Full
    $newVHDSize = Get-Item -Path $Path | Select-Object -ExpandProperty Length
    [PSCustomObject]@{
        Path = $Path
        PreviousSize = $currentVHDSize
        Size = $newVHDSize
        ReclaimedMB = ($currentVHDSize - $newVHDSize) / 1MB
    }
}
```

## Attributions

Refactored into a module from Eric Siron's original script:

https://virtualizationdojo.com/hyper-v/free-powershell-script-use-wsus-update-installation-media-hyper-v-templates/
