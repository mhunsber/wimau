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

## Attributions

Refactored into a module from Eric Siron's original script:

https://virtualizationdojo.com/hyper-v/free-powershell-script-use-wsus-update-installation-media-hyper-v-templates/
