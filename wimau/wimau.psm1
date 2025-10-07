#requires -RunAsAdministrator
#requires -Version 5
#requires -Module @{ ModuleName = 'UpdateServices'; ModuleVersion = '2.0.0.0' }
#requires -Module @{ ModuleName = 'DISM'; ModuleVersion = '3.0' }

<#
.SYNOPSIS
	Syncs offline WIM or VHDX windows images with update packages approved in WSUS.
.DESCRIPTION
	Syncs offline WIM or VHDX windows images with update packages approved in WSUS.
	Can update one or all indexes in a WIM.
.PARAMETER Image
	An array of paths to the images to be updated. Each item in the array can either be a string to the image path, or a hashtable with Path and Index keys for WIM images.
	The Index key specifies which image index(es) to use when an image file has multiple images. VHDX files must always use and index of 1.
	When no Index is specified, the default is -1 which will update all images.
.PARAMETER WsusServerName
	A resolvable name or IP address of the computer that runs WSUS.
.PARAMETER WsusServerPort
	The port that WSUS responds on. Defaults to 8530.
.PARAMETER WsusUsesSSL
	Flag if you should connect to WSUS using SSL. Default is to not use SSL.
.PARAMETER SystemWsusServer
	Use the WSUS server configured via the registry on the current system.
.PARAMETER LocalWsusServer
	Use the WSUS server installed on the current system.
.PARAMETER LocalUpdateCache
	The path to cached update files. This speeds up successive runs by not requiring a download from the WSUS server.
.PARAMETER MinimumPatchAgeInDays
	The minimum number of days since a patch appeared on the WSUS host before it can be applied. Default is 0.
.PARAMETER IgnoreDeclinedStatus
	If specified, updates that appear as both Approved and Declined will be applied (meaning the update is approved in at least one location even though it is declined in another).
	If not specified, an update that is declined anywhere on the WSUS host will be not be applied.
.LINK
	Originally written by Eric Siron, 2016 Altaro Software: https://virtualizationdojo.com/hyper-v/free-powershell-script-use-wsus-update-installation-media-hyper-v-templates/
.EXAMPLE
	Sync-WindowsImage -Image D:\Templates\w2k12r2template.vhdx -LocalWsusServer

	Updates the specified VHDX using the local WSUS server.
.EXAMPLE
	Sync-WindowsImage -Image @{ Path = 'D:\FromISO\2k12r2install.wim'; Index=1 } -SystemWsusServer

	Updates the first image within the specified WIM using the WSUS server configured for the current system.
.EXAMPLE
	$Images = @(
		@{'Path'='D:\FromISOw2k12r2install.wim'; 'Index' = 1},
		@('Path'='D:\FromISOw2k12r2install.wim'; 'Index' = 2),
		@{'Path'='D:\Templatesw2k12r2.vhdx'},
		@{'Path'='D:\FromISOhs2k12r2install.wim'; 'Index' = 1}
	)
	Sync-WindowsImage -Image $Images -WsusServerName 192.168.1.3

	Updates all of the specified images using the WSUS server running on 192.168.1.3.
#>
function Sync-WindowsImage {
	[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='ExplicitSource')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
		[array]$Image,

		[Parameter(ParameterSetName='ExplicitSource', Mandatory)]
		[String]$WsusServerName,

		[Alias('Port')]
		[Parameter(ParameterSetName='ExplicitSource')]
		[UInt16]$WsusServerPort = 8530,

		[Alias('SSL', 'WithSSL')]
		[Parameter(ParameterSetName='ExplicitSource')]
		[Switch]$WsusUsesSSL,

		[Parameter(ParameterSetName='ImplicitSource')]
		[switch]$SystemWsusServer,

		[Parameter(ParameterSetName='LocalSource')]
		[switch]$LocalWsusServer,

		[Parameter()]
		[String]$LocalUpdateCache = "$env:ProgramData\WindowsOfflineUpdates",

		[Parameter()]
		[UInt16]$MinimumPatchAgeInDays = 0,

		[Parameter()]
		[Switch]$IgnoreDeclinedStatus
	)

	begin {
		$ImageList = [System.Collections.Generic.List`1[PSCustomObject]]@()
		try {
			if ($LocalWsusServer) {
				$WsusServer = Get-WsusServer
			}
			elseif ($SystemWsusServer) {
				[uri]$systemWsusUri = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate').WUServer
				$WsusServer = Get-WsusServer -Name $systemWsusUri.Host -PortNumber $systemWsusUri.Port -UseSsl:($systemWsusUri.Scheme -eq 'https')
			}
			else {
				$WsusServer = Get-WsusServer -Name $WsusServerName -PortNumber $WsusServerPort -UseSsl:$WsusUsesSSL
			}
		}
		catch {
			$PSCmdlet.ThrowTerminatingError($PSItem)
		}
	}

	process {
		$ImageList.AddRange(
			[System.Collections.Generic.List`1[PSCustomObject]](
				Find-WindowsImage -Path $Image
			)
		)
	}

	end {
		$TargetProduct = $ImageList | Select-Object -ExpandProperty ImageProduct -Unique
		if ($null -eq $TargetProduct) {
			$PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
				([System.NotSupportedException]"Nothing to update - there were no applicable product titles found in $($ImageList.Count) images."),
				'Sync-WindowsImage',
				[System.Management.Automation.ErrorCategory]::InvalidData,
				$ImageList
			))
		}
		Write-Verbose -Message ('List of applicable product titles: {0}' -f ($TargetProduct -join ', '))

		$WsusUpdates = Find-WsusUpdate -UpdateServer $WsusServer -ProductTitle $TargetProduct -MinimumPatchAgeInDays $MinimumPatchAgeInDays -IgnoreDeclinedStatus:$IgnoreDeclinedStatus
		Write-Verbose -Message ('Updates Found: {0}' -f $WsusUpdates.Count)

		$UpdateFiles = Get-WsusUpdateSelfContainedFile -WsusUpdate $WsusUpdates -Path $LocalUpdateCache
		Write-Verbose -Message ('Eligible patches: {0}' -f $UpdateFiles.Count)

		for($i = 0; $i -lt $ImageList.Count; $i++) {
			$imageToUpdate = $ImageList[$i]
			Write-Progress -Activity 'Sync-WindowsImage' `
					-Status "Applying updates to image $($i + 1) of $($ImageList.Count)." `
					-CurrentOperation "$($imageToUpdate.ImagePath), $($imageToUpdate.ImageIndex) ($($imageToUpdate.ImageProduct))" `
					-PercentComplete (100 * ($i / $ImageList.Count)) `
					-Id 1

			Update-WindowsImage `
				-ImagePath $imageToUpdate.ImagePath `
				-ImageIndex $imageToUpdate.ImageIndex `
				-UpdateFile ($UpdateFiles | Where-Object {
					(Compare-Object -DifferenceObject $_.Product -ReferenceObject $imageToUpdate.ImageProduct -ExcludeDifferent -IncludeEqual)
				}) `
				-RunUpdateCleanup
		}
		Write-Progress -Activity 'Sync-WindowsImage' -Completed -Id 1
	}
}

<#
.SYNOPSIS
	Installs update package files to an offline Windows image in a WIM or VHD file.
.DESCRIPTION
	Installs update package files to an offline Windows image in a WIM or VHD file.
.PARAMETER ImagePath
	Specifies the location of a WIM or VHD file.
.PARAMETER ImageIndex
	Specifies the index number of a Windows image in a WIM or VHD file. For a VHD file, the Index must be 1.
.PARAMETER UpdateFile
	Specifies the update files to install to the Windows image. Parameter expects an object with the following properties:
		Path - The path to the update file
		Title(optional) - Title of the update
		Product(optional) - Product(s) for which the update applies
.PARAMETER RunUpdateCleanup
	Windows keeps copies of all installed updates from Windows Update, even after installing newer versions of updates.
	RunUpdateCleanup will delete or compress older versions of updates that are no longer needed and taking up space.
.NOTES
	Running with -WhatIf *will* still create and remove a temporary mount directory. However, after applying packages, the
	mounted image will be dismounted with the -Discard option, which does not save any of the changes.
.EXAMPLE
	Update-WindowsImage -ImagePath 'myimage.wim' -ImageIndex 5 -UpdateFile @{ Path = 'update1.cab' }, @{ Path = 'update2.cab' }
	Installs update1 and update2 packages to the windows image.
.EXAMPLE
	Update-WindowsImage -ImagePath 'myimage.wim' -ImageIndex 5 -UpdateFile @{ Path = 'update1.cab' } -RunUpdateCleanup
	Installs update1 to the windows image, then performs the windows update cleanup process.
#>
function Update-WindowsImage {
	[CmdletBinding(SupportsShouldProcess)]
	param (
		[Parameter(Mandatory)]
		[String]$ImagePath,

		[Parameter(Mandatory)]
		[int]$ImageIndex,

		[Parameter(Mandatory,ValueFromPipeline)]
		[PSCustomObject[]]$UpdateFile,

		[switch]$RunUpdateCleanup
	)

	begin {
		$allUpdateFiles = [System.Collections.Generic.List`1[PSCustomObject]]@()

		$mountPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
		New-Item -Path $mountPath -ItemType Directory -Force -WhatIf:$false | Out-Null
	}

	process {
		$allUpdateFiles.AddRange($UpdateFile)
	}

	end {
		try {
			Mount-WindowsImage -ImagePath $ImagePath -Index $ImageIndex -Path $mountPath | Out-Null
			for($i = 0; $i -lt $allUpdateFiles.Count; $i++) {
				try {
					$packageFile = $allUpdateFiles[$i]
					Write-Progress -Activity 'Update-WindowsImage' `
						-Status "Applying update package $($i + 1) of $($allUpdateFiles.Count)" `
						-CurrentOperation $packageFile.Title `
						-PercentComplete (100 * ($i / $allUpdateFiles.Count))

					$packageStatus = Get-WindowsPackage -PackagePath $packageFile.Path -Path $mountPath

					if (-not $packageStatus.Applicable) {
						Write-Warning -Message "Skipping $($packageFile.Title) - package is not applicable"
						continue
					}

					if ($packageStatus.PackageState -eq [Microsoft.Dism.Commands.PackageFeatureState]::Installed) {
						Write-Warning -Message "Skipping $($packageFile.Title) - package already installed on $($packageStatus.InstallTime)"
						continue
					}

					Add-WindowsPackage -PackagePath $packageFile.Path -Path $mountPath | Out-Null
				}
				catch {
					# Add-WindowsPackage will throw terminating errors when in a try block, even when ErrorAction is set to Continue.
					# This just re-writes the error without jumping to the catch block so we can continue with the rest of the list.
					Write-Error -Message "Failed to add update $($packageFile.Title) at $($packageFile.Path) to $ImagePath, $ImageIndex - $_" -ErrorAction Continue
				}
			}

			if ($RunUpdateCleanup) {
				Repair-WindowsImage -Path $mountPath -StartComponentCleanup -ResetBase | Out-Null
			}
		}
		catch {
			$PSCmdlet.ThrowTerminatingError($PSItem)
		}
		finally {
			if (Get-WindowsImage -Mounted | Where-Object Path -EQ $mountPath) {
				if ($PSCmdlet.ShouldProcess("$ImagePath, $ImageIndex", "Update-WindowsImage")) {
					$action = 'Save'
				}
				else {
					$action = 'Discard'
				}
				$dismountParams = @{
					Path = $mountPath
					$action = $true
				}
				Dismount-WindowsImage @dismountParams | Out-Null
			}

			if (Test-Path -Path $mountPath) {
				Remove-Item -Path $mountPath -Force -Recurse -WhatIf:$false
			}
		}
	}
}

<#
.SYNOPSIS
	Finds applicable WSUS updates
.DESCRIPTION
	Find applicable WSUS updates
	Find approved, unsusperseded updates in WSUS for a list of product titles
.PARAMETER UpdateServer
	The WsusServer on which to search for updates
.PARAMETER ProductTitle
	A list of Product titles for which to search for updates.
	Use Get-WsusProduct to get the full list of valid options.
.PARAMETER MinimumPatchAgeInDays
	The minimum number of days since a patch appeared on the WSUS host before it can be applied. Default is 0.
.PARAMETER IgnoreDeclinedStatus
	If specified, updates that appear as both Approved and Declined will be applied (meaning the update is approved in at least one location even though it is declined in another).
	If not specified, an update that is declined anywhere on the WSUS host will be not be applied.
#>
function Find-WsusUpdate {
	[OutputType([Microsoft.UpdateServices.Administration.IUpdate])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[Microsoft.UpdateServices.Administration.IUpdateServer]$UpdateServer,

		[Parameter(Mandatory, ValueFromPipeline)]
		[string[]]$ProductTitle,

		[Parameter()]
		[UInt16]$MinimumPatchAgeInDays = 0,

		[Parameter()]
		[switch]$IgnoreDeclinedStatus
	)

	begin {
		Write-Progress -Activity 'Find-WsusUpdate' -Status 'Scanning for applicable updates' -PercentComplete 0
		$WSUSUpdates = $UpdateServer.GetUpdates('LatestRevisionApproved', [DateTime]::MinValue, [DateTime]::MaxValue, $Null, $Null)
		Write-Verbose -Message "Approved Updates: $($WSUSUpdates.Count)"

		Write-Progress -Activity 'Find-WsusUpdate' -Status 'Filtering out declined updates' -PercentComplete 50
		$WSUSUpdates = $WSUSUpdates | Where-Object { $IgnoreDeclinedStatus -or -not $_.IsDeclined }
		Write-Verbose -Message "Approved (not declined) Updates: $($WSUSUpdates.Count)"

		Write-Progress -Activity 'Find-WsusUpdate' -Status "Filtering out updates that are newer than $MininumPatchAgeInDays days" -PercentComplete 99
		$WSUSUpdates = $WSUSUpdates | Where-Object { $_.ArrivalDate.ToLocalTime().AddDays($MinimumPatchAgeInDays) -le [datetime]::Now }
		Write-Verbose -Message "Updates within arrival time: $($WSUSUpdates.Count)"

		$totalUpdatesFound = 0
	}

	process {
		Write-Progress -Activity 'Find-WsusUpdate' -Status "Filtering to ProductTiles in $($ProductTitle -join ', ')" -PercentComplete 0
		$applicableUpdates = $WSUSUpdates | Where-Object {
			(Compare-Object -DifferenceObject $_.ProductTitles -ReferenceObject $ProductTitle -ExcludeDifferent -IncludeEqual)
		}
		Write-Verbose -Message "Updates applicable to ProductTitles: $($applicableUpdates.Count)"
		Write-Progress -Activity 'Find-WsusUpdate' -Status "Filtering out superseded updates from $($applicableUpdates.Count) total updates" -PercentComplete 50
		for($i = 0; $i -lt $applicableUpdates.Count; $i++) {
			$update = $applicableUpdates[$i]
			Write-Progress -Activity 'Find-WsusUpdate' `
				-Status "Filtering out superseded updates" `
				-CurrentOperation $update.Title `
				-PercentComplete (100 * ($i / $applicableUpdates.Count))

			if (-not $update.IsSuperseded) {
				$update
				$totalUpdatesFound++
			}
			else {
				$supersedingUpdates = $update.GetRelatedUpdates('UpdatesThatSupersedeThisUpdate')
				$approvedSupersedingUpdates = $supersedingUpdates | Where-Object { $_.IsApproved }
				if ($approvedSupersedingUpdates.Count -le 0) {
					$update
					$totalUpdatesFound++
				}
			}
		}
	}

	end {
		Write-Verbose -Message ('Found {0} total updates' -f $totalUpdatesFound)
		Write-Progress -Activity 'Find-WsusUpdate' -Completed
	}
}

<#
.SYNOPSIS
	Downloads self-contained update files locally
.DESCRIPTION
	Downloads self-contained update files locally
	If this is ran on a Wsus server, it only finds it on the local file system
.PARAMETER WsusUpdate
	The list of Wsus Updates to download
.PARAMETER Path
	Where to store the self-contained files.
	If the directory does not exist, it will be created.
	The default is the current directory.
.NOTES
	This function requires curl.exe be installed.
	This is preinstalled on windows since Windows 10 (version 1803) and Server 2019
#>
function Get-WsusUpdateSelfContainedFile {
	[OutputType([PSCustomObject])]
	[CmdletBinding(SupportsShouldProcess)]
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Microsoft.UpdateServices.Administration.IUpdate[]]$WsusUpdate,

		[string]$Path = $PWD.Path
	)

	begin {
		$userAgent = "$(curl.exe --version | Select-Object -First 1) poshWUClient"
		try {
			if ($PSCmdlet.ShouldProcess($Path, "Create Download Directory")) {
				$downloadDirectory = (New-Item -Path $Path -ItemType Directory -Force)
			}
			else {
				$downloadDirectory = [System.IO.DirectoryInfo]$Path
			}
		}
		catch {
			$PSCmdlet.ThrowTerminatingError($PSItem)
		}
	}

	process {
		for ($i = 0; $i -lt $WsusUpdate.Length; $i++) {
			$currentUpdate = $WsusUpdate[$i]
			Write-Progress -Activity 'Get-WsusUpdateSelfContainedFile' `
				-Status "Finding package files for update $($i + 1) of $($WsusUpdate.Length)." `
				-CurrentOperation "$($currentUpdate.Title)" `
				-PercentComplete (100 * ($i / $WsusUpdate.Length))

			$updateServerConfiguration = $currentUpdate.UpdateServer.GetConfiguration()
			$localContentCachePath = $updateServerConfiguration
			$currentUpdate.GetInstallableItems().Files | Where-Object {
				($_.Type -eq [Microsoft.UpdateServices.Administration.FileType]::SelfContained) -and `
				($_.FileUri -match '[cab|msu]$')
			} | ForEach-Object {
				$downloadSkipped = $false
				if (-not $updateServerConfiguration.HostBinariesOnMicrosoftUpdate -and $currentUpdate.UpdateServer.IsServerLocal) {
					# This is a local update and we do not have to download it
					$updateFilePath = ($_.FileUri -replace '.*/Content', $localContentCachePath) -replace '/', '\'
				}
				else {
					$updateFilePath = [System.IO.Path]::Combine($downloadDirectory, $_.FileUri.Segments[-1])
					if (-not (Test-Path -Path $updateFilePath)) {
						if ($PSCmdlet.ShouldProcess($_.FileUri, "Download File")) {
							curl.exe -fsSL -o $updateFilePath -A $userAgent $_.FileUri
						}
						else {
							$downloadSkipped = $true
						}
					} # else it is cached already

					if (Test-Path -Path $updateFilePath) {
						[PSCustomObject]@{
							Path    = $updateFilePath
							Title   = $currentUpdate.Title
							Product = $currentUpdate.ProductTitles
						}
					}
					elseif ($downloadSkipped) {
						Write-Warning -Message "$($currentUpdate.Title) - User skipped download of $($_.FileUri)"
					}
					else {
						Write-Error -Message "$($currentUpdate.Title) - Cannot find installable item at $updateFilePath."
					}
				}
			}
		}
		Write-Progress -Activity 'Get-WsusUpdateSelfContainedFile' `
			-Status "Finding Update files for $($WsusUpdate.Length) updates" `
			-Completed
	}
}

<#
.SYNOPSIS
	Finds valid Windows offline Images
.DESCRIPTION
	Find valid Windows offline Images.
	Returns the path, index, and a Product Title suitable for WSUS filtering.
.PARAMETER Path
	An array of paths to the VHDX or WIM images to be updated. Each item in the array can either be a string to the image path, or a hashtable with Path and Index keys.
	The Index key specifies which image index(es) to use when an image file has multiple images.
	When no Index is specified, the default is -1 which will update all images
#>
function Find-WindowsImage {
	[OutputType([PSCustomObject])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory,ValueFromPipeline)]
		[array]$Path
	)

	process {
		Write-Progress -Activity 'Find-WindowsImage' -Status 'Expand paths' -PercentComplete 0
		# Step 1: Expand array of paths (some wildcard) to array of (full) file paths
		$ImageLocations = $Path | ForEach-Object {
			if ($_ -is [string]) {
				$imagePath = $_
				$imageIndex = -1
			}
			else {
				$imagePath = $item.Path
				$imageIndex = $item.Index
			}
			Write-Verbose -Message ('Getting list of image files from "{0}"' -f $imagePath)
			Get-Item -Path $imagePath -ErrorAction Ignore | Where-Object {
				$_.Extension -in '.vhd','.vhdx','.wim'
			} | ForEach-Object {
				[PSCustomObject]@{ ImagePath = $_.FullName; ImageIndex = $imageIndex }
			}
		}

		Write-Progress -Activity 'Find-WindowsImage' -Status 'Find valid images' -PercentComplete 33
		# Step 2: filter out invalid images and expand Image Indexes to individual array items
		$ImageLocations = $ImageLocations | Foreach-Object {
			Write-Verbose -Message ('Getting Windows Image(s) for "{0}"' -f $_.ImagePath)
			$Images = Get-WindowsImage -ImagePath $_.ImagePath -ErrorAction SilentlyContinue
			if ($null -ne $Images) {
				if ($_.ImagePath -imatch '\.vhdx?$') {
					# VHD(X) files are always just 1 image at index 1, and we'll ignore the user's specification since its irrelevant
					[PSCustomObject]@{
						ImagePath = $_.ImagePath
						ImageIndex = 1
					}
				}
				else {
					foreach($image in $Images) {
						if ($_.Index -eq -1) {
							# They want all of them
							[PSCustomObject]@{
								ImagePath = $_.FullName
								ImageIndex = $image.ImageIndex
							}
						}
						elseif ($_.Index -contains $image.ImageIndex) {
							# They've specifically selected this index
							[PSCustomObject]@{
								ImagePath = $_.FullName
								ImageIndex = $image.ImageIndex
							}
						}
					}
				}
			}
			else {
				Write-Warning -Message ('SKIPPING PATH "{0}" - Error getting Windows Image(s) - {1}' -f $_.FullName, $GetImageError)
			}
		}

		Write-Progress -Activity 'Find-WindowsImage' -Status 'Determining Product Titles' -PercentComplete 67
		$ImageLocations | ForEach-Object {
			[PSCustomObject]@{
				ImagePath = $_.ImagePath
				ImageIndex = $_.ImageIndex
				ImageProduct = Get-WindowsImageProduct -ImagePath $_.ImagePath -ImageIndex $_.ImageIndex
			}
		}
	}
}

<#
.SYNOPSIS
	Gets the Windows Product Title of an offline Windows Image
.DESCRIPTION
	Gets the Windows Product Title of an offline Windows Image
	Uses the HKLM:\Software\Microsoft\Windows NT\CurrentVersion registry key to determine the image product name
	Matches the image product name to a dictionary of WSUS Product Titles
.PARAMETER ImagePath
	The File path to the offline image
.PARAMETER ImageIndex
	The index of the Windows Image (vhdx files must use an index of 1)
.NOTES
	This function will try to determine a matching WSUS Product Title for an image based on the value of
		[HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion]>ProductName
	for the saved image. It will find the Key in a dictionary (defined in this function) that most closely matches* the ProductName registry value,
	then use the value of that key as the Wsus Product Title.

	*most closely matches means the "longest key that matches the start of the ProductName". For example, the ProductName
	may be "Windows Server 2022 Standard", so the matching key would be "Windows Server 2022", since the ProductName starts
	with "Windows Server 2022"
#>
function Get-WindowsImageProduct {
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$ImagePath,
		[Parameter(Mandatory)]
		[Int]$ImageIndex
	)

	begin {
		$SoftwareIniPath = "Windows\System32\config\SOFTWARE"
		$NTCurrentVersionRegPath = "Microsoft\Windows NT\CurrentVersion"
		$OSProductTitles = @{
			"Windows 7" = "Windows 7"
			"Windows Server 2008 R2" = "Windows Server 2008 R2"
			"Windows Server 2003" = "Windows Server 2003"
			"Windows Server 2008" = "Windows Server 2008"
			"Windows XP x64 Edition" = "Windows XP x64 Edition"
			"Windows Server 2012 R2" = "Windows Server 2012 R2"
			"Windows 8.1" = "Windows 8.1"
			"Windows 8" = "Windows 8"
			"Windows Server 2012" = "Windows Server 2012"
			"Windows Server 2019" = "Windows Server 2019"
			"Windows Server 2016" = "Windows Server 2016"
			"Windows 10" = "Windows 10"
			"Windows 11" = "Windows 11"
			"Windows Server 2022" = "Microsoft Server operating system-21H2"
			<#
				If you need to add to this list, find out the ProductName of the image you want to update, and then determine the value of the
				"ProductTitles" field you need to map to for that operating system.
			#>
		}
	}

	process {
		$randomName = [System.IO.Path]::GetRandomFileName()
		$fileMountPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $randomName)
		$regMountPath = "HKLM\$randomName"
		$regMountPathPS = "HKLM:\$randomName"

		New-Item -Path $fileMountPath -ItemType Directory -Force | Out-Null
		try {
			Write-Verbose -Message ('Determining Product information for "{0}", index "{1}"' -f $ImagePath, $ImageIndex)
			if (Test-Path -Path $regMountPathPS) {
				reg unload $regMountPath | Out-Null
			}

			Mount-WindowsImage -Path $fileMountPath -ImagePath $ImagePath -Index $ImageIndex | Out-Null

			if (-not (Test-Path "$fileMountPath\$SoftwareIniPath")) {
				Write-Warning -Message ('Unable to load the registry hive at "{2}" for "{0}", index "{1}"' -f $ImagePath, $ImageIndex, $SoftwareIniPath)
				return $null
			}

			reg load $regMountPath "$fileMountPath\$SoftwareIniPath" | Out-Null
			$imageProductName = (Get-ItemProperty -Path "$regMountPathPS\$NTCurrentVersionRegPath" -ErrorAction Ignore).ProductName

			if ([string]::IsNullOrEmpty($imageProductName)) {
				Write-Warning -Message ('Unable to determine NT ProductName for "{0}", index "{1}"' -f $ImagePath, $ImageIndex)
				return $null
			}

			# Find the longest Key that matches the start of the image product name
			$matchingProductName = $OSProductTitles.Keys | Where-Object {
				$imageProductName.StartsWith($_)
			} | Sort-Object -Property { $_.Length } -Descending | Select-Object -First 1

			if ([string]::IsNullOrEmpty($matchingProductName)) {
				Write-Warning -Message ('Unable to match "{2}" with a Product Title for "{0}", index "{1}"' -f $ImagePath, $ImageIndex, $imageProductName)
				return $null
			}

			return $OSProductTitles[$matchingProductName]
		}
		catch {
			Write-Warning -Message "$_"
		}
		finally {
			reg unload $regMountPath | Out-Null
			Dismount-WindowsImage -Path $fileMountPath -Discard -ErrorAction Continue | Out-Null
			Remove-Item -Path $fileMountPath -Recurse -Force -ErrorAction Continue
		}
	}
}
