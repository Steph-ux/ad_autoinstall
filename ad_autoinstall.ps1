# === CONFIGURATION LOGGING ===
$logDir = "$PSScriptRoot\logs"
if (!(Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = "$logDir\ad-install-$timestamp.log"

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$time][$Level] $Message"
    Add-Content -Path $logFile -Value $entry
}

# === INSTALLATION DOMAINE + PROMOTION + DNS POST-PROMOTION + STRATEGIES GLOBALES ===
function Install-DomainController {
    Write-Host "`n🔹 Étape 1 : Installation du domaine AD + DNS + promotion contrôleur principal"
    if (Get-ADDomain -ErrorAction SilentlyContinue) {
        Write-Host "✅ Domaine déjà installé." -ForegroundColor Green
        Write-Log "Le domaine est déjà configuré."
        return
    }

    $domainName = Read-Host "Nom FQDN du domaine (ex: entreprise.local)"
    $netbios = Read-Host "Nom NetBIOS (ex: ENTREPRISE)"
    if ($netbios -match '[\"/\\\[\]:|<>+=;,?*]') {
        Write-Host "Le nom NetBIOS contient des caractères interdits." -ForegroundColor Red
        Write-Log "Nom NetBIOS invalide: $netbios" "ERROR"
        return
    }
    $dsrmPwd = Read-Host "Mot de passe DSRM (mode restauration)" -AsSecureString

    try {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        Write-Log "Rôle AD DS installé."
        Install-ADDSForest -DomainName $domainName -DomainNetbiosName $netbios -SafeModeAdministratorPassword $dsrmPwd -InstallDNS -Force
        Write-Log "Forêt $domainName créée avec succès."
        Write-Host "Installation terminée. Le serveur va redémarrer automatiquement."
    } catch {
        Write-Log "Erreur lors de l'installation domaine: $_" "ERROR"
        Write-Host "❌ Erreur : $_" -ForegroundColor Red
        return
    }

    # --- CONFIGURATION POST-PROMOTION DNS ---
    try {
        $domain = $domainName
        $zone = Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue
        if ($zone) {
            Write-Host "Zone DNS $domain déjà présente."
            Write-Log "Zone DNS $domain déjà présente."
        } else {
            Add-DnsServerPrimaryZone -Name $domain -ReplicationScope "Forest"
            Write-Log "Zone DNS $domain créée."
        }
    } catch {
        Write-Log "Erreur création zone DNS : $_" "ERROR"
    }

    try {
        $redirectors = Get-DnsServerForwarder
        if ($redirectors) {
            Write-Host "Redirecteurs DNS déjà configurés."
            Write-Log "Redirecteurs DNS déjà configurés."
        } else {
            Set-DnsServerForwarder -IPAddress 8.8.8.8,1.1.1.1 -UseRootHint $false
            Write-Log "Redirecteurs DNS configurés."
        }
    } catch {
        Write-Log "Erreur configuration redirecteurs DNS : $_" "ERROR"
    }

    # --- APPLICATION STRATEGIES GLOBALES ---
    Apply-SecurityPolicies
}

# === AJOUT SECOND CONTROLEUR DE DOMAINE ===
function Add-SecondDC {
    do {
        Clear-Host
        Write-Host "=== Ajout d'un second contrôleur de domaine (DC) ==="
        $serverName = Read-Host "Nom du serveur Windows (FQDN) où installer le second DC (`Q` pour quitter)"

        if ($serverName -eq 'Q' -or $serverName -eq 'q') {
            Write-Host "Retour au menu principal." -ForegroundColor Yellow
            return
        }
        if (-not $serverName) {
            Write-Host "Nom de serveur vide, réessayez." -ForegroundColor Red
            Start-Sleep -Seconds 2
            continue
        }

        Write-Host "Test ping vers $serverName..."
        if (-not (Test-Connection -ComputerName $serverName -Count 2 -Quiet)) {
            Write-Host "❌ Le serveur $serverName n'est pas joignable par ping. Vérifiez le nom ou la connexion." -ForegroundColor Red
            Write-Log "Ping échoué vers $serverName"
            Start-Sleep -Seconds 3
            continue
        }
        Write-Host "Ping OK."

        Write-Host "Test WinRM sur $serverName..."
        try {
            Test-WSMan -ComputerName $serverName -ErrorAction Stop | Out-Null
            Write-Host "Connexion WinRM OK."
        } catch {
            Write-Host "❌ WinRM non disponible sur $serverName." -ForegroundColor Red
            Write-Log "WinRM indisponible sur $serverName"
            Start-Sleep -Seconds 3
            continue
        }

        $scriptCheckDC = {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $isDC = (Get-ADDomainController -Filter { HostName -eq $env:COMPUTERNAME }) -ne $null
                return $isDC
            } catch { return $false }
        }
        try {
            $isAlreadyDC = Invoke-Command -ComputerName $serverName -ScriptBlock $scriptCheckDC -ErrorAction Stop
        } catch {
            Write-Host "❌ Impossible de vérifier si $serverName est déjà DC : $_" -ForegroundColor Red
            Write-Log "Erreur vérification DC sur $serverName : $_"
            Start-Sleep -Seconds 3
            continue
        }

        if ($isAlreadyDC) {
            Write-Host "✅ Le serveur $serverName est déjà un contrôleur de domaine." -ForegroundColor Green
            Write-Log "$serverName est déjà un DC."
            Start-Sleep -Seconds 2
            return
        }

        $safeModePwd = Read-Host -AsSecureString "Mot de passe DSRM (mode restauration) pour ce DC"

        $scriptBlock = {
            param ($DomainName, $SafeModePwd)
            Import-Module ServerManager, ADDSDeployment
            Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
            Install-ADDSDomainController `
                -DomainName $DomainName `
                -InstallDns `
                -SafeModeAdministratorPassword $SafeModePwd `
                -Force:$true `
                -NoRebootOnCompletion:$false
        }

        $domain = (Get-ADDomain).DNSRoot

        Write-Host "Déploiement du contrôleur de domaine distant sur $serverName ..."
        Write-Log "Déploiement second DC sur $serverName"

        try {
            Invoke-Command -ComputerName $serverName -ScriptBlock $scriptBlock -ArgumentList $domain, $safeModePwd -ErrorAction Stop
            Write-Host "✅ Installation et promotion terminées sur $serverName. Le serveur redémarrera." -ForegroundColor Green
            Write-Log "Installation et promotion terminées sur $serverName."
            return
        } catch {
            Write-Host "❌ Erreur d'installation sur $serverName : $_" -ForegroundColor Red
            Write-Log "Erreur installation second DC sur $serverName : $_" "ERROR"
            Start-Sleep -Seconds 3
        }
    } while ($true)
}

# === CREATION GPOs SPECIFIQUES AVEC CHOIX GROUPE + APPLICATION STRATEGIES LIEES ===
function Create-SpecificGPOs {
    Write-Host "`n=== Création de GPOs spécifiques avec liaison à un groupe AD ==="
    $applyGPO = Read-Host "Voulez-vous créer des GPOs spécifiques? (O/N)"
    if ($applyGPO.ToUpper() -ne "O") { return }

    $groupName = Read-Host "Nom du groupe AD (groupe de sécurité) auquel appliquer ces GPOs"
    if (-not (Get-ADGroup -Filter {Name -eq $groupName} -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Le groupe '$groupName' n'existe pas dans AD." -ForegroundColor Red
        Write-Log "Groupe AD '$groupName' introuvable."
        return
    }
    Write-Log "Création GPOs et liaison au groupe $groupName"

    # Exemple de GPOs
    $gpoUsbName = "GPO - Désactivation USB"
    $gpoPanneauConfigName = "GPO - Blocage Panneau de configuration"

    # Création GPO désactivation USB
    $gpoUsb = Get-GPO -Name $gpoUsbName -ErrorAction SilentlyContinue
    if (-not $gpoUsb) {
        $gpoUsb = New-GPO -Name $gpoUsbName
        Write-Log "GPO $gpoUsbName créé."
    }
    Set-GPRegistryValue -Name $gpoUsbName -Key "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" -ValueName "Start" -Type DWord -Value 4
    Write-Log "Paramètre USB désactivé dans $gpoUsbName."

    # Création GPO blocage panneau de config
    $gpoPC = Get-GPO -Name $gpoPanneauConfigName -ErrorAction SilentlyContinue
    if (-not $gpoPC) {
        $gpoPC = New-GPO -Name $gpoPanneauConfigName
        Write-Log "GPO $gpoPanneauConfigName créé."
    }
    Set-GPRegistryValue -Name $gpoPanneauConfigName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1
    Write-Log "Paramètre blocage panneau de config appliqué dans $gpoPanneauConfigName."

    # Liaison GPOs au groupe cible via filtre sécurité
    $gpos = @($gpoUsb, $gpoPC)
    foreach ($gpo in $gpos) {
        try {
            # Lier GPO à la racine de domaine
            $domainDN = (Get-ADDomain).DistinguishedName
            New-GPLink -Name $gpo.DisplayName -Target "DC=$($domainDN -replace ',','',1)" -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
            # Appliquer filtre sécurité
            Set-GPPermission -Name $gpo.DisplayName -TargetName $groupName -TargetType Group -PermissionLevel GpoApply
            Write-Log "Liaison et filtre de sécurité appliqués sur GPO $($gpo.DisplayName) pour groupe $groupName"
        } catch {
            Write-Log "Erreur liaison GPO $($gpo.DisplayName) : $_" "ERROR"
        }
    }
    Write-Host "✅ Création et liaison des GPOs terminées."

    # Optionnel : appliquer stratégies spécifiques (ex: forcer mise à jour GPOs)
    gpupdate /force | Out-Null
    Write-Log "gpupdate /force lancé après création GPOs."
}

# === APPLICATION STRATEGIES DE SECURITE GLOBALES ===
function Apply-SecurityPolicies {
    Write-Host "`n🔹 Étape 4 : Application de stratégies de sécurité globale"

    $infFile = "$env:TEMP\ad-security.inf"
    $sdbFile = "$env:TEMP\ad-security.sdb"
    $logFileSecedit = "$env:TEMP\secedit.log"

    $infContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 8
PasswordComplexity = 1
[Event Audit]
AuditSystemEvents = 1
AuditLogonEvents = 1
[Security Options]
ShutdownWithoutLogon = 0
"@

    Set-Content -Path $infFile -Value $infContent -Encoding Unicode

    try {
        $proc = Start-Process -FilePath secedit -ArgumentList "/configure /db $sdbFile /cfg $infFile /overwrite /log $logFileSecedit /quiet" -Wait -PassThru -NoNewWindow

        if ($proc.ExitCode -eq 0) {
            Write-Log "Stratégies de sécurité locales appliquées avec succès."
            Write-Host "Stratégies appliquées."
        } else {
            Write-Host "Erreur lors de l'application des stratégies. Code de sortie : $($proc.ExitCode)" -ForegroundColor Red
            Write-Log "Erreur secedit, code de sortie : $($proc.ExitCode)" "ERROR"
            if (Test-Path $logFileSecedit) {
                Write-Host "Contenu du fichier de log secedit :" -ForegroundColor Yellow
                Get-Content $logFileSecedit | ForEach-Object { Write-Host $_ }
            }
        }
    } catch {
        Write-Log "Exception lors de l'exécution de secedit : $_" "ERROR"
        Write-Host "Exception lors de l'application des stratégies : $_" -ForegroundColor Red
    }
}


# === MENU PRINCIPAL ===
function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "==== MENU D'ADMINISTRATION DOMAINE ====" -ForegroundColor Cyan
        Write-Host "1. Installer domaine AD + DNS + promotion contrôleur principal + config DNS + stratégies globales"
        Write-Host "2. Ajouter un second contrôleur de domaine (DC)"
        Write-Host "3. Créer des GPOs spécifiques et les lier à un groupe"
        Write-Host "4. Appliquer stratégies de sécurité globale"
        Write-Host "5. Quitter"
        $choice = Read-Host "Choisissez une option"

        if ($choice -eq '5') {
            Write-Log "Fin du script"
            Write-Host "Sortie du script."
            break  # Sort de la boucle do…while et donc termine la fonction
        }

        switch ($choice) {
            '1' { Install-DomainController }
            '2' { Add-SecondDC }
            '3' { Create-SpecificGPOs }
            '4' { Apply-SecurityPolicies }
            default { Write-Host "Option invalide." -ForegroundColor Red }
        }

        Write-Host "`nAppuyez sur une touche pour continuer..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

    } while ($true)
}


# === POINT D'ENTREE ===
Write-Log "Début du script PowerShell d'administration AD."
Show-MainMenu
