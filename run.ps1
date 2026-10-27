$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$secretsPath = Join-Path $projectRoot ".env.local"
if (-not (Test-Path -LiteralPath $secretsPath)) {
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $jwtBytes = New-Object byte[] 32
        $encryptionBytes = New-Object byte[] 32
        $adminBytes = New-Object byte[] 24
        $random.GetBytes($jwtBytes)
        $random.GetBytes($encryptionBytes)
        $random.GetBytes($adminBytes)
    }
    finally {
        $random.Dispose()
    }

    $jwtSecret = [Convert]::ToBase64String($jwtBytes)
    $encryptionKey = [Convert]::ToBase64String($encryptionBytes)
    $adminPassword = ([Convert]::ToBase64String($adminBytes).TrimEnd("=") + "aA9!")
    @(
        "JWT_SECRET=$jwtSecret"
        "CREDENTIAL_ENCRYPTION_KEY=$encryptionKey"
        "ADMIN_USERNAME=admin"
        "ADMIN_PASSWORD=$adminPassword"
        "COOKIE_SECURE=false"
    ) | Set-Content -LiteralPath $secretsPath -Encoding Ascii
    Write-Output "Created persistent local secrets in .env.local (excluded from version control)."
}

foreach ($line in Get-Content -LiteralPath $secretsPath) {
    if ($line -match "^\s*([^#=]+)=(.*)$") {
        [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2], "Process")
    }
}

$mavenWrapper = Join-Path $projectRoot "mvnw.cmd"
if (Test-Path -LiteralPath $mavenWrapper) {
    & $mavenWrapper spring-boot:run
    exit $LASTEXITCODE
}

$maven = Get-Command mvn.cmd -ErrorAction SilentlyContinue
if (-not $maven) {
    $cachedMaven = Join-Path $HOME ".m2\wrapper\dists\apache-maven-3.9.9"
    if (Test-Path -LiteralPath $cachedMaven) {
        $maven = Get-ChildItem -LiteralPath $cachedMaven -Recurse -Filter mvn.cmd |
            Select-Object -First 1
    }
}
if (-not $maven) {
    throw "Maven 3.9+ is required. Install Maven or use the included Maven Wrapper."
}

& $maven.Source spring-boot:run
exit $LASTEXITCODE
