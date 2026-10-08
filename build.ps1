param([switch]$Test)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $jarTool = Get-Command jar -ErrorAction SilentlyContinue
    if ($jarTool) { $jarExe = $jarTool.Source }
    else {
        # Oracle's Windows javapath shim exposes javac but often omits jar.
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $javaSettings = (& java -XshowSettings:properties -version 2>&1 | Out-String)
        $ErrorActionPreference = $savedPreference
        $jdkPath = [regex]::Match($javaSettings, 'java.home\s*=\s*([^\r\n]+)').Groups[1].Value.Trim()
        $jarExe = Join-Path $jdkPath 'bin/jar.exe'
        if (!(Test-Path -LiteralPath $jarExe)) { throw 'A full JDK 17+ with javac and jar is required.' }
    }
    New-Item -ItemType Directory -Force lib, build | Out-Null
    $dependencies = @{
        'burp-extender-api-2.3.jar' = 'https://repo.maven.apache.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar'
        'gson-2.11.0.jar' = 'https://repo.maven.apache.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar'
    }
    foreach ($name in $dependencies.Keys) {
        $destination = Join-Path 'lib' $name
        if (!(Test-Path -LiteralPath $destination)) { Invoke-WebRequest -Uri $dependencies[$name] -OutFile $destination }
    }
    # Fresh staging prevents removed classes from surviving a rebuild.
    $stage = Join-Path $PSScriptRoot ('build/package-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    $api = Join-Path $PSScriptRoot 'lib/burp-extender-api-2.3.jar'
    $gson = Join-Path $PSScriptRoot 'lib/gson-2.11.0.jar'
    $classpath = $api + [IO.Path]::PathSeparator + $gson
    & javac --release 17 -encoding UTF-8 -cp $classpath -d $stage BurpExtender.java BLHifyBURP.java SocialChecker.java
    if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed' }
    Push-Location $stage
    try {
        & $jarExe xf $gson com/google/gson
        if ($LASTEXITCODE -ne 0) { throw 'Gson packaging failed' }
    } finally { Pop-Location }
    if ($Test) {
        $testClasses = Join-Path $stage 'test-classes'
        New-Item -ItemType Directory -Path $testClasses | Out-Null
        & javac --release 17 -encoding UTF-8 -cp ($stage + [IO.Path]::PathSeparator + $classpath) -d $testClasses tests/BLHifyTest.java
        if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed' }
        & java '-Djava.awt.headless=true' -cp ($testClasses + [IO.Path]::PathSeparator + $stage + [IO.Path]::PathSeparator + $classpath) burp.BLHifyTest
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    }
    & $jarExe --create --file BLHify.jar -C $stage burp -C $stage com
    if ($LASTEXITCODE -ne 0) { throw 'JAR packaging failed' }
    Write-Host 'Built BLHify.jar (Java 17+, Gson bundled; Burp API supplied by Burp).'
} finally { Pop-Location }
