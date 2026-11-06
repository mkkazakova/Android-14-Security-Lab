# Optional Windows build. Main supported zero-setup route is GitHub Actions.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not $env:JAVA_HOME) {
    $studioJava = Join-Path $env:ProgramFiles 'Android\Android Studio\jbr'
    if (Test-Path $studioJava) { $env:JAVA_HOME = $studioJava; $env:Path = "$studioJava\bin;$env:Path" }
}
if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
if (-not (Test-Path "$env:ANDROID_HOME\platforms\android-34")) { throw 'Установите SDK Platform 34 через SDK Manager Android Studio или используйте GitHub Actions.' }
python -m pip install -r scripts/requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Не удалось подготовить Python.' }
if (-not (Test-Path '.lab-secrets/fixture.json')) {
    python scripts/prepare.py
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать лабораторные сертификаты.' }
}
New-Item -ItemType Directory -Force results/apk | Out-Null
& .\gradlew.bat --no-daemon :lab:assembleDebug :helper:assembleDebug :sample:assembleDebug -PsampleVersion=1 -PsampleSigner=a
if ($LASTEXITCODE -ne 0) { throw 'Ошибка сборки. Сохраните вывод Gradle.' }
Copy-Item lab/build/outputs/apk/debug/lab-debug.apk results/apk/security-lab.apk
Copy-Item helper/build/outputs/apk/debug/helper-debug.apk results/apk/lab-helper.apk
Copy-Item sample/build/outputs/apk/debug/sample-debug.apk results/apk/sample-v1-a.apk
foreach ($labSigner in @('b','a')) {
    & .\gradlew.bat --no-daemon :sample:assembleDebug -PsampleVersion=2 "-PsampleSigner=$labSigner"
    if ($LASTEXITCODE -ne 0) { throw 'Ошибка сборки Update Sample.' }
    Copy-Item sample/build/outputs/apk/debug/sample-debug.apk "results/apk/sample-v2-$labSigner.apk"
}
Write-Host 'APK находятся в results/apk. Для сетевого опыта запустите python scripts/server.py в этой папке проекта.'
