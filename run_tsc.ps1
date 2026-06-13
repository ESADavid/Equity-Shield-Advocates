# Run TypeScript compiler check
Set-Location -Path "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE"
npx tsc --noEmit
$exitCode = $LASTEXITCODE
Write-Host "Exit code: $exitCode"
if ($exitCode -eq 0) {
    Write-Host "SUCCESS: No TypeScript errors found"
} else {
    Write-Host "FAILURE: TypeScript errors detected"
}
exit $exitCode
