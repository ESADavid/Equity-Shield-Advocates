@"
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "types": ["jest"],
    "baseUrl": "."
  },
  "include": ["FOUR-ERA-AI/test/**/*.ts", "FOUR-ERA-AI/src/**/*.ts"]
}
"@ | Out-File -Encoding utf8 tsconfig.json -Force
