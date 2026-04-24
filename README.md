# utils

A collection of utility scripts for PowerShell and Bash.

## Scripts

| Script | Language | Description | SHA-256 |
|--------|----------|-------------|---------|
| `SecurePassword.ps1` | PowerShell | CSPRNG cryptographically secure password generator | `88283CFDA27C65AA1D2FE42773AF7CD71D9D7CFEAFF7B68A4219244CD02452B3` |

## Verify integrity

**PowerShell:**
```powershell
Get-FileHash .\SecurePassword.ps1 -Algorithm SHA256
```

**Bash:**
```bash
sha256sum SecurePassword.ps1
```

## Requirements

- PowerShell 7+ (for `.ps1` scripts)
- Bash 4+ (for `.sh` scripts)

## License

MIT
