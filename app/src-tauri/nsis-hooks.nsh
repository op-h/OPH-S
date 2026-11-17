; OPH-S installer hooks (Tauri NSIS bundler)
!macro NSIS_HOOK_POSTINSTALL
  ; start with Windows: logon task with highest privileges (no UAC prompt at every boot)
  nsExec::Exec '"$INSTDIR\OPH-S.exe" --install-autostart'
  ; (re)start protection right away: after an upgrade the network's DNS must come back immediately
  Exec '"$INSTDIR\OPH-S.exe" --minimized'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; stop the running app (also needed so an upgrade can replace the exe)
  nsExec::Exec 'taskkill /F /IM OPH-S.exe'
  ; real uninstall only: undo every system change (hosts entries, firewall rules, autostart).
  ; During an upgrade (/UPDATE) keep them, or LAN devices would lose DNS access.
  ${If} $UpdateMode <> 1
    nsExec::Exec '"$INSTDIR\OPH-S.exe" --cleanup'
  ${EndIf}
!macroend

