; NSIS hooks for the NetDeck installer (tauri.conf.json → bundle.windows.nsis.installerHooks).

; Uninstalling removes "Start with Windows" too, so Windows is not left trying to start a program that is gone.
; Not when the uninstaller runs as part of installing a newer version ($UpdateMode), which keeps the setting.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "NetDeck"
  ${EndIf}
!macroend
