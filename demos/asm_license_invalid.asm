; Minimal assembly license check - INVALID
; Assemble: ml64 /c asm_license_invalid.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:start /NODEFAULTLIB kernel32.lib asm_license_invalid.obj

EXTERN ExitProcess:PROC

.code
start PROC
    ; Load license key
    mov al, 'X'          ; Invalid key
    
    ; Check if valid
    cmp al, 'V'
    je valid
    
    ; Invalid path
    mov rcx, 1           ; Exit code 1
    call ExitProcess
    
valid:
    ; Valid path
    mov rcx, 0           ; Exit code 0
    call ExitProcess
    
start ENDP
END
