.text
    .global _start
_start:
    // 1. Load 0xBEEFCAFEBABEDEAD into X14
    mov  x14, #0xDEAD
    movk x14, #0xBABE, lsl #16
    movk x14, #0xCAFE, lsl #32
    movk x14, #0xBEEF, lsl #48

    // 2. Perform EOR operation (result in X29)
    eor  x29, x14, #0x1000000010000000

    // 3. Proper Linux exit system call
    mov  w8, #93    // Syscall number for exit()
    mov  x0, #0     // Exit code 0 (Success)
    svc  #0         // Execute the system call (Supervisor Call)
