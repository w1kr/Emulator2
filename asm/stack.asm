mov r0, 0x123
push r0
pop r1

push 0x11111111
push 0x22222222
push 0x33333333
push 0x44444444

pop r4
pop r3
pop r2
pop r1

hlt
