-------- PROJECT GENERATOR --------
PROJECT NAME :	test80
PROJECT DIRECTORY :	C:\WorkSpace\test80\test80
CPU SERIES :	2000
CPU TYPE :	2329F
TOOLCHAIN NAME :	Renesas H8S,H8/300 Standard Toolchain
TOOLCHAIN VERSION :	7.0.0.0
GENERATION FILES :
    C:\WorkSpace\test80\test80\dbsct.c
        Setting of B,R Section
    C:\WorkSpace\test80\test80\typedefine.h
        Aliases of Integer Type
    C:\WorkSpace\test80\test80\sbrk.c
        Program of sbrk
    C:\WorkSpace\test80\test80\iodefine.h
        Definition of I/O Register
    C:\WorkSpace\test80\test80\intprg.c
        Interrupt Program
    C:\WorkSpace\test80\test80\resetprg.c
        Reset Program
    C:\WorkSpace\test80\test80\hwsetup.c
        Hardware Setup file
    C:\WorkSpace\test80\test80\test80.c
        Main Program
    C:\WorkSpace\test80\test80\sbrk.h
        Header file of sbrk file
    C:\WorkSpace\test80\test80\stacksct.h
        Setting of Stack area
START ADDRESS OF SECTION :
 H'000000400	PResetPRG,PIntPRG
 H'000000800	P,C,C$DSEC,C$BSEC,D
 H'000FF7C00	B,R
 H'000FFF9F0	S

* When the user program is executed,
* the interrupt mask has been masked.
* 
* ****H8S/2329F Advanced****

SELECT TARGET :
    H8S/2000A Simulator
    H8S/2000N Simulator
DATE & TIME : 12/05/2018 11:16:31 PM
