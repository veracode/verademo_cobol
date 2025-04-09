      *****************************************************************
      *    When the last input parameter for CALL X"91" function 35   *
      *    is set to zero, whatever has been previously written to    *
      *    the command line is executed.                              *
      *****************************************************************
       IDENTIFICATION DIVISION.
       PROGRAM-ID. x91_35_1.
       DATA DIVISION.
       working-storage section.
       01 command-string   pic x(80) value spaces.
       01 exec-result      pic x comp-x.
       01 function-35      pic 99 comp     value 35. 
       01 null-parameter   pic 99 comp     value 0.
       
       procedure division.
           display spaces upon crt.
       
       vulnerable.
      *    CWE 248
           ACCEPT command-string. *> CWE 248


           DISPLAY command-string UPON command-line.

      *    The following CALL is vulnerable if the latest display 
      *    closer to this call used a TAINTED value, the second param
      *    is == 35 and the latest parameter == 0

      *    CWEID 78 
           CALL X"91" USING exec-result, function-35, null-parameter. 

       safe.
           display spaces upon crt.
           DISPLAY "ls -la" UPON command-line.

      *    the closest DISPLAY used a safe value
      *    FP 78
           CALL X"91" USING exec-result, function-35, null-parameter. 
       
           stop run.
           