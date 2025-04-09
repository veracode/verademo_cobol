      ******************************************************************
      * Sample Program 12: Dynamic SQL Method 4 using ANSI Dynamic SQL *
      * *
      * This program shows the basic steps required to use dynamic *
      * SQL Method 4 with ANSI Dynamic SQL. After logging on to *
      * ORACLE, the program prompts the user for a SQL statement, *
      * PREPAREs the statement, DECLAREs a cursor, checks for any *
      * bind variables using DESCRIBE INPUT, OPENs the cursor, and *
      * DESCRIBEs any select-list variables. If the input SQL *
      * statement is a query, the program FETCHes each row of data, *
      * then CLOSEs the cursor. *
      * use option dynamic=ansi when precompiling this sample. *
      ******************************************************************
       IDENTIFICATION DIVISION.
       PROGRAM-ID. sql-injection-04.
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 USERNAME PIC X(20).
      *    CWE 259 because used int SQL CONNECT
       01 PASSWD PIC X(20) VALUE "THIS IS HARDCODED". *> CWE 259
       01 BDSC PIC X(6) VALUE "BNDDSC".
       01 SDSC PIC X(6) VALUE "SELDSC".
       01 BNDCNT PIC S9(9) COMP.
       01 SELCNT PIC S9(9) COMP.
       01 BNDNAME PIC X(80).
       01 BNDVAL PIC X(80).
      * VARYING will generate two variables
      *    SELNAME-len PIC S9(4) COMP.
      *    SELNAME-ARR PIC X(80).
       01 SELNAME PIC X(80) VARYING.
       01 SELDATA PIC X(80).
       01 SELTYP PIC S9(4) COMP.
       01 SELPREC PIC S9(4) COMP.
       01 SELLEN PIC S9(4) COMP.
       01 SELIND PIC S9(4) COMP.
       01 DYN-STATEMENT PIC X(80).
       01 BND-INDEX PIC S9(9) COMP.
       01 SEL-INDEX PIC S9(9) COMP.
       01 VARCHAR2-TYP PIC S9(4) COMP VALUE 1.
       01 VAR-COUNT PIC 9(2).
       01 ROW-COUNT PIC 9(4).
       01 NO-MORE-DATA PIC X(1) VALUE "N".
       01 TMPLEN PIC S9(9) COMP.
       01 MAX-LENGTH PIC S9(9) COMP VALUE 80.

           EXEC SQL INCLUDE SQLCA END-EXEC.

       PROCEDURE DIVISION.
       START-MAIN.
           EXEC SQL WHENEVER SQLERROR GOTO SQL-ERROR END-EXEC.

           DISPLAY "USERNAME: " WITH NO ADVANCING.
      *    CWEID 248
           ACCEPT USERNAME. *> CWEID 248
           DISPLAY "PASSWORD: " WITH NO ADVANCING.

      *    CWE 259
           EXEC SQL 
              CONNECT :USERNAME IDENTIFIED BY "SECRETPWD" *> CWE 259
           END-EXEC.


           EXEC SQL CONNECT :USERNAME IDENTIFIED BY :PASSWD END-EXEC.
           DISPLAY "CONNECTED TO ORACLE AS USER: ", USERNAME.

      * ALLOCATE THE BIND AND SELECT DESCRIPTORS.

           EXEC SQL ALLOCATE DESCRIPTOR :BDSC WITH MAX 20 END-EXEC.
           EXEC SQL ALLOCATE DESCRIPTOR :SDSC WITH MAX 20 END-EXEC.

      * GET A SQL STATEMENT FROM THE OPERATOR.

           DISPLAY "ENTER SQL STATEMENT WITHOUT TERMINATOR:".
           DISPLAY ">" WITH NO ADVANCING.
      *    CWEID 248
           ACCEPT DYN-STATEMENT.  *> CWEID 248
           DISPLAY " ".

      * PREPARE THE SQL STATEMENT AND DECLARE A CURSOR.
      *    CWEID 89
           EXEC SQL PREPARE S1 FROM :DYN-STATEMENT END-EXEC. *> CWE 89
           EXEC SQL DECLARE C1 CURSOR FOR S1 END-EXEC.

      * DESCRIBE BIND VARIABLES.

           EXEC SQL DESCRIBE INPUT S1 USING DESCRIPTOR :BDSC END-EXEC.

           EXEC SQL GET DESCRIPTOR :BDSC :BNDCNT = COUNT END-EXEC.

           IF BNDCNT < 0
              DISPLAY "TOO MANY BIND VARIABLES."
              GO TO END-SQL
           ELSE
              DISPLAY "NUMBER OF BIND VARIABLES: " WITH NO ADVANCING
              MOVE BNDCNT TO VAR-COUNT
              DISPLAY VAR-COUNT
      *       EXEC SQL SET DESCRIPTOR :BDSC COUNT = :BNDCNT END-EXEC
           END-IF.

           IF BNDCNT = 0
              GO TO DESCRIBE-ITEMS.
           PERFORM SET-BND-DSC
              VARYING BND-INDEX FROM 1 BY 1
              UNTIL BND-INDEX > BNDCNT.

      *    OPEN THE CURSOR AND DESCRIBE THE SELECT-LIST ITEMS.

       DESCRIBE-ITEMS.
           EXEC SQL OPEN C1 USING DESCRIPTOR :BDSC END-EXEC.

           EXEC SQL DESCRIBE OUTPUT S1 USING DESCRIPTOR :SDSC END-EXEC.

           EXEC SQL GET DESCRIPTOR :SDSC :SELCNT = COUNT END-EXEC.

           IF SELCNT < 0
              DISPLAY "TOO MANY SELECT-LIST ITEMS."
              GO TO END-SQL
           ELSE
              DISPLAY "NUMBER OF SELECT-LIST ITEMS: "
                 WITH NO ADVANCING
              MOVE SELCNT TO VAR-COUNT
              DISPLAY VAR-COUNT
              DISPLAY " "
      *       EXEC SQL SET DESCRIPTOR :SDSC COUNT = :SELCNT END-EXEC
           END-IF.

      *    SET THE INPUT DESCRIPTOR

           IF SELCNT > 0
                 PERFORM SET-SEL-DSC
                 VARYING SEL-INDEX FROM 1 BY 1
                 UNTIL SEL-INDEX > SELCNT
                 DISPLAY " ".

      *    FETCH EACH ROW AND PRINT EACH SELECT-LIST VALUE.

           IF SELCNT > 0
              PERFORM FETCH-ROWS UNTIL NO-MORE-DATA = "Y".

           DISPLAY " "
           DISPLAY "NUMBER OF ROWS PROCESSED: " WITH NO ADVANCING.
           MOVE SQLERRD(3) TO ROW-COUNT.
           DISPLAY ROW-COUNT.

      *    CLEAN UP AND TERMINATE.

           EXEC SQL CLOSE C1 END-EXEC.
           EXEC SQL DEALLOCATE DESCRIPTOR :BDSC END-EXEC.
           EXEC SQL DEALLOCATE DESCRIPTOR :SDSC END-EXEC.
           EXEC SQL ROLLBACK WORK RELEASE END-EXEC.
           DISPLAY " ".
           DISPLAY "HAVE A GOOD DAY!".
           DISPLAY " ".
           STOP RUN.

      *    DISPLAY ORACLE ERROR MESSAGE AND CODE.

       SQL-ERROR.
           DISPLAY " ".
      *    CWEID 209
           DISPLAY SQLERRMC. *> CWEID 209
       END-SQL.
           EXEC SQL WHENEVER SQLERROR CONTINUE END-EXEC.
           EXEC SQL ROLLBACK WORK RELEASE END-EXEC.
           STOP RUN.

      *    PERFORMED SUBROUTINES BEGIN HERE:

      *    SET A BIND-LIST ELEMENT'S ATTRIBUTE
      *    LET THE USER FILL IN THE BIND VARIABLES AND
      *    REPLACE THE 0S DESCRIBED INTO THE DATATYPE FIELDS OF THE
      *    BIND DESCRIPTOR WITH 1S TO AVOID AN "INVALID DATATYPE"
      *    ORACLE ERROR
       SET-BND-DSC.
           EXEC SQL GET DESCRIPTOR :BDSC VALUE
              :BND-INDEX :BNDNAME = NAME END-EXEC.
           DISPLAY "ENTER VALUE FOR ", BNDNAME.
      *    CWEID 248
           ACCEPT BNDVAL. *> CWEID 248
           EXEC SQL SET DESCRIPTOR :BDSC VALUE :BND-INDEX
              TYPE = :VARCHAR2-TYP, LENGTH = :MAX-LENGTH,
              DATA = :BNDVAL END-EXEC.

      * SET A SELECT-LIST ELEMENT'S ATTRIBUTES
           SET-SEL-DSC.

           MOVE SPACES TO SELNAME-ARR.

           EXEC SQL GET DESCRIPTOR :SDSC VALUE :SEL-INDEX
              :SELNAME = NAME, :SELTYP = TYPE,
              :SELPREC = PRECISION, :SELLEN = LENGTH END-EXEC.

      *    IF DATATYPE IS DATE, LENGTHEN TO 9 CHARACTERS.
           IF SELTYP = 12
              MOVE 9 TO SELLEN.

      *    IF DATATYPE IS NUMBER, SET LENGTH TO PRECISION.
           MOVE 0 TO TMPLEN.

           IF SELTYP = 2 AND SELPREC = 0
              MOVE 40 TO TMPLEN.
           IF SELTYP = 2 AND SELPREC > 0
              ADD 2 TO SELPREC
              MOVE SELPREC TO TMPLEN.

           IF SELTYP = 2
              IF TMPLEN > MAX-LENGTH
                 DISPLAY "COLUMN VALUE TOO LARGE FOR DATA BUFFER."
                 GO TO END-SQL
              ELSE
                 MOVE TMPLEN TO SELLEN.

      * COERCE DATATYPES TO VARCHAR2.
           MOVE 1 TO SELTYP.

      * DISPLAY COLUMN HEADING.
           DISPLAY " ", SELNAME-ARR(1:SELLEN) WITH NO ADVANCING.

           EXEC SQL SET DESCRIPTOR :SDSC VALUE :SEL-INDEX
              TYPE = :SELTYP, LENGTH = :SELLEN END-EXEC.

      * FETCH A ROW AND PRINT THE SELECT-LIST VALUE.

       FETCH-ROWS.
           EXEC SQL FETCH C1 INTO DESCRIPTOR :SDSC END-EXEC.
           IF SQLCODE NOT = 0
              MOVE "Y" TO NO-MORE-DATA.
           IF SQLCODE = 0
              PERFORM PRINT-COLUMN-VALUES
              VARYING SEL-INDEX FROM 1 BY 1
              UNTIL SEL-INDEX > SELCNT
              DISPLAY " ".

      * PRINT A SELECT-LIST VALUE.

       PRINT-COLUMN-VALUES.
           MOVE SPACES TO SELDATA.
      * returned length is not set for blank padded types
           IF SELTYP EQUALS 1
              EXEC SQL GET DESCRIPTOR :SDSC VALUE :SEL-INDEX
                    :SELDATA = DATA, :SELIND = INDICATOR,
                    :SELLEN = LENGTH END-EXEC
           ELSE
              EXEC SQL GET DESCRIPTOR :SDSC VALUE :SEL-INDEX
                    :SELDATA = DATA, :SELIND = INDICATOR,
                    :SELLEN = RETURNED_LENGTH END-EXEC.
           IF (SELIND = -1)
              move " NULL" to SELDATA.

           DISPLAY SELDATA(1:SELLEN), " "
              WITH NO ADVANCING.
              