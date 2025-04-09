       IDENTIFICATION DIVISION.
      ***************************
       PROGRAM-ID. crypto_icsf_csn_dsg1.
      *****************************
       ENVIRONMENT DIVISION.
      *****************************************************************
       CONFIGURATION SECTION.
       SOURCE-COMPUTER. IBM-370.
       OBJECT-COMPUTER. IBM-370.
      *****************************
       DATA DIVISION.
      *****************************************************************
       FILE SECTION.
       WORKING-STORAGE SECTION.
       01 SERVICE-NAME-GEN PIC X(8).
       01 SERVICE-NAME-VFY PIC X(8).

       01 MY-MESSAGE PIC X(5000) VALUE 'MY-MESSAGE-TO-SIGN'.

      ************* DEFINE SAPI INPUT/OUTPUT PARAMETERS ************
       01 SAPI-REC.
           05 RETURN-CODE-S PIC 9(08) COMP.
           05 REASON-CODE-S PIC 9(08) COMP.
           05 EXIT-DATA-LENGTH-S PIC 9(08) COMP.
           05 EXIT-DATA-S PIC X(04).
           05 RULE-ARRAY-COUNT-S PIC 9 COMP.
           05 RULE-ARRAY-S.
              10 RULE-1 PIC X(08).
              10 RULE-2 PIC X(08).
              10 RULE-3 PIC X(08).
              10 RULE-4 PIC X(08).
           05 PRIV-KEY-IDENTIFIER-LENGTH PIC 9(4).
           05 PRIV-KEY-IDENTIFIER PIC X(8000).
           05 DATA-VALUE-LENGTH PIC 9(4).
           05 DATA-VALUE PIC X(8192).
           05 SIGN-FIELD-LENGTH PIC 9(4).
           05 SIGN-BIT-LENGTH PIC 9(10).
           05 SIGN-FIELD PIC X(2000).

       01 VERIFY-REC.
           05 PUB-KEY-IDENTIFIER-LENGTH PIC 9(4).
           05 PUB-KEY-IDENTIFIER PIC X(8000).
           05 V-RULE-ARRAY-S.
              10 V-RULE-1 PIC X(08).
              10 V-RULE-2 PIC X(08).
              10 V-RULE-3 PIC X(08).
              10 V-RULE-4 PIC X(08).
              10 V-RULE-5 PIC X(08).
              10 V-RULE-6 PIC X(08).





      *****************************************************************
       PROCEDURE DIVISION.
      *****************************************************************
       MAIN-RTN.
      
      *****************************************************************
      ***** ******** ******** D family  *******************************
      *****************************************************************


           MOVE 0 TO EXIT-DATA-LENGTH-S.
           MOVE 'RSA' TO RULE-1 IN RULE-ARRAY-S .
           MOVE 'PKCS-PSS' TO RULE-2  IN RULE-ARRAY-S . *> good padding
           MOVE 'HASH' TO RULE-3 IN RULE-ARRAY-S .
           MOVE 'SHA-384' TO RULE-4  IN RULE-ARRAY-S . *> good sign hash
           MOVE 4 TO RULE-ARRAY-COUNT-S .
           MOVE MY-MESSAGE TO DATA-VALUE .
           MOVE 18 TO DATA-VALUE-LENGTH .

      *    Skipping other parameters that are not required
      *    for the purpose of this testcase
           MOVE 'CSNDDSG' TO SERVICE-NAME-GEN.
           MOVE 'CSNDDSV' TO SERVICE-NAME-VFY.

      *    CWE 252
           CALL SERVICE-NAME-GEN USING RETURN-CODE-S *> CWE 252
                                   REASON-CODE-S
                                   EXIT-DATA-LENGTH-S
                                   EXIT-DATA-S
                                   RULE-ARRAY-COUNT-S
                                   RULE-ARRAY-S
                                   PRIV-KEY-IDENTIFIER-LENGTH
                                   PRIV-KEY-IDENTIFIER
                                   DATA-VALUE-LENGTH
                                   DATA-VALUE
                                   SIGN-FIELD-LENGTH
                                   SIGN-BIT-LENGTH
                                   SIGN-FIELD.

           MOVE 0 TO EXIT-DATA-LENGTH-S.
           MOVE 'RSA' TO V-RULE-1 .
           MOVE RULE-2 TO V-RULE-2 .
           MOVE RULE-3 TO V-RULE-3 .
           MOVE RULE-4 TO V-RULE-4 .
           MOVE 'PKI-CHK' TO V-RULE-5 .
           MOVE 5 TO RULE-ARRAY-COUNT-S .

      *    CWE 252
           CALL SERVICE-NAME-VFY USING RETURN-CODE-S *> CWE 252
                              REASON-CODE-S
                              EXIT-DATA-LENGTH-S
                              EXIT-DATA-S
                              RULE-ARRAY-COUNT-S
                              V-RULE-ARRAY-S
                              PUB-KEY-IDENTIFIER-LENGTH
                              PUB-KEY-IDENTIFIER
                              DATA-VALUE-LENGTH
                              DATA-VALUE
                              SIGN-FIELD-LENGTH
                              SIGN-FIELD.

           DISPLAY '*** Digital Signature Verify Succeded ***'.


      ***** ******** ******** F family  *******************************

           MOVE 0 TO EXIT-DATA-LENGTH-S.
           MOVE 'RSA' TO RULE-1 IN RULE-ARRAY-S .
           MOVE 'PKCS-1.1' TO RULE-2  IN RULE-ARRAY-S . *> good padding
           MOVE 'HASH' TO RULE-3 IN RULE-ARRAY-S .
           MOVE 'SHA-224' TO RULE-4  IN RULE-ARRAY-S . *> good sign hash
           MOVE 4 TO RULE-ARRAY-COUNT-S .
           MOVE MY-MESSAGE TO DATA-VALUE .
           MOVE 18 TO DATA-VALUE-LENGTH .

      *    Skipping other parameters that are not required
      *    for the purpose of this testcase
           MOVE 'CSNFDSG' TO SERVICE-NAME-GEN.
           MOVE 'CSNFDSV' TO SERVICE-NAME-VFY.

      *    CWE 252
           CALL SERVICE-NAME-GEN USING RETURN-CODE-S *> CWE 252
                                   REASON-CODE-S
                                   EXIT-DATA-LENGTH-S
                                   EXIT-DATA-S
                                   RULE-ARRAY-COUNT-S
                                   RULE-ARRAY-S
                                   PRIV-KEY-IDENTIFIER-LENGTH
                                   PRIV-KEY-IDENTIFIER
                                   DATA-VALUE-LENGTH
                                   DATA-VALUE
                                   SIGN-FIELD-LENGTH
                                   SIGN-BIT-LENGTH
                                   SIGN-FIELD.

           MOVE 0 TO EXIT-DATA-LENGTH-S.
           MOVE 'RSA' TO V-RULE-1 .
           MOVE RULE-2 TO V-RULE-2 .
           MOVE RULE-3 TO V-RULE-3 .
           MOVE RULE-4 TO V-RULE-4 .
           MOVE 'PKI-CHK' TO V-RULE-5 .
           MOVE 5 TO RULE-ARRAY-COUNT-S .

      *    CWE 252
           CALL SERVICE-NAME-VFY USING RETURN-CODE-S *> CWE 252
                                REASON-CODE-S
                                EXIT-DATA-LENGTH-S
                                EXIT-DATA-S
                                RULE-ARRAY-COUNT-S
                                V-RULE-ARRAY-S
                                PUB-KEY-IDENTIFIER-LENGTH
                                PUB-KEY-IDENTIFIER
                                DATA-VALUE-LENGTH
                                DATA-VALUE
                                SIGN-FIELD-LENGTH

           DISPLAY '*** Digital Signature Verify Succeded ***'.



           DISPLAY '*** TEST PROGRAM ENDED ***'
           STOP RUN.
           