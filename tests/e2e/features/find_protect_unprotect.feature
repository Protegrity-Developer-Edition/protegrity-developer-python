# ⚠️ KNOWN ISSUE: Sensitive data protection may be inconsistent.
Feature: Sensitive Data Protection using protegrity_developer_python
    As a user of the protegrity_developer_python module
    I want to protect sensitive data from text files
    I also want to unprotect the data back to its original form
    So that I can do analysis on the data without exposing personally identifiable information (PII)

    Background:
        Given docker-compose.yml is up and running
        And protegrity_developer_python module is installed

    @find_protect_unprotect @discover
    Scenario: Protect and Unprotect PII from input text using protegrity_developer_python module
        Given the protegrity_developer_python module is configured
        When the user invokes the "find_and_protect" function with the following input text:
            """
            On March 15, 2025 at 10:30 AM, Olive called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the 5555 5555 5555 4444, and the confirmation was sent to vegetables@gmaik.com. Please ensure all sensitive data is redacted before sharing this report externally.
            """
        Then the output should be protected as follows:
            """
            On March 15, 2025 at 10:30 AM, [PERSON]DIadE[/PERSON] called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the [CREDIT_CARD]6731 8596 8633 7617[/CREDIT_CARD], and the confirmation was sent to [EMAIL_ADDRESS]ScraSM2yiu@gmaik.com[/EMAIL_ADDRESS]. Please ensure all sensitive data is redacted before sharing this report externally.
            """
        When the user invokes the find_and_unprotect function with the protected output
        Then the unprotected output should match the original input

    @find_protect_unprotect @discover
    Scenario: Perform Protection on an input text which does not contain any PII data using protegrity_developer_python module
        Given the protegrity_developer_python module is configured
        When the user invokes the "find_and_protect" function with the following input text:
            """
            The customer reported an issue with the login process and provided logs showing unexpected behavior in the authentication module.
            """
        Then the output should be same as the input as follows:
            """
            The customer reported an issue with the login process and provided logs showing unexpected behavior in the authentication module.
            """

    @find_protect_unprotect @discover
    Scenario: Protect PII from input text containing a variety of entity types using protegrity_developer_python module
        Given the protegrity_developer_python module is configured
        When the user invokes the "find_and_protect" function with the input file "input_variety.txt"
        Then the protected output should match with the expected output in "exp_output_variety_prot.txt"
        When the user invokes the find_and_unprotect function with the protected output
        Then the unprotected output should match the original input

    @find_protect_unprotect @negative @discover
    Scenario: Perform Protection with empty input text using protegrity_developer_python module
        Given the protegrity_developer_python module is configured
        When the user invokes the "find_and_protect" function with empty input text:
            """
            EMPTY
            """
        Then the error should be seen as "400 Client Error: Bad Request for url:"

    @find_protect_unprotect @discover
    Scenario: Protect PII from input text containing english, chinese, spanish PII and emojis using protegrity_developer_python module
        Given the protegrity_developer_python module is configured
        When the user invokes the "find_and_protect" function with the following input text:
            """
            John Doe (SSN: 123-45-6789, 📧: john.doe@example.com) from New York transferred ¥5000 to 王小明 (身份证号: 110101199003078888, 📱: +86 138 0000 0000) in 北京市朝阳区. Meanwhile, María González (DNI: 12345678Z, 📞: +34 600 123 456) from Madrid updated her IBAN to ES91 2100 0418 4502 0005 1332. 🏦💳 The transaction was logged at 2025-07-21 14:30:00 UTC. Everything looked normal until 🚨 a suspicious login was detected from IP 192.168.1.101. Stay safe online! 🔐🌐
            """
        Then the output should be protected as follows:
            """
            [PERSON]SZvn mLb[/PERSON] (SSN: [SOCIAL_SECURITY_NUMBER]616-16-2210[/SOCIAL_SECURITY_NUMBER], 📧: [EMAIL_ADDRESS]EVsQ.Tv0@example.com[/EMAIL_ADDRESS]) from [LOCATION]OuT bQaK[/LOCATION] transferred ¥5000 to 王小明 (身份证号: 110101199003078888, 📱: [LOCATION]+iM fvU 3v0H T98V[/LOCATION]) in 北京市朝阳区. Meanwhile, [PERSON]5dDíF JhjGá3GK[/PERSON] (DNI: [ID_CARD]95805408Z[/ID_CARD], 📞: [AU_TFN]+39 012 771 097)[/AU_TFN] from [CITY]QSGGRk[/CITY] updated her IBAN to ES91 2100 0418 4502 0005 1332. 🏦💳 The transaction was logged at [DATE]3175-06-15[/DATE] 14:30:00 UTC. Everything looked normal until 🚨 a suspicious login was detected from IP [IP_ADDRESS]vk5.y8P.d.VP1[/IP_ADDRESS]. Stay safe online! 🔐🌐
            """
        When the user invokes the find_and_unprotect function with the protected output
        Then the unprotected output should match the original input