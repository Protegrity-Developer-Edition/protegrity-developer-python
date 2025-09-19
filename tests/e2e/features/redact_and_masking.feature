# ⚠️ KNOWN ISSUE: Sensitive data redaction/masking may be inconsistent.
Feature: Sensitive Data Redaction and Masking using protegrity_developer_python
    As a user of the protegrity_developer_python module
    I want to redact or mask sensitive data from text files
    So that I can do analysis on the data without exposing personally identifiable information (PII)

    Background:
        Given docker-compose.yml is up and running
        And protegrity_developer_python module is installed

    @redact @discover
    Scenario: Redact PII from input text using protegrity_developer_python module
        Given the configuration file has "method" as "redact" and protegrity_developer_python module is configured
            | masking_char |
            | NA           |
        When the user invokes the "find_and_redact" function with the following input text:
            """
            On March 15, 2025 at 10:30 AM, Olive called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the 5555 5555 5555 4444, and the confirmation was sent to vegetables@gmaik.com. Please ensure all sensitive data is redacted before sharing this report externally.
            """
        Then the output should be redacted as follows:
            """
            On [DATE] at [TIME], [PERSON] called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the [CREDIT_CARD], and the confirmation was sent to [EMAIL_ADDRESS]. Please ensure all sensitive data is redacted before sharing this report externally.
            """

    @mask @discover
    Scenario: Mask PII with "*" character from input text using protegrity_developer_python module
        Given the configuration file has "method" as "mask" and protegrity_developer_python module is configured
            | masking_char |
            | *            |
        When the user invokes the "find_and_redact" function with the following input text:
            """
            On March 15, 2025 at 10:30 AM, Olive called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the 5555 5555 5555 4444, and the confirmation was sent to vegetables@gmaik.com. Please ensure all sensitive data is redacted before sharing this report externally.
            """
        Then the output should be masked as follows:
            """
            On ************** at ********, ***** called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the *******************, and the confirmation was sent to ********************. Please ensure all sensitive data is redacted before sharing this report externally.
            """

    @mask @discover
    Scenario: Mask PII with "%" character from input text using protegrity_developer_python module
        Given the configuration file has "method" as "mask" and protegrity_developer_python module is configured
            | masking_char |
            | %            |
        When the user invokes the "find_and_redact" function with the following input text:
            """
            On March 15, 2025 at 10:30 AM, Olive called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the 5555 5555 5555 4444, and the confirmation was sent to vegetables@gmaik.com. Please ensure all sensitive data is redacted before sharing this report externally.
            """
        Then the output should be masked as follows:
            """
            On %%%%%%%%%%%%%% at %%%%%%%%, %%%%% called our support line at 203-555-1286 to report an issue with a recent transaction. The transaction was made using the %%%%%%%%%%%%%%%%%%%, and the confirmation was sent to %%%%%%%%%%%%%%%%%%%%. Please ensure all sensitive data is redacted before sharing this report externally.
            """

    @redact @discover
    Scenario: Perform Redaction on an input text which does not contain any PII data using protegrity_developer_python module
        Given the configuration file has "method" as "redact" and protegrity_developer_python module is configured
            | masking_char |
            | NA           |
        When the user invokes the "find_and_redact" function with the following input text:
            """
            The customer reported an issue with the login process and provided logs showing unexpected behavior in the authentication module.
            """
        Then the output should be same as the input as follows:
            """
            The customer reported an issue with the login process and provided logs showing unexpected behavior in the authentication module.
            """

    @redact @discover
    Scenario: Redact PII from input text containing a variety of entity types using protegrity_developer_python module
        Given the configuration file has "method" as "redact" and protegrity_developer_python module is configured
            | masking_char |
            | NA           |
        When the user invokes the "find_and_redact" function with the input file "input_variety.txt"
        Then the redacted output should match with the expected output in "exp_output_variety.txt"

    @mask @discover
    Scenario: Mask PII from input text containing a variety of entity types using protegrity_developer_python module
        Given the configuration file has "method" as "mask" and protegrity_developer_python module is configured
            | masking_char |
            | @            |
        When the user invokes the "find_and_redact" function with the input file "input_variety.txt"
        Then the masked output should match with the expected output in "exp_output_mask.txt"

    @redact @negative @discover
    Scenario: Perform Redaction with empty input text using protegrity_developer_python module
        Given the configuration file has "method" as "redact" and protegrity_developer_python module is configured
            | masking_char |
            | NA           |
        When the user invokes the "find_and_redact" function with empty input text:
            """
            EMPTY
            """
        Then the error should be seen as "400 Client Error: Bad Request for url:"

    @redact @negative @discover
    Scenario: Perform Redaction with invalid method using protegrity_developer_python module
        Given the configuration file has "method" as "tokenization" and protegrity_developer_python module is configured
            | masking_char |
            | NA           |
        When the user calls the find_and_redact function with the following input text while capturing logs:
            """
            2025-07-21 21:40:26,675: Jupiter is the biggest planet in the solar system and has a mass that is more than twice that of all the other planets combined. It is known for its Great Red Spot, a giant storm that has been raging for hundreds of years.
            """
        Then the output should be redacted as follows by defaulting to "redact" method:
            """
            [TIME|DATE_TIME|DATE]: [LOCATION] is the biggest planet in the solar system and has a mass that is more than twice that of all the other planets combined. It is known for its Great Red Spot, a giant storm that has been raging for [DATE_TIME].
            """

    @redact @discover
    Scenario: Redact PII from input text containing english, chinese, spanish PII and emojis using protegrity_developer_python module
        Given the configuration file has "method" as "redact" and protegrity_developer_python module is configured
            | masking_char |
            | NA           |
        When the user invokes the "find_and_redact" function with the following input text:
            """
            John Doe (SSN: 123-45-6789, 📧: john.doe@example.com) from New York transferred ¥5000 to 王小明 (身份证号: 110101199003078888, 📱: +86 138 0000 0000) in 北京市朝阳区. Meanwhile, María González (DNI: 12345678Z, 📞: +34 600 123 456) from Madrid updated her IBAN to ES91 2100 0418 4502 0005 1332. 🏦💳 The transaction was logged at 2025-07-21 14:30:00 UTC. Everything looked normal until 🚨 a suspicious login was detected from IP 192.168.1.101. Stay safe online! 🔐🌐
            """
        Then the output should be redacted as follows:
            """
            [PERSON] (SSN: [SOCIAL_SECURITY_NUMBER], 📧: [EMAIL_ADDRESS]) from [LOCATION] transferred ¥5000 to 王小明 (身份证号: 110101199003078888, 📱: [LOCATION|PHONE_NUMBER]) in 北京市朝阳区. Meanwhile, [PERSON] (DNI: [ID_CARD], 📞: [AU_TFN|PHONE_NUMBER] from [CITY] updated her IBAN to [DATE_TIME|IBAN_CODE]. 🏦💳 The transaction was logged at [DATE] 14:30:00 UTC. Everything looked normal until 🚨 a suspicious login was detected from IP [IP_ADDRESS]. Stay safe online! 🔐🌐
            """