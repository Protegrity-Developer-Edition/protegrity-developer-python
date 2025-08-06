Feature: Sensitive Data Redaction and Masking using sample application
    As a user of the sample application
    I want to redact or mask sensitive data from text files
    So that I can do analysis on the data without exposing personally identifiable information (PII)

    Background:
        Given python version 3.9 or higher is installed as "python"
        And docker-compose.yml is up and running
        And protegrity_developer_python module is present
        And sample application is present
        And a sample input file containing PII data
        And config.json is present

    @run
    Scenario: Redact PII from sample input text using sample app
        When the user runs the sample app with method configured as "redact" in config.json file
        Then the output.txt file containing named entity labels should match with "sample_exp_output_redact.txt" file

    @run
    Scenario: Mask PII from sample input text using sample app
        When the user runs the sample app with method configured as "mask" in config.json file
        Then the output.txt file containing masking characters should match with "sample_exp_output_mask.txt" file