Feature: Sensitive Data Redaction and Masking Using Sample Application
    As a user of the "sample-app-find-and-redact" sample application
    I want to redact or mask sensitive data from text files
    So that I can do analysis on the data without exposing personally identifiable information (PII)

    Background:
        Given docker-compose.yml is up and running
        And protegrity_developer_python module is installed
        And sample application is present
        And a sample input file containing PII data
        And config.json is present

    @sample_app_find_and_redact @discover
    Scenario: Redact PII from sample input text using sample app
        When the user runs the sample app "sample_app_find_and_redact" with method configured as "redact" in config.json file
        Then the output file containing named entity labels should match with "sample_exp_output_redact.txt" file

    @sample_app_find_and_mask @discover
    Scenario: Mask PII from sample input text using sample app
        When the user runs the sample app "sample_app_find_and_redact" with method configured as "mask" in config.json file
        Then the output file containing masking characters should match with "sample_exp_output_mask.txt" file