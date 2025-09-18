Feature: Sensitive Data Find And Protect/Unprotect Using Sample Application
    As a user of the "sample-app-find-and-protect" and "sample-app-find-and-unprotect" sample applications
    I want to find and protect sensitive data from text files
    I also want to unprotect the data back to its original form
    So that I can analyze the data without exposing personally identifiable information (PII)

    Background:
        Given python is installed as "python"
        And docker-compose.yml is up and running
        And protegrity_developer_python module is installed
        And sample application is present
        And a sample input file containing PII data
        And config.json is present

    @sample_app_find_and_protect @discover
    Scenario: Find and Protect PII from sample input text using sample app
        When the user runs the sample app "sample_app_find_and_protect"
        Then the output file containing named entity labels should match with "sample_exp_output_protect.txt" file

    @sample_app_find_and_unprotect @discover
    Scenario: Unprotect the protected data from sample protected output file using sample app
        When the user runs the sample app "sample_app_find_and_unprotect"
        Then the output file containing named entity labels should match with "input.txt" file