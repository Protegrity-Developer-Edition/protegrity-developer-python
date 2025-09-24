Feature: Successful Protection Operations For Date Input Data
    As a user of the appython module (installed via protegrity_developer_python)
    I want to perform protect and unprotect operations on date input data
    So that I can ensure data security and integrity

    Background:
        Given the appython module is available via the protegrity_developer_python installation
        And the enviroment variables DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD and DEV_EDITION_API_KEY are set
        And a policy is deployed with required data elements and user "superuser" is present

    @tokenization @single
    Scenario: Tokenize and Detokenize single date input data
        When the user performs "tokenization" operations on the "single date" input data using the following data elements
            | data_element | input_data |
            | datetime     | 0600-01-01 |
            | datetime     | 2023/09/04 |
            | datetime     | 2023.09.04 |
            | datetime     | 3337-11-27 |
            | datetime     | 3337-11-27 |
            | datetime     | 1897.07.12 |
            | datetime     | 1958/06/30 |
            | datetime     | 1906-12-02 |
            | datetime     | 1911-07-10 |
            | datetime     | 1963-03-21 |
            | datetime     | 1970-04-02 |
            | datetime     | 1931.07.16 |
            | datetime     | 2005-02-24 |
        Then all the data is validated
        And all the data should be written to a file "token_date.txt"

    @tokenization @bulk
    Scenario Outline: Tokenize and Detokenize bulk input data passed as a "<input_type>"
        When the user performs "tokenization" operations on the "<input_type>" using the following data elements
            | data_element | input_data                                                                                         |
            | datetime     | ["0600-01-01", "2023/09/04", "2023.09.04", "3337-11-27", "3337-11-27", "1897.07.12", "1958/06/30"] |
            | datetime     | ["1906-12-02", "1911-07-10", "1963-03-21", "1970-04-02", "1931.07.16", "2005-02-24"]               |
        Then all the data is validated
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type     | output_file             |
            | list of dates  | token_list_of_date.txt  |
            | tuple of dates | token_tuple_of_date.txt |