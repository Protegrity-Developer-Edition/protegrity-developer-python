Feature: Successful Protection Operations For Integer Input Data
    As a user of the appython module (installed via protegrity_developer_python)
    I want to perform protect and unprotect operations on integer input data
    So that I can ensure data security and integrity

    Background:
        Given the appython module is available via the protegrity_developer_python installation
        And the enviroment variables DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD and DEV_EDITION_API_KEY are set
        And a policy is deployed with required data elements and user "superuser" is present

    @tokenization @single
    Scenario: Tokenize and Detokenize single integer input data
        When the user performs "tokenization" operations on the "single integer" input data using the following data elements
            | data_element | input_data  |
            | int          | 12345       |
            | int          | 0           |
            | int          | -2147483648 |
            | int          | 2147483647  |
            | int          | 1           |
            | int          | -1          |
            | int          | 100         |
            | int          | -100        |
            | int          | 1615614986  |
            | int          | -1426897611 |
            | int          | -525186374  |
            | int          | 1972304527  |
        Then all the data is validated
        And all the data should be written to a file "token_integer.txt"

    @encryption @single
    Scenario: Encyrpt and Decrypt single integer input data
        When the user performs "encryption" operations on the "single integer" input data using the following data elements
            | data_element | input_data |
            | text         | 1972304527 |
        Then all the data is validated
        And all the data should be written to a file "encrypt_integer.txt"

    @encryption @bulk
    Scenario Outline: Encyrpt and Decrypt bulk input data passed as a "<input_type>"
        When the user performs "encryption" operations on the "<input_type>" using the following data elements
            | data_element | input_data                        |
            | text         | ["-525186374", "1", "1615614986"] |
        Then all the data is validated
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type        | output_file                   |
            | list of integers  | encrypt_list_of_integers.txt  |
            | tuple of integers | encrypt_tuple_of_integers.txt |

    # EIV is not supported with Encryption, NoEncryption, PreserverPosition_PreserverCase alphanum, Decimal and Datetime DEs
    @tokenization @single @eiv
    Scenario: Tokenize and Detokenize single integer input data with External Initialization Vector (EIV)
        When the user performs "tokenization" operations on the "single integer" input data using the following data elements and external IV
            | data_element | input_data  | external_iv |
            | int          | 12345       | iv_int_001  |
            | int          | 0           | iv_int_002  |
            | int          | -2147483648 | iv_int_003  |
            | int          | 2147483647  | iv_int_004  |
            | int          | 1           | iv_int_005  |
            | int          | -1          | iv_int_006  |
            | int          | 100         | iv_int_007  |
            | int          | -100        | iv_int_008  |
            | int          | 1615614986  | iv_int_009  |
            | int          | -1426897611 | iv_int_010  |
            | int          | -525186374  | iv_int_011  |
            | int          | 1972304527  | iv_int_012  |
        Then all the data is validated for eiv
        And all the data should be written to a file "token_integer_IV.txt"

    @tokenization @bulk
    Scenario Outline: Tokenize and Detokenize bulk input data passed as a "<input_type>"
        When the user performs "tokenization" operations on the "<input_type>" using the following data elements
            | data_element | input_data                                                                                  |
            | int          | ["12345", "0", "-2147483648", "2147483647", "1", "-1", "100", "-100"]                       |
            | int          | ["1615614986", "-1426897611", "-525186374", "1972304527", "42", "-42", "314159", "-271828"] |
        Then all the data is validated
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type        | output_file                 |
            | list of integers  | token_list_of_integers.txt  |
            | tuple of integers | token_tuple_of_integers.txt |

    @tokenization @bulk @eiv
    Scenario Outline: Tokenize and Detokenize bulk input data passed as a <input_type> with External Initialization Vector (EIV)
        When the user performs "tokenization" operations on the "<input_type>" using the following data elements and external IV
            | data_element | input_data                                                                                  | external_iv    |
            | int          | ["12345", "0", "-2147483648", "2147483647", "1", "-1", "100", "-100"]                       | protegrity 123 |
            | int          | ["1615614986", "-1426897611", "-525186374", "1972304527", "42", "-42", "314159", "-271828"] | iv_int_001     |
        Then all the data is validated for eiv
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type        | output_file                    |
            | list of integers  | token_list_of_integers_IV.txt  |
            | tuple of integers | token_tuple_of_integers_IV.txt |