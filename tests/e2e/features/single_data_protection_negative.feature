Feature: Unsuccessful Protection Operations For Various Combinations of User, Operation, Data Element and Single Input Data
    As a user of the appython module (installed via protegrity_developer_python)
    I want to verify protection operations fail for invalid, unauthorized and other negative cases
    So that I can ensure errors are handled correctly and data security is not compromised

    Background:
        Given the appython module is available via the protegrity_developer_python installation
        And the enviroment variables DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD and DEV_EDITION_API_KEY are set
        And a policy is deployed with required data elements, users and permissions required to test the scenario

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on single string input data access with user having no appropriate permisions
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user           | data_element | input_data               | result    | output           | error_message                                                                             |
            | protect   | finance        | name         | John Doe                 | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | marketing      | name         | John Doe                 | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | hr             | name         | John Doe                 | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | robin.goodwill | ccn          | 4111111122223333         | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | finance        | ccn          | 4111111122223333         | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | hr             | ccn          | 4111111122223333         | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | merlin.ishida  | ccn          | 4111111122223333         | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | finance        | postcode     | SW1A 1AA                 | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | hr             | postcode     | SW1A 1AA                 | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | marketing      | postcode     | SW1A 1AA                 | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | paloma.torres  | city         | Springfield              | exception | None             | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | admin          | name         | John Doe                 | None      | John Doe         | None                                                                                      |
            | unprotect | admin          | ccn          | 4111111122223333         | None      | 4111111122223333 | None                                                                                      |
            | unprotect | admin          | postcode     | SW1A 1AA                 | None      | SW1A 1AA         | None                                                                                      |
            | unprotect | devops         | name         | John Doe                 | None      | John Doe         | None                                                                                      |
            | unprotect | devops         | ccn          | 4111111122223333         | None      | 4111111122223333 | None                                                                                      |
            | unprotect | devops         | postcode     | SW1A 1AA                 | None      | SW1A 1AA         | None                                                                                      |
            | unprotect | jay.banerjee   | name         | John Doe                 | None      | John Doe         | None                                                                                      |
            | unprotect | paloma.torres  | datetime     | 2023-09-04T14:30:00      | None      | None             | None                                                                                      |
            | unprotect | paloma.torres  | nin          | QQ123456C                | None      | None             | None                                                                                      |
            | unprotect | merlin.ishida  | address      | 123 Main St, Springfield | None      | None             | None                                                                                      |
            | unprotect | merlin.ishida  | ccn          | 4111111122223333         | None      | None             | None                                                                                      |
            | unprotect | admin          | ssn          | 123-45-6789              | None      | 123-45-6789      | None                                                                                      |
            | unprotect | devops         | int          | 12335                    | None      | 12335            | None                                                                                      |
            | unprotect | jay.banerjee   | ssn          | 123-45-6789              | None      | 123-45-6789      | None                                                                                      |
            | unprotect | paloma.torres  | ssn          | 123-45-6789              | None      | None             | None                                                                                      |
            | unprotect | merlin.ishida  | ssn          | 123-45-6789              | None      | None             | None                                                                                      |
            | unprotect | admin          | passport     | X1234567                 | None      | X1234567         | None                                                                                      |
            | unprotect | devops         | passport     | X1234567                 | None      | X1234567         | None                                                                                      |
            | unprotect | jay.banerjee   | passport     | X1234567                 | None      | X1234567         | None                                                                                      |
            | unprotect | paloma.torres  | passport     | X1234567                 | None      | None             | None                                                                                      |
            | unprotect | merlin.ishida  | passport     | X1234567                 | None      | None             | None                                                                                      |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect with user not present in policy for single string input data
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data  | result    | output | error_message                                                                             |
            | protect   | dummyUser | name         | John Doe    | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | dummyUser | int          | 12345       | None      | None   | None                                                                                      |
            | reprotect | dummyUser | ssn          | 123-45-6789 | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect with data element not present in policy for single string input data
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data  | result    | output | error_message                                         |
            | protect   | superuser | dummyDE      | John Doe    | exception | None   | 2, The data element could not be found in the policy. |
            | unprotect | superuser | dummyDE      | 12345       | exception | None   | 2, The data element could not be found in the policy. |
            | reprotect | superuser | dummyDE      | 123-45-6789 | exception | None   | 2, The data element could not be found in the policy. |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing invalid single string input data
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data                                                                     | result    | output | error_message                                   |
            | protect   | superuser | email        | John Doe                                                                       | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | email        | John Doe                                                                       | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | email        | John Doe                                                                       | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | email        | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaQ@example.coma | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | ccn          | aA1 bB2 cC3 dD4 eE5 fF6 gG7 hH9 iI0                                            | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | ccn          | aA1 bB2 cC3 dD4 eE5 fF6 gG7 hH9 iI0                                            | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | ccn          | aA1 bB2 cC3 dD4 eE5 fF6 gG7 hH9 iI0                                            | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | int          | abcdef                                                                         | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | int          | abcdef                                                                         | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | int          | abcdef                                                                         | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | datetime     | 1906-12-02 13:11:09 4004453117                                                 | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | datetime     | 1906-12-02 13:11:09 4004453117                                                 | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | datetime     | 1906-12-02 13:11:09 4004453117                                                 | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | datetime     | 1906:12:02                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | datetime     | 1906:12:02                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | datetime     | 1906:12:02                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | datetime     | 12/02/1999                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | datetime     | 12/02/1999                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | datetime     | 12/02/1999                                                                     | exception | None   | 44, The content of the input data is not valid. |

    @tokenization @single @bytes @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing invalid single bytes input data
        When the user performs "<operation>" operation using "tokenization" method on the "single bytes" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data                                                                     | result    | output | error_message                                   |
            | protect   | superuser | email        | John Doe                                                                       | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | email        | John Doe                                                                       | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | email        | John Doe                                                                       | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | email        | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaQ@example.coma | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | ccn          | aA1 bB2 cC3 dD4 eE5 fF6 gG7 hH9 iI0                                            | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | ccn          | aA1 bB2 cC3 dD4 eE5 fF6 gG7 hH9 iI0                                            | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | ccn          | aA1 bB2 cC3 dD4 eE5 fF6 gG7 hH9 iI0                                            | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | int          | abcdef                                                                         | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | int          | abcdef                                                                         | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | int          | abcdef                                                                         | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | datetime     | 1906-12-02 13:11:09 4004453117                                                 | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | datetime     | 1906-12-02 13:11:09 4004453117                                                 | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | datetime     | 1906-12-02 13:11:09 4004453117                                                 | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | datetime     | 1906:12:02                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | datetime     | 1906:12:02                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | datetime     | 1906:12:02                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | protect   | superuser | datetime     | 12/02/1999                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | datetime     | 12/02/1999                                                                     | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | datetime     | 12/02/1999                                                                     | exception | None   | 44, The content of the input data is not valid. |

    @tokenization @single @integer @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing invalid single integer input data
        When the user performs "<operation>" operation using "tokenization" method on the "single integer" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data  | result    | output | error_message                                   |
            | protect   | superuser | int          | -4147483648 | exception | None   | 44, The content of the input data is not valid. |
            | unprotect | superuser | int          | 4147483648  | exception | None   | 44, The content of the input data is not valid. |
            | reprotect | superuser | int          | 10147483648 | exception | None   | 44, The content of the input data is not valid. |

    @tokenization @single @string @negative @PDE-98
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing single string input data of more than valid max length
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data                        | result    | output | error_message                                     |
            | protect   | superuser | name         | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | city_de      | InputDataMoreThan_4096_CodePoints | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | address      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | zipcode      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | email        | InputDataMoreThan_256_Bytes       | exception | None   | 44, The content of the input data is not valid.   |
            | protect   | superuser | ccn          | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | name         | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | city_de      | InputDataMoreThan_4096_CodePoints | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | address      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | zipcode      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | email        | InputDataMoreThan_256_Bytes       | exception | None   | 44, The content of the input data is not valid.   |
            | unprotect | superuser | ccn          | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | name         | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | city_de      | InputDataMoreThan_4096_CodePoints | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | address      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | zipcode      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | email        | InputDataMoreThan_256_Bytes       | exception | None   | 44, The content of the input data is not valid.   |
            | reprotect | superuser | ccn          | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |

    @tokenization @single @bytes @negative @PDE-98
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing single bytes input data of more than valid max length
        When the user performs "<operation>" operation using "tokenization" method on the "single bytes" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data                        | result    | output | error_message                                     |
            | protect   | superuser | name         | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | city_de      | InputDataMoreThan_4096_CodePoints | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | address      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | zipcode      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | protect   | superuser | email        | InputDataMoreThan_256_Bytes       | exception | None   | 44, The content of the input data is not valid.   |
            | protect   | superuser | ccn          | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | name         | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | city_de      | InputDataMoreThan_4096_CodePoints | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | address      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | zipcode      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | unprotect | superuser | email        | InputDataMoreThan_256_Bytes       | exception | None   | 44, The content of the input data is not valid.   |
            | unprotect | superuser | ccn          | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | name         | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | city_de      | InputDataMoreThan_4096_CodePoints | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | address      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | zipcode      | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |
            | reprotect | superuser | email        | InputDataMoreThan_256_Bytes       | exception | None   | 44, The content of the input data is not valid.   |
            | reprotect | superuser | ccn          | InputDataMoreThan_4096_Bytes      | exception | None   | 23, Data is too long to be protected/unprotected. |

    @tokenization @single @integer @negative @PDE-122
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing unsupported data type for data element that supports only string data type (single integer input data)
        When the user performs "<operation>" operation using "tokenization" method on the "single integer" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data | result    | output | error_message                                                                  |
            | protect   | superuser | address      | 12456      | exception | None   | 26, Unsupported algorithm or unsupported action for the specific data element. |
            | unprotect | superuser | address      | 12456      | exception | None   | 26, Unsupported algorithm or unsupported action for the specific data element. |
    # | reprotect | superuser | address      | 12456      | exception | None   | 26, Unsupported algorithm or unsupported action for the specific data element. |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect using encryption data element without passing encrypt_to parameter in the API call for single string input data
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data              | result    | output | error_message                                                                  |
            | protect   | superuser | text         | 12456 this is some data | exception | None   | 26, Unsupported algorithm or unsupported action for the specific data element. |
            | unprotect | superuser | text         | 12456 this is some data | exception | None   | 26, Unsupported algorithm or unsupported action for the specific data element. |
            | reprotect | superuser | text         | 12456 this is some data | exception | None   | 26, Unsupported algorithm or unsupported action for the specific data element. |

    @encryption @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect using data element of type encryption for various negative scenarios with single string input data
        When the user performs "<operation>" operation using "encryption" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user          | data_element | input_data       | result    | output | error_message                                                                             |
            | protect   | finance       | text         | John Doe         | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | finance       | text         | 123-45-6789      | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | jay.banerjee  | text         | 123-45-6789      | None      | None   | None                                                                                      |
            | unprotect | paloma.torres | text         | 2023-09-04       | None      | None   | None                                                                                      |
            | protect   | dummyUser     | text         | John Doe         | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | dummyUser     | text         | SGVsbG8sIEpvIQ== | None      | None   | None                                                                                      |
            | reprotect | dummyUser     | text         | 123-45-6789      | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | superuser     | dummyDE      | John Doe         | exception | None   | 2, The data element could not be found in the policy.                                     |
            | unprotect | superuser     | dummyDE      | 12345            | exception | None   | 2, The data element could not be found in the policy.                                     |
            | reprotect | superuser     | dummyDE      | 123-45-6789      | exception | None   | 2, The data element could not be found in the policy.                                     |

    @encryption @single @bytes @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect using data element of type encryption for various negative scenarios with single bytes input data
        When the user performs "<operation>" operation using "encryption" method on the "single bytes" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user          | data_element | input_data          | result    | output | error_message                                                                             |
            | protect   | finance       | text         | John Doe            | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | finance       | text         | 123-45-6789         | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | jay.banerjee  | text         | 123-45-6789         | None      | None   | None                                                                                      |
            | unprotect | paloma.torres | text         | 2023-09-04T14:30:00 | None      | None   | None                                                                                      |
            | protect   | dummyUser     | text         | John Doe            | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | dummyUser     | text         | 12345               | None      | None   | None                                                                                      |
            | reprotect | dummyUser     | text         | 123-45-6789         | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |

    @encryption @single @integer @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect using data element of type encryption for various negative scenarios with single integer input data
        When the user performs "<operation>" operation using "encryption" method on the "single integer" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user          | data_element | input_data | result    | output | error_message                                                                             |
            | protect   | finance       | text         | 12345      | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | protect   | finance       | text         | 10000      | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | jay.banerjee  | text         | -132324    | None      | None   | None                                                                                      |
            | unprotect | paloma.torres | text         | 1234       | None      | None   | None                                                                                      |
            | protect   | dummyUser     | text         | 99999      | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |
            | unprotect | dummyUser     | text         | 123        | None      | None   | None                                                                                      |
            | reprotect | dummyUser     | text         | 1234       | exception | None   | 3, The user does not have the appropriate permissions to perform the requested operation. |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing invalid data type for data element (single string input data)
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element  | input_data | result    | output | error_message                                        |
            | protect   | superuser | data_type_int | 12456      | exception | None   | -1, Data element parameter should be of String type. |
            | unprotect | superuser | data_type_int | 12456      | exception | None   | -1, Data element parameter should be of String type. |
            | reprotect | superuser | data_type_int | 12456      | exception | None   | -1, Data element parameter should be of String type. |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing invalid data type for user (single string input data)
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user          | data_element | input_data | result    | output | error_message                                     |
            | protect   | data_type_int | name         | John Doe   | exception | None   | -1, User name parameter should be of String type. |
            | unprotect | data_type_int | name         | John Doe   | exception | None   | -1, User name parameter should be of String type. |
            | reprotect | data_type_int | name         | John Doe   | exception | None   | -1, User name parameter should be of String type. |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing empty/None data element (single string input data)
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data | result    | output | error_message                            |
            | protect   | superuser | Empty        | 12456      | exception | None   | -1, Data element cannot be none or empty |
            | unprotect | superuser | None         | 12456      | exception | None   | -1, Data element cannot be none or empty |
            | reprotect | superuser | Empty        | 12456      | exception | None   | -1, Data element cannot be none or empty |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing empty/None user (single string input data)
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user  | data_element | input_data | result    | output | error_message                           |
            | protect   | Empty | name         | John       | exception | None   | -1, Policy user cannot be none or empty |
            | unprotect | None  | name         | John       | exception | None   | -1, Policy user cannot be none or empty |
            | reprotect | Empty | name         | John       | exception | None   | -1, Policy user cannot be none or empty |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect on passing string data type for external IV (single string input data)
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>" and external IV as "data_type_string"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data | result    | output | error_message                                                                                  |
            | protect   | superuser | name         | John       | exception | None   | -1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>     |
            | unprotect | superuser | name         | John       | exception | None   | -1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>     |
            | reprotect | superuser | name         | John       | exception | None   | -1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'> |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect after the session has expired
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>" after the session has expired "0.001"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data | result    | output | error_message                          |
            | protect   | superuser | name         | John       | exception | None   | User session is invalid or timed out!! |
            | unprotect | superuser | name         | John       | exception | None   | User session is invalid or timed out!! |
            | reprotect | superuser | name         | John       | exception | None   | User session is invalid or timed out!! |

    @tokenization @single @string @negative
    Scenario Outline: Validate error message on performing protect/unprotect/reprotect with an invalid session timeout value of string data type
        When the user performs "<operation>" operation using "tokenization" method on the "single string" input data "<input_data>" using "<data_element>" data element with the username "<user>" with invalid data type for session timeout "string_timeout"
        Then the result is "<result>", the error message should be "<error_message>" and output as "<output>"
        Examples:
            | operation | user      | data_element | input_data | result    | output | error_message                               |
            | protect   | superuser | name         | John       | exception | None   | timeout must be an integer or float value!! |