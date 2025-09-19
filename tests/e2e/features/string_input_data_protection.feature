Feature: Successful Protection Operations For String Input Data
    As a user of the appython module (installed via protegrity_developer_python)
    I want to perform protect and unprotect operations on string input data
    So that I can ensure data security and integrity

    Background:
        Given the appython module is available via the protegrity_developer_python installation
        And the enviroment variables DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD and DEV_EDITION_API_KEY are set
        And a policy is deployed with required data elements and user "superuser" is present

    @tokenization @single @string @positive
    Scenario: Tokenize and Detokenize single string input data
        When the user performs "tokenization" operations on the "single string" input data using the following data elements
            | data_element | input_data                                                                                                                |
            | name         | John Doe                                                                                                                  |
            | address      | 123 Main St, Springfield                                                                                                  |
            | city         | Springfield                                                                                                               |
            | postcode     | SW1A 1AA                                                                                                                  |
            | zipcode      | 90210                                                                                                                     |
            | phone        | +1-202-555-0173                                                                                                           |
            | email        | johndoe@example.com                                                                                                       |
            | datetime     | 2023-09-04T14:30:00                                                                                                       |
            | datetime     | 2023-09-04                                                                                                                |
            | datetime_yc  | 2023-09-04T14:30:00                                                                                                       |
            | datetime_yc  | 2023-09-04                                                                                                                |
            | int          | 12345                                                                                                                     |
            | nin          | QQ123456C                                                                                                                 |
            | ssn          | 123-45-6789                                                                                                               |
            | ccn          | 4111111111111111                                                                                                          |
            | ccn_bin      | 4111111122223333                                                                                                          |
            | passport     | X1234567                                                                                                                  |
            | iban         | GB82WEST12345698765432                                                                                                    |
            | iban_cc      | 12345678901234567890                                                                                                      |
            | string       | The 'string' data element protects all alphabetic symbols (both lowercase and uppercase letters), as well as digits 1234. |
            | number       | 9876543210 11 234                                                                                                         |
            | name_de      | Max Mustermann                                                                                                            |
            | name_fr      | Jean Dupont                                                                                                               |
            | address_de   | Musterstraße 12, München                                                                                                  |
            | address_fr   | 10 Rue de Rivoli, Paris                                                                                                   |
            | city_de      | München                                                                                                                   |
            | city_fr      | Paris                                                                                                                     |
        Then all the data is validated
        And all the data should be written to a file "token_string.txt"

    @encryption @single @string @positive
    Scenario: Encyrpt and Decrypt single string input data
        When the user performs "encryption" operations on the "single string" input data using the following data elements
            | data_element | input_data                                                                                                                    |
            | text         | The Encryption data Element , Encrypts all alphabetic symbols (both lowercase and uppercase letters), as well as digits 5678. |
        Then all the data is validated
        And all the data should be written to a file "encrypt_string.txt"

    @encryption @bulk @string @positive
    Scenario Outline: Encyrpt and Decrypt bulk input data passed as a "<input_type>"
        When the user performs "encryption" operations on the "<input_type>" using the following data elements
            | data_element | input_data                                                                                                                              |
            | text         | ["The Encryption data Element", "Encrypts all alphabetic symbols", "(both lowercase and uppercase letters)", "as well as digits 5678."] |
        Then all the data is validated
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type       | output_file                  |
            | list of strings  | encrypt_list_of_strings.txt  |
            | tuple of strings | encrypt_tuple_of_strings.txt |

    # EIV is not supported with Encryption, NoEncryption, PreserverPosition_PreserverCase alphanum, Decimal and Datetime DEs
    @tokenization @single @eiv @string @positive
    Scenario: Tokenize and Detokenize single string input data with External Initialization Vector (EIV)
        When the user performs "tokenization" operations on the "single string" input data using the following data elements and external IV
            | data_element | input_data                                                                                                                | external_iv       |
            | name         | John Doe                                                                                                                  | iv_name_001       |
            | address      | 123 Main St, Springfield                                                                                                  | iv_address_004    |
            | city         | Springfield                                                                                                               | iv_city_007       |
            | zipcode      | 90210                                                                                                                     | iv_zipcode_011    |
            | phone        | +1-202-555-0173                                                                                                           | iv_phone_012      |
            | email        | johndoe@example.com                                                                                                       | iv_email_013      |
            | int          | 12345                                                                                                                     | iv_int_018        |
            | ssn          | 123-45-6789                                                                                                               | iv_ssn_020        |
            | ccn          | 4111111111111111                                                                                                          | iv_ccn_021        |
            | ccn_bin      | 4111111122223333                                                                                                          | iv_ccn_bin_022    |
            | iban_cc      | 12345678901234567890                                                                                                      | iv_iban_cc_025    |
            | string       | The 'string' data element protects all alphabetic symbols (both lowercase and uppercase letters), as well as digits 1234. | iv_string_026     |
            | number       | 9876543210 11 234                                                                                                         | iv_number_027     |
            | name_de      | Max Mustermann                                                                                                            | iv_name_de_002    |
            | name_fr      | Jean Dupont                                                                                                               | iv_name_fr_003    |
            | address_de   | Musterstraße 12, München                                                                                                  | iv_address_de_005 |
            | address_fr   | 10 Rue de Rivoli, Paris                                                                                                   | iv_address_fr_006 |
            | city_de      | München                                                                                                                   | iv_city_de_008    |
            | city_fr      | Paris                                                                                                                     | iv_city_fr_009    |
        Then all the data is validated for eiv
        And all the data should be written to a file "token_string_IV.txt"

    @tokenization @bulk @string @positive
    Scenario Outline: Tokenize and Detokenize bulk input data passed as a "<input_type>"
        When the user performs "tokenization" operations on the "<input_type>" using the following data elements
            | data_element | input_data                                                                                                                                                                                                                                                                                                               |
            | name         | ["John Doe", "Jane Smith", "Alice Johnson", "Bob Lee", "Élodie Durand", "Diana Prince", "Eve Adams", "Frank Müller"]                                                                                                                                                                                                     |
            | address      | ["123 Main St, Springfield", "456 Elm St, Shelbyville", "789 Oak Ave, Capital City", "101 Maple Rd, Smalltown", "202 Pine St, Bigcity", "303 Cedar Blvd, Midtown", "404 Birch Ln, Uptown", "505 Walnut Dr, Downtown"]                                                                                                    |
            | city         | ["Springfield", "Shelbyville", "Capital City", "Smalltown", "Bigcity", "Midtown", "Uptown", "München"]                                                                                                                                                                                                                   |
            | postcode     | ["SW1A 1AA", "W1A 0AX", "EC1A 1BB", "GIR 0AA", "L1 8JQ", "M1 1AE", "B33 8TH", "CR2 6XH"]                                                                                                                                                                                                                                 |
            | zipcode      | ["90210", "10001", "60601", "94105", "30301", "73301", "02108", "12345"]                                                                                                                                                                                                                                                 |
            | phone        | ["+1-202-555-0173", "+44-20-7946-0958", "+49-30-123456", "+33-1-23456789", "+91-22-12345678", "+81-3-1234-5678", "+61-2-9876-5432", "+34-91-1234567"]                                                                                                                                                                    |
            | email        | ["johndoe@example.com", "janesmith@domain.co.uk", "alicej@web.de", "boblee@free.fr", "charlieb@company.com", "dianap@service.org", "evea@site.net", "frankm@provider.eu"]                                                                                                                                                |
            | datetime     | ["2023-09-04 14:30:00", "2022-08-05T10:15:00", "0600-01-01 00:00:00 000", "1970-04-02 07:00:58 369000", "2019-05-08 16:20:00", "3337-11-27 23:59:59 999", "1931.07.16 15:29:24 838467", "1958/06/30 11:38:03 051", "1906-12-02T13:11:09.400445311", "2020-07-17 11:47:07,715820"]                                        |
            | datetime     | ["2023-09-04", "2022-08-05", "2021-07-06", "2020-06-07", "2019-05-08", "2018-04-09", "2017-03-10", "2016-02-11"]                                                                                                                                                                                                         |
            | datetime     | ["2023-09-04 14:30:00", "2022-08-05T10:15:00", "0600-01-01 00:00:00 000", "1970-04-02 07:00:58 369000", "2019-05-08 16:20:00", "3337-11-27 23:59:59 999", "1931.07.16 15:29:24 838467", "1958/06/30 11:38:03 051", "3337-11-27T23:59:59.abcdefgh8", "1764-10-02 00:00:15.820715"]                                        |
            | datetime_yc  | ["2023-09-04", "2022-08-13", "2021-07-14", "2020-06-15", "2019-05-16", "2018-04-17", "2017-03-18", "2016-02-19"]                                                                                                                                                                                                         |
            | int          | ["12345", "67890", "23456", "78901", "34567", "89012", "45678", "90123"]                                                                                                                                                                                                                                                 |
            | nin          | ["QQ123456C", "CD654321E", "EF112233A", "GH445566B", "IJ778899D", "KL990011F", "MN223344G", "OP556677H"]                                                                                                                                                                                                                 |
            | ssn          | ["123-45-6789", "987-65-4321", "111-22-3333", "444-55-6666", "777-88-9999", "000-11-2222", "333-44-5555", "666-77-8888"]                                                                                                                                                                                                 |
            | ccn          | ["4111111111111111", "5500000000000004", "340000000000009", "30000000000004", "6011000000000004", "201400000000009", "3088000000000009", "3530111333300000"]                                                                                                                                                             |
            | ccn_bin      | ["4111111122223333", "5500000022223333", "340000002222333", "30000000222233", "6011000022223333", "201400002222333", "308800002222333", "3530111322223333"]                                                                                                                                                              |
            | passport     | ["X1234567", "Y7654321", "A1122334", "B4455667", "C7788990", "D9900112", "E2233445", "F5566778"]                                                                                                                                                                                                                         |
            | iban         | ["GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606", "ES9121000418450200051332", "IT60X0542811101000000123456", "NL91ABNA0417164300", "BE68539007547034", "CH9300762011623852957"]                                                                                                        |
            | iban_cc      | ["12345678901234567890", "09876543210987654321", "11223344556677889900", "22334455667788990011", "33445566778899001122", "44556677889900112233", "55667788990011223344", "66778899001122334455"]                                                                                                                         |
            | string       | ["The 'string' data element protects all alphabetic symbols (both lowercase and uppercase letters), as well as digits 1234.", "Uppercase and lowercase letters.", "Special characters are ignored.", "Bulk input test string 1.", "Bulk input test string 2.", "Bulk input test string 3.", "Bulk input test string 4."] |
            | number       | ["9876543210 11 234", "1122 33445 5", "2233445566", "3344556677", "4455667788", "5566778899", "6677889900", "7788990011"]                                                                                                                                                                                                |
            | name_de      | ["Max Mustermann", "Anna Schmidt", "Peter Müller", "Julia Fischer", "Lukas Weber", "Sophie Becker", "Tim Wagner", "Laura Hoffmann"]                                                                                                                                                                                      |
            | name_fr      | ["Jean Dupont", "Marie Curie", "Émile Zola", "Lucie Bernard", "Paul Moreau", "Sophie Laurent", "Louis Petit", "Julie Robert"]                                                                                                                                                                                            |
            | address_de   | ["Musterstraße 12, München", "Bahnhofstr. 5, Berlin", "Hauptstr. 7, Hamburg", "Marktplatz 1, Köln", "Schulstr. 3, Frankfurt", "Ringstr. 8, Stuttgart", "Parkweg 2, Düsseldorf", "Wiesenweg 4, Bremen"]                                                                                                                   |
            | address_fr   | ["10 Rue de Rivoli, Paris", "20 Avenue Victor Hugo, Lyon", "5 Boulevard Saint-Michel, Marseille", "15 Rue de la Païx, Nice", "8 Place Bellecour, Toulouse", "12 Rue du Bac, Bordeaux", "3 Avenue Foch, Lille", "7 Rue Gambetta, Nantes"]                                                                                 |
            | city_de      | ["München", "Berlin", "Hamburg", "Köln", "Frankfurt", "Stuttgart", "Düsseldorf", "Bremen"]                                                                                                                                                                                                                               |
            | city_fr      | ["Paris", "Lyon", "Marseille", "Nice", "Toulouse", "Bordeaux", "Lille", "Nantes"]                                                                                                                                                                                                                                        |
        Then all the data is validated
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type       | output_file                |
            | list of strings  | token_list_of_strings.txt  |
            | tuple of strings | token_tuple_of_strings.txt |

    @tokenization @bulk @eiv @string @positive
    Scenario Outline: Tokenize and Detokenize bulk input data passed as a <input_type> with External Initialization Vector (EIV)
        When the user performs "tokenization" operations on the "<input_type>" using the following data elements and external IV
            | data_element | input_data                                                                                                                                                                                                                                                                                                               | external_iv       |
            | name         | ["John Doe", "Jane Smith", "Alice Johnson", "Bob Lee", "Élodie Durand", "Diana Prince", "Eve Adams", "Frank Müller"]                                                                                                                                                                                                     | iv_name_001       |
            | address      | ["123 Main St, Springfield", "456 Elm St, Shelbyville", "789 Oak Ave, Capital City", "101 Maple Rd, Smalltown", "202 Pine St, Bigcity", "303 Cedar Blvd, Midtown", "404 Birch Ln, Uptown", "505 Walnut Dr, Downtown"]                                                                                                    | iv_address_002    |
            | city         | ["Springfield", "Shelbyville", "Capital City", "Smalltown", "Bigcity", "Midtown", "Uptown", "München"]                                                                                                                                                                                                                   | iv_city_003       |
            | zipcode      | ["90210", "10001", "60601", "94105", "30301", "73301", "02108", "12345"]                                                                                                                                                                                                                                                 | iv_zipcode_005    |
            | phone        | ["+1-202-555-0173", "+44-20-7946-0958", "+49-30-123456", "+33-1-23456789", "+91-22-12345678", "+81-3-1234-5678", "+61-2-9876-5432", "+34-91-1234567"]                                                                                                                                                                    | iv_phone_006      |
            | email        | ["johndoe@example.com", "janesmith@domain.co.uk", "alicej@web.de", "boblee@free.fr", "charlieb@company.com", "dianap@service.org", "evea@site.net", "frankm@provider.eu"]                                                                                                                                                | iv_email_007      |
            | int          | ["12345", "67890", "23456", "78901", "34567", "89012", "45678", "90123"]                                                                                                                                                                                                                                                 | iv_int_012        |
            | ssn          | ["123-45-6789", "987-65-4321", "111-22-3333", "444-55-6666", "777-88-9999", "000-11-2222", "333-44-5555", "666-77-8888"]                                                                                                                                                                                                 | iv_ssn_014        |
            | ccn          | ["4111111111111111", "5500000000000004", "340000000000009", "30000000000004", "6011000000000004", "201400000000009", "3088000000000009", "3530111333300000"]                                                                                                                                                             | iv_ccn_015        |
            | ccn_bin      | ["4111111122223333", "5500000022223333", "340000002222333", "30000000222233", "6011000022223333", "201400002222333", "308800002222333", "3530111322223333"]                                                                                                                                                              | iv_ccn_bin_016    |
            | iban_cc      | ["12345678901234567890", "09876543210987654321", "11223344556677889900", "22334455667788990011", "33445566778899001122", "44556677889900112233", "55667788990011223344", "66778899001122334455"]                                                                                                                         | iv_iban_cc_019    |
            | string       | ["The 'string' data element protects all alphabetic symbols (both lowercase and uppercase letters), as well as digits 1234.", "Uppercase and lowercase letters.", "Special characters are ignored.", "Bulk input test string 1.", "Bulk input test string 2.", "Bulk input test string 3.", "Bulk input test string 4."] | iv_string_020     |
            | number       | ["9876543210 11 234", "1122 33445 5", "2233445566", "3344556677", "4455667788", "5566778899", "6677889900", "7788990011"]                                                                                                                                                                                                | iv_number_021     |
            | name_de      | ["Max Mustermann", "Anna Schmidt", "Peter Müller", "Julia Fischer", "Lukas Weber", "Sophie Becker", "Tim Wagner", "Laura Hoffmann"]                                                                                                                                                                                      | iv_name_de_002    |
            | name_fr      | ["Jean Dupont", "Marie Curie", "Émile Zola", "Lucie Bernard", "Paul Moreau", "Sophie Laurent", "Louis Petit", "Julie Robert"]                                                                                                                                                                                            | iv_name_fr_003    |
            | address_de   | ["Musterstraße 12, München", "Bahnhofstr. 5, Berlin", "Hauptstr. 7, Hamburg", "Marktplatz 1, Köln", "Schulstr. 3, Frankfurt", "Ringstr. 8, Stuttgart", "Parkweg 2, Düsseldorf", "Wiesenweg 4, Bremen"]                                                                                                                   | iv_address_de_005 |
            | address_fr   | ["10 Rue de Rivoli, Paris", "20 Avenue Victor Hugo, Lyon", "5 Boulevard Saint-Michel, Marseille", "15 Rue de la Païx, Nice", "8 Place Bellecour, Toulouse", "12 Rue du Bac, Bordeaux", "3 Avenue Foch, Lille", "7 Rue Gambetta, Nantes"]                                                                                 | iv_address_fr_006 |
            | city_de      | ["München", "Berlin", "Hamburg", "Köln", "Frankfurt", "Stuttgart", "Düsseldorf", "Bremen"]                                                                                                                                                                                                                               | iv_city_de_008    |
            | city_fr      | ["Paris", "Lyon", "Marseille", "Nice", "Toulouse", "Bordeaux", "Lille", "Nantes"]                                                                                                                                                                                                                                        | iv_city_fr_009    |
        Then all the data is validated for eiv
        And all the data should be written to a file "<output_file>"
        Examples:
            | input_type       | output_file                   |
            | list of strings  | token_list_of_strings_IV.txt  |
            | tuple of strings | token_tuple_of_strings_IV.txt |