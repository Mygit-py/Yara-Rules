rule msfvenom_strings_and_hex_values
{
        meta:
                author = "Max Foster"
                filetype = "Msfvenom generated EXE"
                date = "9/2/2021"
                version = "1.0"
        strings:
                $s1 = "D$$[[aYZQ" //encoded string
                $h1 = { FC E8 8F}

        condition:
                $s1 or $h1
}
