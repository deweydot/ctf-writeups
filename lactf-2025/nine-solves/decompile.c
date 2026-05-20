int main(void)
{
    uint input_char;
    char input_str [6];
    puts("Welcome to the Tianhuo Research Center.");
    printf("Please enter your access code: ");
    fgets(input_str,16,stdin);
    for(long i = 0; i != 6; i = i + 1) {
        input_char = (uint)input_str[i];
        if (input_str[i] > '~') || (yi[i] == 0) goto ACCESS_DENIED;
        for(int j = 0; j != yi[i]; j = j + 1) {
            if ((input_char & 1) == 0) {
                input_char = input_char >> 1;
            }
            else {
                input_char = input_char * 3 + 1;
            }
            if (input_char == 1) goto ACCESS_DENIED;
        }
        if (input_char != 1) goto ACCESS_DENIED;
    }
    if ((input_char == '\0') || (input_char == '\n')) {
        eigong();
        return 0;
    }
    else {
ACCESS_DENIED:
        puts("ACCESS DENIED");
        return 1;
    }
}