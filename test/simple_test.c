#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCHAR char
//char test[100] = "V'SLELI YUWKNID DI LEPCG JIYFY TQ NAOJVUY";
char *customCommands[] =
{
	"core_loadlib",
    "request_core_loadlib",
	"core_enumextcmd",
    "request_core_enumextcmd",
	"core_machine_id",
    "request_core_machine_id",
	"core_get_session_guid",
    "request_core_get_session_guid"
};

char test[] = "J'ADORE ECOUTER LA RADIO TOUTE LA JOURNEE";

char test2[] = "Test: several strings.";
int main(int argc, char** argv)
{
    int a = atoi("313371337");

    printf("%s\n", test);
    char test3[200];
    strcpy(test3, test2);
    printf("%s\n", test3);
    printf("%d\n", a);
    return 0;
}
