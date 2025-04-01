#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int extract_integer(const char *str)
{
	// Skip over non-numeric characters

	while (*str != '\0' && !isdigit(*str) && *str != '-' && *str != '+')
	{
		str++;
	}

	// Now we expect to find the integer
	if (*str == '\0')
	{
		printf("No integer found in the string.\n");
		return 0; // No integer found
	}

	// Convert the string to an integer
	char *endptr;
	long int num = strtol(str, &endptr, 10);

	// Return the converted integer
	return (int)num;
}

int runRamCheck()
{
	char fileName[256];
	snprintf(fileName, sizeof(fileName), "/proc/%d/status", getpid());
	FILE *fp = fopen(fileName, "r"); // After this point, file will not be changed
	// printf("Checking pid: %d\n", getpid());
	if (fp == NULL)
	{
		perror("fopen");
		// printf("failed to open file");
		return 0;
	}

	char line[256];
	while (fgets(line, sizeof(line), fp))
	{
		// printf(line);
		if (strncmp(line, "VmHWM", 5) == 0)
		{ // VmHWM is the peak memory usage
			fclose(fp);
			return extract_integer(line);
		}
	}
	printf("Error, did not find file");
	return 0;
}

