#include <stdio.h>

extern "C" int unlink_no_refs(int value)
{
	return (value * 3) + 7;
}

int unlink_global_value = 11;

extern "C" int unlink_uses_global(int value)
{
	unlink_global_value += value;
	return unlink_global_value;
}

extern "C" int unlink_uses_function(int value)
{
	return unlink_no_refs(value) - 2;
}

int main(void)
{
	printf("hello world\n");
	return 0;
}
